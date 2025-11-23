"""
cd "d:\phishguard-extension - Main v2\backend"
python -m uvicorn main:app --reload --port 8001
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import csv
import logging
from report_phishing import report_phishing
from datetime import datetime
import os

# ---------- Setup ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishguard")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Load Model + Threshold ----------
MODEL_BUNDLE = "phishing_model_v2.pkl"
try:
    bundle = joblib.load(MODEL_BUNDLE)
    model = bundle["model"]
    THRESHOLD = bundle["threshold"]
    logger.info("Loaded calibrated model with threshold %.3f", THRESHOLD)
except Exception as e:
    logger.exception("Failed to load model: %s", e)
    model = None
    THRESHOLD = 0.5

# ---------- Load PhishTank CSV for exact matches (optional file) ----------
def load_phishing_urls(file_path):
    phishing_urls = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) > 0:
                    phishing_urls.add(row[0].strip().lower())
        logger.info("Loaded %d phishing URLs from %s", len(phishing_urls), file_path)
    except FileNotFoundError:
        logger.warning("PhishTank CSV not found at %s, skipping.", file_path)
    except Exception as e:
        logger.exception("Failed to load phishtank CSV: %s", e)
    return phishing_urls

phishing_urls = load_phishing_urls("online-valid.csv")  # optional

# ---------- Labeled dataset lookup (checks labeled_urls.csv first) ----------
def get_label_from_labeled_csv(url: str):
    """Return label (as 'phishing' or 'safe') if url exists in labeled_urls.csv, else None.
    We do a simple exact (stripped, lower) match. This reads the file each call so changes
    made by the dashboard are picked up immediately.
    """
    try:
        from urllib.parse import urlparse
        def normalize(u: str):
            s = (u or "").strip()
            if not s:
                return "", ""
            s_low = s.lower().rstrip('/')
            parsed = urlparse(s_low)
            netloc = (parsed.netloc or parsed.path).lower()  # some inputs may be domain-only
            # full normalized url and domain/netloc
            return s_low, netloc

        labels_path = os.path.join(os.path.dirname(__file__), "labeled_urls.csv")
        if not os.path.exists(labels_path):
            return None

        target_full, target_netloc = normalize(url)

        with open(labels_path, "r", encoding="utf-8", errors="ignore") as lf:
            next(lf, None)
            for row in lf:
                parts = [p.strip() for p in row.split(",")]
                if len(parts) >= 2:
                    raw_u = parts[0]
                    lab = parts[1]
                    u_full, u_netloc = normalize(raw_u)
                    # match full normalized URL first, then netloc/domain
                    if u_full and u_full == target_full:
                        val = lab.lower()
                    elif u_netloc and target_netloc and u_netloc == target_netloc:
                        val = lab.lower()
                    else:
                        continue
                    try:
                        if int(val) == 1:
                            return "phishing"
                        else:
                            return "safe"
                    except:
                        if val in ("phishing", "1", "true", "t"):
                            return "phishing"
                        return "safe"
    except Exception:
        logger.exception("Failed to read labeled_urls.csv")
    return None

# ---------- Load whitelist URLs from CSV ----------
def load_whitelist(file_path):
    whitelist = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            next(f, None)
            for line in f:
                u = line.strip().lower()
                if u:
                    whitelist.add(u)
        logger.info("Loaded %d whitelist entries from %s", len(whitelist), file_path)
    except FileNotFoundError:
        logger.warning("Whitelist file not found at %s, starting with empty set.", file_path)
    except Exception as e:
        logger.exception("Error loading whitelist file: %s", e)
    return whitelist

WHITELIST_URLS = load_whitelist("whitelist_urls.csv")

# ---------- Request Model ----------
class URLRequest(BaseModel):
    url: str

@app.get("/health")
async def health():
    return {"status": "ok"}

def extract_features(url: str):
    try:
        parsed = urlparse(url or "")
        domain = (parsed.netloc or "").lower()
        url_s = url or ""
        url_length = len(url_s)
        num_dots = domain.count(".")
        contains_at = int("@" in url_s)
        has_https = int(parsed.scheme == "https")
        num_digits = sum(c.isdigit() for c in url_s)
        num_hyphens = url_s.count("-")
        suspicious_words = int(any(w in url_s.lower() for w in ["login","secure","account","bank","update"]))
        ip_address = 0
        domain_clean = domain.strip("[]")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_clean) or re.match(r"^[0-9a-fA-F:]+$", domain_clean):
            ip_address = 1
        features = [url_length, num_dots, contains_at, has_https, num_digits, num_hyphens, suspicious_words, ip_address]
        return np.array([features], dtype=float)
    except Exception as e:
        logger.exception("extract_features error for url=%s: %s", url, e)
        return np.zeros((1,8), dtype=float)

@app.post("/predict")
async def predict_phish(req: URLRequest, request: Request):
    try:
        raw_url = (req.url or "").strip()
        url = raw_url.lower()
        logger.info("Predict request for url=%s from %s", url, request.client)

        # 1) Exact whitelist check (substring match)
        for safe in WHITELIST_URLS:
            if safe in url:
                return {"prediction": "safe", "source": "whitelist", "url": raw_url}

        # 2) Check labeled URLs first (this allows admin-updated labels to override model)
        labeled_label = get_label_from_labeled_csv(url)
        if labeled_label is not None:
            # record as dataset match (optional) and return authoritative label
            try:
                written = report_phishing(raw_url, labeled_label, "dataset", source="dataset")
                if not written:
                    logger.info("Duplicate dataset report skipped for %s", raw_url)
            except Exception:
                logger.exception("Failed to record dataset report for %s", raw_url)
            return {"prediction": labeled_label, "source": "labeled_dataset", "url": raw_url}

        # fallback to phishtank exact matches (if available)
        if url in phishing_urls:
            try:
                written = report_phishing(raw_url, "phishing", "dataset", source="dataset")
                if not written:
                    logger.info("Duplicate dataset report skipped for %s", raw_url)
            except Exception:
                logger.exception("Failed to record dataset report for %s", raw_url)
            return {"prediction": "phishing", "source": "dataset", "url": raw_url}

        # 3) Model prediction
        if model is None:
            return {"error": "model not loaded"}, 500

        X = extract_features(url)
        prob = float(model.predict_proba(X)[0][1])

        if prob >= THRESHOLD:
            result = "phishing"
        elif prob >= (THRESHOLD - 0.1):
            result = "suspicious"
        else:
            result = "safe"

        # If phishing (or suspicious) -> log report automatically
        if result in ("phishing", "suspicious"):
            try:
                written = report_phishing(raw_url, prob, "phishing_model_v2", source="model")
                if not written:
                    logger.info("Duplicate model report skipped for %s", raw_url)
            except Exception:
                logger.exception("Failed to record model report for %s", raw_url)

        # --- Runtime prediction logging for offline analysis ---
        try:
            runtime_path = os.path.join(os.path.dirname(__file__), "runtime_predictions.csv")
            write_header = not os.path.exists(runtime_path)
            with open(runtime_path, "a", encoding="utf-8", newline="") as rf:
                writer = csv.writer(rf)
                if write_header:
                    writer.writerow(["timestamp", "url", "probability", "prediction", "source", "model"])
                writer.writerow([datetime.utcnow().isoformat(), raw_url, f"{prob:.6f}", result, "model", "phishing_model_v2"])
        except Exception:
            logger.exception("Failed to write runtime prediction for %s", raw_url)

        return {"prediction": result, "probability": prob, "source": "model", "url": raw_url}

    except Exception as e:
        logger.exception("predict error: %s", e)
        return {"error": str(e)}, 500

# Endpoint to accept manual reports (from extension UI)
@app.post("/report")
async def manual_report(req: dict):
    url = req.get("url")
    confidence = req.get("confidence", "manual")
    model_name = req.get("model", "manual_report")
    action = req.get("action", "")  # distinguish false positives

    if not url:
        return {"error": "URL is required"}, 400

    try:
        # For false positives, use special source and model to flag for admin review
        source = "pending_review" if action == "false_positive" else "manual"
        if action == "false_positive":
            model_name = "false_positive_pending"  # flag for admin to review
            confidence = "pending_safe"  # indicates user thinks it's safe but needs verify

        # Record the report with appropriate flags
        written = report_phishing(url, confidence, model_name, source=source)
        logger.info("Report recorded for %s (action=%s, model=%s, source=%s)", 
                   url, action, model_name, source)

        if written:
            msg = "Report submitted for admin review" if action == "false_positive" else "Reported successfully"
            return {
                "message": msg,
                "url": url,
                "needs_review": action == "false_positive",
                "status": "pending_review" if action == "false_positive" else "reported"
            }
        else:
            return {"message": "Duplicate report skipped", "url": url}

    except Exception as e:
        logger.exception("Failed to write manual report: %s", e)
        return {"error": "Failed to record report"}, 500
