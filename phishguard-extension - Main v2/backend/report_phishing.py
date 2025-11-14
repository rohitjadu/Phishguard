import csv
from datetime import datetime, timedelta
import os

REPORT_FILE = "phishing_reports.csv"

# Create file + header if missing
if not os.path.exists(REPORT_FILE):
    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "url", "confidence", "model", "source"])


def report_phishing(url, confidence, model="phishing_model_v2", source="model", dedupe_minutes: int = 1440):
    """Append a phishing report to REPORT_FILE unless a duplicate exists.

    Deduplication: if an entry with the same URL and source exists within the
    last `dedupe_minutes` minutes, the new report will be skipped.

    Returns True if the report was written, False if skipped as duplicate.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=dedupe_minutes)

    # Check for recent duplicate
    try:
        if os.path.exists(REPORT_FILE):
            with open(REPORT_FILE, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        existing_url = (row.get("url") or "").strip()
                        existing_source = (row.get("source") or "").strip()
                        ts = row.get("timestamp") or ""
                        if not ts:
                            continue
                        existing_time = datetime.fromisoformat(ts)
                    except Exception:
                        # skip malformed rows
                        continue

                    if existing_url == url and existing_source == source and existing_time >= cutoff:
                        print(f"[DUPLICATE SKIPPED] {url} | src={source} | last={existing_time.isoformat()}")
                        return False
    except Exception as e:
        # If dedupe check fails for some reason, proceed to append to avoid data loss
        print(f"[DEDUPE CHECK ERROR] {e}")

    # Append new report
    try:
        with open(REPORT_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([now.isoformat(), url, confidence, model, source])
        print(f"[REPORT LOGGED] {url} | conf={confidence} | src={source}")
        return True
    except Exception as e:
        print(f"[REPORT ERROR] Failed to write report: {e}")
        return False
