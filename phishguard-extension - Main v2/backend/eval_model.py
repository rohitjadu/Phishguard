import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "phishing_model_v2.pkl")
DATA_CSV = os.path.join(HERE, "labeled_urls.csv")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run train_model_v2.py to create it.")
if not os.path.exists(DATA_CSV):
    raise FileNotFoundError(f"Labeled CSV not found at {DATA_CSV}")

bundle = joblib.load(MODEL_PATH)
model = bundle.get("model")
threshold = float(bundle.get("threshold", 0.5))

print("Loaded model from", MODEL_PATH)
print("Using threshold:", threshold)

# Feature extractor
import re
from urllib.parse import urlparse

def extract_features(url: str):
    parsed = urlparse(url or "")
    domain = (parsed.netloc or "").lower()
    url_s = url or ""
    url_length = len(url_s)
    num_dots = domain.count(".")
    contains_at = int("@" in url_s)
    has_https = int(parsed.scheme == "https")
    num_digits = sum(c.isdigit() for c in url_s)
    num_hyphens = url_s.count("-")
    suspicious_words = int(any(w in url_s.lower() for w in ["login", "secure", "account", "bank", "update"]))
    ip_address = 0
    domain_clean = domain.strip("[]")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_clean) or re.match(r"^[0-9a-fA-F:]+$", domain_clean):
        ip_address = 1
    return [url_length, num_dots, contains_at, has_https, num_digits, num_hyphens, suspicious_words, ip_address]

# Load labeled data
df = pd.read_csv(DATA_CSV).dropna(subset=["url", "label"]) 
X = np.array([extract_features(u) for u in df["url"].astype(str)])
y = df["label"].astype(int).values

# Predict probabilities
probs = model.predict_proba(X)[:, 1]

y_pred = (probs >= threshold).astype(int)

print("Accuracy:", accuracy_score(y, y_pred))
print(classification_report(y, y_pred))
try:
    print("ROC AUC:", roc_auc_score(y, probs))
except Exception:
    pass
print("Confusion matrix:\n", confusion_matrix(y, y_pred))
