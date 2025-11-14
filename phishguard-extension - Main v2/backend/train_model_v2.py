import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_curve, classification_report, accuracy_score
import joblib

# ---------- Feature Extractor ----------
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


# Use relative paths inside the backend folder
import os
HERE = os.path.dirname(__file__)
DATA_CSV = os.path.join(HERE, "labeled_urls.csv")
OUTPUT_MODEL = os.path.join(HERE, "phishing_model_v2.pkl")

if not os.path.exists(DATA_CSV):
    raise FileNotFoundError(f"Training CSV not found at {DATA_CSV}. Please place labeled_urls.csv in the backend folder.")

# Load data
df = pd.read_csv(DATA_CSV).dropna(subset=["url", "label"])
X = np.array([extract_features(u) for u in df["url"].astype(str)])
y = df["label"].astype(int).values

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.2, random_state=42
)

# Train calibrated RandomForest
base_rf = RandomForestClassifier(
    n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
)
clf = CalibratedClassifierCV(base_rf, cv=3)
clf.fit(X_train, y_train)

# Evaluate + find optimal threshold
probs = clf.predict_proba(X_test)[:, 1]
precision, recall, thresholds = precision_recall_curve(y_test, probs)

# precision_recall_curve returns arrays where thresholds length = len(precision)-1
# compute F1 for the thresholded points (skip the last precision/recall pair that has no threshold)
if len(thresholds) == 0:
    # fallback: use 0.5
    best_thr = 0.5
else:
    f1_scores = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1_scores))
    best_thr = float(thresholds[best_idx])

print(f"\n✅ Best threshold (max F1): {best_thr:.3f}")
print("📊 Accuracy:", accuracy_score(y_test, (probs >= best_thr).astype(int)))
print(classification_report(y_test, (probs >= best_thr).astype(int)))

# Save model and threshold
joblib.dump({"model": clf, "threshold": best_thr}, OUTPUT_MODEL)
print(f"\n💾 Model + threshold saved to {OUTPUT_MODEL}")
