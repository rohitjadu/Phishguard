# train_model.py
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

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
    suspicious_words = int(any(w in url_s.lower() for w in ["login","secure","account","bank","update"]))
    ip_address = 0
    domain_clean = domain.strip("[]")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_clean) or re.match(r"^[0-9a-fA-F:]+$", domain_clean):
        ip_address = 1
    return [url_length, num_dots, contains_at, has_https, num_digits, num_hyphens, suspicious_words, ip_address]

# ---- Edit here: path to your labeled CSV with columns 'url' and 'label' ----
DATA_CSV = "labeled_urls.csv"   # must contain url,label
OUTPUT_MODEL = "phishing_model_8features.pkl"

# Load dataset
df = pd.read_csv(DATA_CSV)  # ensure it has columns 'url' and 'label'
df = df.dropna(subset=['url','label'])

# Extract features
X = np.array([extract_features(u) for u in df['url'].astype(str)])
y = df['label'].astype(int).values

# Split + train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save
joblib.dump(clf, OUTPUT_MODEL)
print("Saved model to", OUTPUT_MODEL)
