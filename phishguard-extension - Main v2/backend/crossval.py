import os
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, roc_auc_score

HERE = os.path.dirname(__file__)
CSV = os.path.join(HERE, "labeled_urls.csv")
if not os.path.exists(CSV):
    raise FileNotFoundError(CSV)

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

# Load
df = pd.read_csv(CSV).dropna(subset=['url','label'])
X = np.array([extract_features(u) for u in df['url'].astype(str)])
y = df['label'].astype(int).values

print('Dataset size:', X.shape, 'Class counts:', np.bincount(y))

kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
accs = []
aucs = []
fold = 0
for train_idx, test_idx in kf.split(X, y):
    fold += 1
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    base_rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    clf = CalibratedClassifierCV(base_rf, cv=3)
    try:
        clf.fit(X_train, y_train)
        probs = clf.predict_proba(X_test)[:,1]
        preds = (probs >= 0.5).astype(int)
        acc = accuracy_score(y_test, preds)
        accs.append(acc)
        try:
            auc = roc_auc_score(y_test, probs)
            aucs.append(auc)
        except Exception:
            aucs.append(np.nan)
        print(f'Fold {fold}: test_size={len(y_test)}, acc={acc:.3f}, auc={aucs[-1]:.3f}')
    except Exception as e:
        print(f'Fold {fold} failed: {e}')

print('\nCross-val accuracy mean/std:', np.nanmean(accs), np.nanstd(accs))
print('Cross-val AUC mean/std:', np.nanmean(aucs), np.nanstd(aucs))
