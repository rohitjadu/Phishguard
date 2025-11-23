# PhishGuard

PhishGuard is a browser extension + backend project for detecting and reporting potential phishing websites.

This repository is organized into two main folders:

- `extension/` — the browser extension (Manifest v3), contains popup UI, background service worker, content script, and icons.
- `backend/` — local backend that serves prediction and reporting endpoints (used during development).

## Quick start (development)

### 1. Backend (Python)
```bash
# Create & activate virtualenv
python -m venv .venv
source .venv/bin/activate   # macOS / Linux
# or .venv\Scripts\activate on Windows PowerShell

pip install -r backend/requirements.txt

# Example (Flask)
cd backend
FLASK_APP=app.py flask run --host=127.0.0.1 --port=8001
```

### 2. Extension (Chrome)
1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder inside the repository root.
3. Open the extension popup and test "Check Site".
