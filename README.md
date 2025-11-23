# PhishGuard Documentation

## Overview

PhishGuard is a browser extension and backend project for detecting and reporting potential phishing websites. It’s composed of:

- **extension/**: The browser extension (Manifest v3), includes popup UI, background service worker, content script, and icons.
- **backend/**: Local backend serving prediction and reporting endpoints (used during development).

## Quick Start

### Backend
1. Create a Python virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # macOS/Linux
   # or .venv\Scripts\activate for Windows
   ```
2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Run the backend (Flask example):
   ```bash
   cd backend
   FLASK_APP=app.py flask run --host=127.0.0.1 --port=8001
   ```

### Extension
1. Open Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode**, click **Load unpacked**, and select the `extension/` folder.
3. Open the extension popup and test “Check Site”.

## Architecture

PhishGuard is split into two main components:

### 1. Browser Extension (`extension/`)
- Popup UI for “Check Site” on the active tab.
- Background service worker for network calls to the backend.
- Content script for collecting safe page metadata.

### 2. Backend (`backend/`)
- `/predict` endpoint: Receives `{ "url": "..." }`, returns `{ "prediction": "phishing"|"safe", "source": "..." }`
- `/report` endpoint: Receives `{ "url": "...", "note": "..." }`

**Data Flow Diagram (ASCII):**
```
+-----------+        message         +-------------+       HTTP        +-----------+
|  Popup UI | <--------------------> | Background  | <---------------> |  Backend  |
| extension |   chrome.runtime.send  | service wkr |    POST /predict   |  (ML API) |
+-----------+                        +-------------+                    +-----------+
      ^                                      ^
      | content script (PAGE_INFO)           |
      +--------------------------------------+
```

## Installation & Setup

For detailed setup steps, see the [INSTALL.md](https://github.com/rohitjadu/Phishguard/blob/main/INSTALL.md) file in the repository.

## Contributing

- Fork the repository and create a branch for your changes.
- Keep changes small and focused, and open a PR with a clear description.
- Ensure sensitive data and virtual environments are not included.
- Run tests (if any) before submitting.

See [CONTRIBUTING.md](https://github.com/rohitjadu/Phishguard/blob/main/CONTRIBUTING.md) for full guidelines.

## License

PhishGuard is licensed under the terms found in the [LICENSE](https://github.com/rohitjadu/Phishguard/blob/main/LICENSE) file.

## References

- [README.md](https://github.com/rohitjadu/Phishguard/blob/main/README.md)
- [ARCHITECTURE.md](https://github.com/rohitjadu/Phishguard/blob/main/ARCHITECTURE.md)
- [INSTALL.md](https://github.com/rohitjadu/Phishguard/blob/main/INSTALL.md)
- [CONTRIBUTING.md](https://github.com/rohitjadu/Phishguard/blob/main/CONTRIBUTING.md)
