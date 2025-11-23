# Architecture Overview

PhishGuard is split into two main components:

1. **Browser Extension (extension/)** — runs in the user's browser. Responsibilities:
   - UI (popup) that allows the user to run a quick phishing check on the active tab.
   - Background service worker that performs network calls to the backend and mediates messages with content scripts.
   - Content script (optional) that collects safe page metadata (hostname, title) and reports to background if needed.

2. **Backend (backend/)** — local or remote server which runs the ML model and accepting reports.
   - `/predict` endpoint: accepts `{ "url": "..." }` and returns `{ "prediction": "phishing"|"safe", "source": "..." }`
   - `/report` endpoint: accepts `{ "url": "...", "note": "..." }`

## Diagram (ASCII)
```
+-----------+        message         +-------------+       HTTP        +-----------+
|  Popup UI | <--------------------> | Background  | <---------------> |  Backend  |
| extension |   chrome.runtime.send  | service wkr |    POST /predict   |  (ML API) |
+-----------+                        +-------------+                    +-----------+
      ^                                      ^
      | content script (PAGE_INFO)           |
      +--------------------------------------+
```
