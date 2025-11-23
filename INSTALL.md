# Installation & Setup

## Backend
1. Create a Python virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Run the backend (example for Flask):
   ```bash
   cd backend
   FLASK_APP=app.py flask run --host=127.0.0.1 --port=8001
   ```

## Extension
1. In Chrome, go to `chrome://extensions/` -> Developer mode -> Load unpacked -> select `extension/` folder.
2. Test the popup UI and ensure the backend is running on `127.0.0.1:8001`.
