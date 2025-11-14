from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from typing import Optional
import json
import os

security = HTTPBasic()

# Load credentials from config file or use defaults
def load_credentials() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except:
        # Default credentials - make sure to change these!
        return {
            "username": "admin",
            "password": "phishguard2024"
        }

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Verify HTTP Basic Auth credentials"""
    config = load_credentials()
    correct_username = secrets.compare_digest(credentials.username, config["username"])
    correct_password = secrets.compare_digest(credentials.password, config["password"])
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return credentials.username