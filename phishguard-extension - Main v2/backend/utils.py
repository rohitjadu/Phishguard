import os
from datetime import datetime
import pandas as pd
from typing import Dict, List, Optional, Union
from pydantic import BaseModel

class Message(BaseModel):
    type: str  # success, info, warning, danger
    text: str

class DashboardStats(BaseModel):
    total: int
    rows: List[Dict]
    source_stats: Dict[str, int]
    source_percentages: Dict[str, float]

def get_csv_path(filename: str) -> str:
    """Get absolute path for a CSV file in the backend directory"""
    return os.path.join(os.path.dirname(__file__), filename)

def read_dataframe(filename: str, default_columns: Dict = None) -> pd.DataFrame:
    """Read a CSV file and ensure required columns exist"""
    path = get_csv_path(filename)
    if not os.path.exists(path):
        # Create empty DataFrame with default columns
        return pd.DataFrame(columns=list(default_columns.keys()) if default_columns else [])
    
    df = pd.read_csv(path)
    
    if default_columns:
        # Add any missing columns with default values
        for col, default in default_columns.items():
            if col not in df.columns:
                df[col] = default
    
    return df

def clean_dataframe(df: pd.DataFrame, column_defaults: Dict[str, Union[str, int, float, bool]]) -> pd.DataFrame:
    """Clean NaN values in DataFrame using specified defaults"""
    return df.fillna(column_defaults)

def get_pending_reports_count() -> int:
    """Get count of unresolved reports"""
    try:
        df = read_dataframe("phishing_reports.csv")
        if df.empty:
            return 0
        return len(df[~df.get('labeled', False)])
    except Exception:
        return 0