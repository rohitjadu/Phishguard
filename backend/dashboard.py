"""
PhishGuard Admin Dashboard
Run: python -m uvicorn dashboard:app --reload
Visit: http://127.0.0.1:8000/dashboard
"""
from fastapi import FastAPI, Query, Request, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import Optional, List
import pandas as pd
import os

from auth import verify_credentials
from utils import (
    Message, DashboardStats, get_csv_path, read_dataframe,
    clean_dataframe, get_pending_reports_count
)

# Predefined list of sources used in the project
DEFAULT_SOURCES = [
    "model",          # ML model predictions
    "dataset",        # PhishTank dataset matches
    "manual",         # User manual reports
    "whitelist",      # Whitelist matches
    "extension"       # Browser extension reports
]

app = FastAPI(title="PhishGuard Admin")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
templates_dir = os.path.join(os.path.dirname(__file__), "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Templates
templates = Jinja2Templates(directory=templates_dir)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/download-csv")
async def download_csv(
    start_date: str = Query(None),
    end_date: str = Query(None),
    min_confidence: str = Query(None),  # Changed to str to handle empty values
    source: str = Query(None)
):
    try:
        csv_path = os.path.join(os.path.dirname(__file__), "phishing_reports.csv")
        if not os.path.exists(csv_path):
            return HTMLResponse(
                content="<h1>No data available</h1>",
                status_code=404
            )
        
        df = pd.read_csv(csv_path)
        
        # Apply filters (robust datetime parsing)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            if start_date:
                start_dt = pd.to_datetime(start_date, errors='coerce')
                if pd.notna(start_dt):
                    df = df[df['timestamp'] >= start_dt]
            if end_date:
                end_dt = pd.to_datetime(end_date, errors='coerce')
                if pd.notna(end_dt):
                    df = df[df['timestamp'] <= end_dt]
        if min_confidence and min_confidence.strip():
            try:
                df['confidence'] = pd.to_numeric(df['confidence'], errors='coerce')
                df = df[df['confidence'] >= float(min_confidence)]
            except (ValueError, TypeError):
                pass
        if source:
            df = df[df['source'] == source]
        
        # Save filtered data to temporary file
        temp_path = os.path.join(os.path.dirname(__file__), "filtered_reports.csv")
        df.to_csv(temp_path, index=False)
        return FileResponse(temp_path, filename="phishing_reports_filtered.csv")
    except Exception as e:
        return HTMLResponse(
            content=f"<h1>Error processing request</h1><p>{str(e)}</p>",
            status_code=500
        )
    


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    username: str = Depends(verify_credentials),
    start_date: str = Query(None),
    end_date: str = Query(None),
    min_confidence: str = Query(None),
    source: str = Query(None)
):
    """Main dashboard view showing reports stats and filters."""
    try:
        csv_path = os.path.join(os.path.dirname(__file__), "phishing_reports.csv")
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            df = clean_dataframe(df, {
                'url': '',
                'timestamp': '',
                'confidence': 0.0,
                'model': '',
                'source': '',
                'labeled': False,
                'labeler_label': '',
                'labeled_at': ''
            })
        else:
            df = pd.DataFrame()

        # Apply filters
        if not df.empty:
            # normalize timestamp column and apply filters safely
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if start_date and start_date.strip():
                    start_dt = pd.to_datetime(start_date, errors='coerce')
                    if pd.notna(start_dt):
                        df = df[df['timestamp'] >= start_dt]
                if end_date and end_date.strip():
                    end_dt = pd.to_datetime(end_date, errors='coerce')
                    if pd.notna(end_dt):
                        df = df[df['timestamp'] <= end_dt]
            if min_confidence and min_confidence.strip():
                try:
                    df['confidence'] = pd.to_numeric(df['confidence'], errors='coerce')
                    conf_value = float(min_confidence)
                    df = df[df['confidence'] >= conf_value]
                except (ValueError, TypeError):
                    pass  # Invalid confidence value, ignore filter
            if source and source.strip():
                df = df[df['source'] == source.strip()]

        total = len(df)
        last_rows = df.tail(50) if not df.empty else pd.DataFrame()

        data_sources = df['source'].unique().tolist() if not df.empty and 'source' in df.columns else []
        sources = sorted(list(set(DEFAULT_SOURCES + data_sources)))

        source_stats = df['source'].value_counts().to_dict() if not df.empty and 'source' in df.columns else {}
        source_percentages = (df['source'].value_counts(normalize=True) * 100).round(1).to_dict() if not df.empty and 'source' in df.columns else {}

        # normalize timestamp for last_rows
        if not last_rows.empty and 'timestamp' in last_rows.columns:
            last_rows = last_rows.copy()
            last_rows['timestamp'] = last_rows['timestamp'].astype(str)

        pending_count = get_pending_reports_count()

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "username": username,
                "pending_reports_count": pending_count,
                "start_date": start_date or (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
                "end_date": end_date or datetime.now().strftime('%Y-%m-%d'),
                "min_confidence": min_confidence,
                "source": source,
                "sources": sources or DEFAULT_SOURCES,
                "total": total,
                "rows": last_rows.to_dict('records') if not last_rows.empty else [],
                "source_stats": source_stats,
                "source_percentages": source_percentages
            }
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<h3>Error loading dashboard</h3><p>{str(e)}</p>",
            status_code=500
        )


@app.get("/reports.json")
async def reports_json(
    start_date: str = Query(None),
    end_date: str = Query(None),
    min_confidence: str = Query(None),
    source: str = Query(None)
):
    """Return filtered reports as JSON for client-side polling."""
    try:
        csv_path = os.path.join(os.path.dirname(__file__), "phishing_reports.csv")
        if not os.path.exists(csv_path):
            return {"total": 0, "rows": [], "source_stats": {}, "source_percentages": {}}

        df = pd.read_csv(csv_path)

        # Apply same filters as dashboard
        if not df.empty:
            # normalize timestamp column and apply filters safely
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                if start_date and start_date.strip():
                    start_dt = pd.to_datetime(start_date, errors='coerce')
                    if pd.notna(start_dt):
                        df = df[df['timestamp'] >= start_dt]
                if end_date and end_date.strip():
                    end_dt = pd.to_datetime(end_date, errors='coerce')
                    if pd.notna(end_dt):
                        df = df[df['timestamp'] <= end_dt]
            if min_confidence and min_confidence.strip():
                try:
                    df['confidence'] = pd.to_numeric(df['confidence'], errors='coerce')
                    conf_value = float(min_confidence)
                    df = df[df['confidence'] >= conf_value]
                except (ValueError, TypeError):
                    pass  # Invalid confidence value, ignore filter
            if source and source.strip():
                df = df[df['source'] == source.strip()]

        total = len(df)
        last_rows = df.tail(50)

        # normalize timestamp and convert to records
        if 'timestamp' in last_rows.columns:
            last_rows['timestamp'] = last_rows['timestamp'].astype(str)
        rows = last_rows.to_dict(orient='records') if not last_rows.empty else []

        source_stats = df['source'].value_counts().to_dict() if 'source' in df.columns else {}
        source_percentages = (df['source'].value_counts(normalize=True) * 100).round(1).to_dict() if 'source' in df.columns else {}

        # Safely convert each row — preserve strings, convert numerics
        def safe_val(v):
            try:
                if pd.isna(v):
                    return None
            except Exception:
                pass
            import numpy as np
            if isinstance(v, (np.integer,)):
                return int(v)
            if isinstance(v, (np.floating,)):
                return None if np.isnan(v) else float(v)
            if isinstance(v, float):
                return None if v != v else v
            if isinstance(v, int):
                return v
            return str(v) if v is not None else None

        rows_sanitized = [
            {k: safe_val(v) for k, v in rec.items()}
            for rec in rows
        ]

        def safe_int(v):
            try: return int(v)
            except: return 0
        def safe_float(v):
            try: return float(v)
            except: return 0.0

        source_stats_out = {str(k): safe_int(v) for k, v in source_stats.items()} if source_stats else {}
        source_pct_out   = {str(k): safe_float(v) for k, v in source_percentages.items()} if source_percentages else {}

        return {
            "total": int(total),
            "rows": rows_sanitized,
            "source_stats": source_stats_out,
            "source_percentages": source_pct_out,
        }
    except Exception as e:
        import traceback
        return {"error": str(e), "trace": traceback.format_exc()}


@app.get("/label", response_class=HTMLResponse)
async def label_page(request: Request):
    """Simple labeling UI: shows recent runtime predictions and allows labeling as phishing (1) or safe (0)."""
    try:
        runtime_path = os.path.join(os.path.dirname(__file__), "runtime_predictions.csv")
        if not os.path.exists(runtime_path):
            return HTMLResponse(content="<h3>No runtime predictions collected yet.</h3>", status_code=200)

        rdf = pd.read_csv(runtime_path)
        # filter out already labeled rows if present
        if 'labeled' in rdf.columns:
            display_df = rdf[~rdf['labeled'].astype(bool)].tail(200).iloc[::-1]
        else:
            display_df = rdf.tail(200).iloc[::-1]

        rows_html = ""
        for i, r in display_df.iterrows():
            url = str(r.get('url',''))
            prob = r.get('probability', '')
            pred = r.get('prediction','')
            ts = r.get('timestamp','')
            # escape single quotes in url for embedding
            url_escaped = url.replace("'", "\'")
            rows_html += f"""
                <tr>
                    <td>{ts}</td>
                    <td style=\"max-width:420px;word-break:break-all;\"><a href='{url_escaped}' target='_blank'>{url}</a></td>
                    <td>{prob}</td>
                    <td>{pred}</td>
                    <td>
                        <form method=\"post\" action=\"/label\" style=\"display:inline-block;margin-right:6px;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"label\" value=\"1\" />
                            <button class=\"btn btn-sm btn-danger\" type=\"submit\">Mark Phishing</button>
                        </form>
                        <form method=\"post\" action=\"/label\" style=\"display:inline-block;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"label\" value=\"0\" />
                            <button class=\"btn btn-sm btn-success\" type=\"submit\">Mark Safe</button>
                        </form>
                    </td>
                </tr>
            """

        msg = request.query_params.get('msg', '')
        header_line = f'<h3 style="font-family:var(--font-title);color:var(--neon-cyan);font-size:15px;letter-spacing:3px">// RUNTIME PREDICTIONS</h3>' if not msg else f'<h3 style="font-family:var(--font-title);color:var(--neon-cyan);font-size:15px;letter-spacing:3px">// RUNTIME PREDICTIONS <small style="color:var(--neon-green);font-size:11px">{msg}</small></h3>'

        html = f"""
        <html>
        <head>
            <title>PhishGuard — Label Data</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;800&family=Share+Tech+Mono&display=swap" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <link href="/static/css/style.css" rel="stylesheet">
        </head>
        <body style="display:block;margin-left:0">
            <div class="grid-bg"></div>
            <div class="scanlines"></div>
            <div style="padding:20px 28px;position:relative;z-index:2">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
                    {header_line}
                    <a class="btn btn-secondary" href="/dashboard"><i class="bi bi-arrow-left"></i> Dashboard</a>
                </div>
                <p style="color:var(--text-dim);margin-bottom:14px;font-size:12px">Click a button to label the URL — appends to <code style="color:var(--neon-cyan)">labeled_urls.csv</code>.</p>
                <div class="hud-panel">
                    <div class="panel-header"><span class="panel-title"><i class="bi bi-tag"></i> RUNTIME PREDICTIONS</span></div>
                    <div class="table-responsive">
                        <table class="hud-table">
                            <thead><tr><th>TIMESTAMP</th><th>URL</th><th>PROBABILITY</th><th>PREDICTION</th><th>LABEL ACTION</th></tr></thead>
                            <tbody>{rows_html}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading label page</h3><p>{str(e)}</p>", status_code=500)


@app.post("/label")
async def label_submit(url: str = Form(...), label: int = Form(...)):
    """Append labeled URL to labeled_urls.csv and mark runtime entries as labeled."""
    try:
        labels_path = os.path.join(os.path.dirname(__file__), "labeled_urls.csv")
        cleaned = url.strip()
        # Read existing labels and update/dedupe
        existing = {}
        if os.path.exists(labels_path):
            try:
                import csv as _csv
                with open(labels_path, "r", encoding="utf-8", errors="ignore") as rf:
                    reader = _csv.reader(rf)
                    next(reader, None)
                    for r in reader:
                        if not r: continue
                        u = r[0].strip()
                        lab = r[1].strip() if len(r) > 1 else ""
                        existing[u.lower()] = lab
            except Exception:
                pass

        # If exists and same label -> skip
        if existing.get(cleaned.lower()) is not None:
            try:
                if str(int(label)) == str(int(existing.get(cleaned.lower()) or '')):
                    # already present with same label
                    return RedirectResponse(url="/label?msg=Already+exists", status_code=303)
            except Exception:
                # fall through to update
                pass

        # If exists with different label -> update file
        if existing.get(cleaned.lower()) is not None and str(existing.get(cleaned.lower())) != str(int(label)):
            try:
                # rewrite CSV with updated label for matching url
                import csv as _csv
                rows = []
                with open(labels_path, "r", encoding="utf-8", errors="ignore") as rf:
                    reader = _csv.reader(rf)
                    header = next(reader, None)
                    for r in reader:
                        if not r: continue
                        u = r[0].strip()
                        if u.lower() == cleaned.lower():
                            rows.append([u, str(int(label))])
                        else:
                            rows.append([r[0].strip(), r[1].strip() if len(r) > 1 else ''])
                with open(labels_path, "w", encoding="utf-8", newline="") as wf:
                    writer = _csv.writer(wf)
                    writer.writerow(["url", "label"]) if header is None else writer.writerow(header)
                    writer.writerows(rows)
            except Exception:
                # fallback to append if update fails
                with open(labels_path, "a", encoding="utf-8", newline="") as lf:
                    if os.path.getsize(labels_path) == 0:
                        lf.write("url,label\n")
                    lf.write(f"{cleaned},{int(label)}\n")
        else:
            # append new
            write_header = not os.path.exists(labels_path) or os.path.getsize(labels_path) == 0
            with open(labels_path, "a", encoding="utf-8", newline="") as lf:
                if write_header:
                    lf.write("url,label\n")
                lf.write(f"{cleaned},{int(label)}\n")
        # Mark runtime entries as labeled so they are hidden from the UI
        try:
            runtime_path = os.path.join(os.path.dirname(__file__), "runtime_predictions.csv")
            if os.path.exists(runtime_path):
                rdf = pd.read_csv(runtime_path)
                # create columns if missing
                if 'labeled' not in rdf.columns:
                    rdf['labeled'] = False
                if 'labeler_label' not in rdf.columns:
                    rdf['labeler_label'] = ''
                if 'labeled_at' not in rdf.columns:
                    rdf['labeled_at'] = ''
                # mark rows that match this URL (exact match)
                mask = rdf['url'].astype(str).str.strip() == cleaned
                if mask.any():
                    rdf.loc[mask, 'labeled'] = True
                    rdf.loc[mask, 'labeler_label'] = int(label)
                    rdf.loc[mask, 'labeled_at'] = datetime.utcnow().isoformat()
                    rdf.to_csv(runtime_path, index=False)
        except Exception:
            # non-fatal
            pass

        return RedirectResponse(url="/label?msg=Saved", status_code=303)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error labeling URL</h3><p>{str(e)}</p>", status_code=500)


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Admin page: show unresolved reports from phishing_reports.csv and allow marking as Safe/Phishing.
    Marks will append to labeled_urls.csv and annotate the report row as labeled.
    """
    try:
        csv_path = os.path.join(os.path.dirname(__file__), "phishing_reports.csv")
        if not os.path.exists(csv_path):
            return HTMLResponse(content="<h3>No reports yet.</h3>", status_code=200)

        df = pd.read_csv(csv_path)
        # Clean any NaN values
        df = df.fillna({
            'url': '',
            'timestamp': '',
            'confidence': 0.0,
            'model': '',
            'source': '',
            'labeled': False,
            'labeler_label': '',
            'labeled_at': ''
        })
        # show only rows not yet labeled
        if 'labeled' in df.columns:
            unlabeled = df[~df['labeled'].astype(bool)]
        else:
            unlabeled = df

        # Split into false positives vs other reports
        fp_mask = (
            (unlabeled['source'] == 'pending_review') | 
            (unlabeled['model'] == 'false_positive_pending') |
            (unlabeled['confidence'] == 'pending_safe')
        )
        fp_df = unlabeled[fp_mask].tail(200).iloc[::-1]
        other_df = unlabeled[~fp_mask].tail(200).iloc[::-1]

        # Render false positives table
        pending_false_positives_html = ""
        for _, r in fp_df.iterrows():
            url = str(r.get('url',''))
            ts = str(r.get('timestamp',''))
            source = r.get('source','')
            url_escaped = url.replace("'", "\'")
            pending_false_positives_html += f"""
                <tr>
                    <td>{ts}</td>
                    <td style=\"max-width:420px;word-break:break-all;\"><a href='{url_escaped}' target='_blank'>{url}</a></td>
                    <td><span class="badge bg-info">User Report</span></td>
                    <td><span class="badge bg-warning">Pending Review</span></td>
                    <td>
                        <form method=\"post\" action=\"/resolve_report\" style=\"display:inline-block;margin-right:6px;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"timestamp\" value=\"{ts}\" />
                            <input type=\"hidden\" name=\"label\" value=\"0\" />
                            <input type=\"hidden\" name=\"was_false_positive\" value=\"1\" />
                            <button class=\"btn btn-sm btn-success\" type=\"submit\">Confirm Safe</button>
                        </form>
                        <form method=\"post\" action=\"/resolve_report\" style=\"display:inline-block;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"timestamp\" value=\"{ts}\" />
                            <input type=\"hidden\" name=\"label\" value=\"1\" />
                            <input type=\"hidden\" name=\"was_false_positive\" value=\"1\" />
                            <button class=\"btn btn-sm btn-warning\" type=\"submit\">Mark as Phishing</button>
                        </form>
                    </td>
                </tr>
            """

        # Render other reports table
        rows_html = ""
        for _, r in other_df.iterrows():
            url = str(r.get('url',''))
            ts = str(r.get('timestamp',''))
            conf = r.get('confidence','')
            model = r.get('model','')
            source = r.get('source','')
            url_escaped = url.replace("'", "\'")
            rows_html += f"""
                <tr>
                    <td>{ts}</td>
                    <td style=\"max-width:420px;word-break:break-all;\"><a href='{url_escaped}' target='_blank'>{url}</a></td>
                    <td>{conf}</td>
                    <td>{model}</td>
                    <td>{source}</td>
                    <td>
                        <form method=\"post\" action=\"/resolve_report\" style=\"display:inline-block;margin-right:6px;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"timestamp\" value=\"{ts}\" />
                            <input type=\"hidden\" name=\"label\" value=\"1\" />
                            <button class=\"btn btn-sm btn-danger\" type=\"submit\">Mark Phishing</button>
                        </form>
                        <form method=\"post\" action=\"/resolve_report\" style=\"display:inline-block;\">
                            <input type=\"hidden\" name=\"url\" value=\"{url}\" />
                            <input type=\"hidden\" name=\"timestamp\" value=\"{ts}\" />
                            <input type=\"hidden\" name=\"label\" value=\"0\" />
                            <button class=\"btn btn-sm btn-success\" type=\"submit\">Mark Safe</button>
                        </form>
                    </td>
                </tr>
            """
        
        html = f"""
        <html>
        <head>
            <title>PhishGuard — Reports Review</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;800&family=Share+Tech+Mono&display=swap" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <link href="/static/css/style.css" rel="stylesheet">
        </head>
        <body style="display:block;margin-left:0">
            <div class="grid-bg"></div>
            <div class="scanlines"></div>
            <div style="padding:20px 28px;position:relative;z-index:2">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
                    <h3 style="font-family:var(--font-title);color:var(--neon-cyan);font-size:15px;letter-spacing:3px">// REPORTS PENDING REVIEW</h3>
                    <a class="btn btn-secondary" href="/dashboard"><i class="bi bi-arrow-left"></i> Dashboard</a>
                </div>

                <div class="hud-panel" style="margin-bottom:20px">
                    <div class="panel-header">
                        <span class="panel-title"><i class="bi bi-exclamation-triangle"></i> FALSE POSITIVE QUEUE</span>
                        <span style="font-size:10px;color:var(--neon-orange)">Users reported these as safe — verify before approving</span>
                    </div>
                    <div class="table-responsive">
                        <table class="hud-table">
                            <thead><tr><th>TIMESTAMP</th><th>URL TARGET</th><th>REPORTER</th><th>STATUS</th><th>RESOLVE</th></tr></thead>
                            <tbody>{pending_false_positives_html}</tbody>
                        </table>
                    </div>
                </div>

                <div class="hud-panel">
                    <div class="panel-header"><span class="panel-title"><i class="bi bi-flag"></i> PENDING THREAT REPORTS</span></div>
                    <div class="table-responsive">
                        <table class="hud-table">
                            <thead><tr><th>TIMESTAMP</th><th>URL TARGET</th><th>CONFIDENCE</th><th>MODEL</th><th>SOURCE</th><th>RESOLVE</th></tr></thead>
                            <tbody>{rows_html}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading reports page</h3><p>{str(e)}</p>", status_code=500)


@app.post("/resolve_report")
async def resolve_report(url: str = Form(...), timestamp: str = Form(None), label: int = Form(...)):
    """Admin action: append labeled URL and mark reports rows as labeled/resolved."""
    try:
        # Append to labeled_urls.csv (dedupe/update behavior)
        labels_path = os.path.join(os.path.dirname(__file__), "labeled_urls.csv")
        cleaned = url.strip()
        existing = {}
        if os.path.exists(labels_path):
            try:
                import csv as _csv
                with open(labels_path, "r", encoding="utf-8", errors="ignore") as rf:
                    reader = _csv.reader(rf)
                    next(reader, None)
                    for r in reader:
                        if not r: continue
                        u = r[0].strip()
                        lab = r[1].strip() if len(r) > 1 else ''
                        existing[u.lower()] = lab
            except Exception:
                pass

        if existing.get(cleaned.lower()) is not None:
            # if same label, skip; if different, update
            try:
                if str(int(existing.get(cleaned.lower()) or '')) == str(int(label)):
                    # nothing to do
                    pass
                else:
                    # update existing row
                    try:
                        import csv as _csv
                        rows = []
                        with open(labels_path, "r", encoding="utf-8", errors="ignore") as rf:
                            reader = _csv.reader(rf)
                            header = next(reader, None)
                            for r in reader:
                                if not r: continue
                                u = r[0].strip()
                                if u.lower() == cleaned.lower():
                                    rows.append([u, str(int(label))])
                                else:
                                    rows.append([r[0].strip(), r[1].strip() if len(r) > 1 else ''])
                        with open(labels_path, "w", encoding="utf-8", newline="") as wf:
                            writer = _csv.writer(wf)
                            writer.writerow(["url", "label"]) if header is None else writer.writerow(header)
                            writer.writerows(rows)
                    except Exception:
                        # fallback to append
                        with open(labels_path, "a", encoding="utf-8", newline="") as lf:
                            if os.path.getsize(labels_path) == 0:
                                lf.write("url,label\n")
                            lf.write(f"{cleaned},{int(label)}\n")
            except Exception:
                pass
        else:
            # append new
            write_header = not os.path.exists(labels_path) or os.path.getsize(labels_path) == 0
            with open(labels_path, "a", encoding="utf-8", newline="") as lf:
                if write_header:
                    lf.write("url,label\n")
                lf.write(f"{cleaned},{int(label)}\n")

            # Mark matching rows in phishing_reports.csv as labeled
            reports_path = os.path.join(os.path.dirname(__file__), "phishing_reports.csv")
            try:
                if os.path.exists(reports_path):
                    rdf = pd.read_csv(reports_path)
                    if 'labeled' not in rdf.columns:
                        rdf['labeled'] = False
                    if 'labeler_label' not in rdf.columns:
                        rdf['labeler_label'] = ''
                    if 'labeled_at' not in rdf.columns:
                        rdf['labeled_at'] = ''
                    # try to match by timestamp and url, fallback to url-only match
                    mask = (rdf['url'].astype(str).str.strip() == cleaned)
                    if timestamp:
                        mask = mask & (rdf['timestamp'].astype(str).str.strip() == timestamp.strip())
                    if mask.any():
                        rdf.loc[mask, 'labeled'] = True
                        rdf.loc[mask, 'labeler_label'] = int(label)
                        rdf.loc[mask, 'labeled_at'] = datetime.utcnow().isoformat()
                        rdf.to_csv(reports_path, index=False)
            except Exception:
                # non-fatal
                pass

            # Also update runtime_predictions.csv if the URL exists there
            runtime_path = os.path.join(os.path.dirname(__file__), "runtime_predictions.csv")
            try:
                if os.path.exists(runtime_path):
                    rtdf = pd.read_csv(runtime_path)
                    # Mark matching URLs as labeled
                    mask = rtdf['url'].astype(str).str.strip() == cleaned
                    if mask.any():
                        rtdf.loc[mask, 'labeled'] = True
                        rtdf.loc[mask, 'labeler_label'] = int(label)
                        rtdf.loc[mask, 'labeled_at'] = datetime.utcnow().isoformat()
                        # Also update the prediction to match the label
                        rtdf.loc[mask, 'prediction'] = int(label)
                        rtdf.loc[mask, 'probability'] = 1.0 if int(label) == 1 else 0.0
                        # Clean any NaN values before saving
                        rtdf = rtdf.fillna({'prediction': 0, 'probability': 0.0, 'labeled': False, 'labeler_label': '', 'labeled_at': ''})
                        rtdf.to_csv(runtime_path, index=False)
            except Exception:
                # non-fatal
                pass
        return RedirectResponse(url="/reports", status_code=303)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error resolving report</h3><p>{str(e)}</p>", status_code=500)
