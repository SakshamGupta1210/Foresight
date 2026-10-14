"""
FORESIGHT: QR Code Destination Analysis & Risk Assessment
Main FastAPI Application Server with Multi-Page Routing
"""

import os
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .analyzer.risk_engine import evaluate_destination
from .storage.access_tracker import (
    init_db,
    get_db,
    create_user,
    authenticate_user,
    get_user_by_token,
    delete_session,
    save_user_scan,
    get_user_scans,
    get_user_scan_by_id,
    get_user_dashboard_stats,
    record_access,
    get_all_incidents,
    get_incident_by_id,
    get_platform_stats
)
from .qr_decoder import decode_qr_image

# Initialize database schema. Never let a DB problem crash the whole
# serverless function at import time; log it and retry on first use
# (every storage function calls init_db() again).
try:
    init_db()
except Exception as exc:  # noqa: BLE001
    print(f"[FORESIGHT] init_db failed at startup: {exc!r}", flush=True)

app = FastAPI(
    title="FORESIGHT API",
    description="QR Code Destination Analysis & Risk Assessment Platform",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ---------------------------------------------------------------------
# AUTHENTICATION HELPERS & DEPENDENCIES
# ---------------------------------------------------------------------

def get_current_user_optional(request: Request) -> Optional[dict]:
    """Extracts logged-in user from Authorization: Bearer <token> if present."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        token = request.query_params.get("token")
        if token:
            return get_user_by_token(token)
        return None

    parts = auth_header.strip().split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return get_user_by_token(parts[1])
    return None

def get_current_user_required(request: Request) -> dict:
    """Enforces authentication for protected API routes."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please sign in to continue."
        )
    return user


# ---------------------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    confirm_password: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

class AnalyzeRequest(BaseModel):
    payload: str
    client_id: Optional[str] = None
    follow_redirects: Optional[bool] = True
    action_taken: Optional[str] = "AVOID"


# ---------------------------------------------------------------------
# AUTHENTICATION ENDPOINTS
# ---------------------------------------------------------------------

@app.post("/api/auth/register")
async def register(body: RegisterRequest):
    """Registers a new user account with PBKDF2-HMAC-SHA256 password hashing."""
    if body.confirm_password is not None and body.password != body.confirm_password:
        raise HTTPException(status_code=400, detail="Password and Confirm Password do not match.")

    try:
        user_data, token = create_user(body.name, body.email, body.password)
        return {
            "success": True,
            "message": "Account created successfully.",
            "user": user_data,
            "token": token
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login")
async def login(body: LoginRequest):
    """Authenticates credentials and returns a secure session token."""
    try:
        user_data, token = authenticate_user(body.email, body.password)
        return {
            "success": True,
            "message": "Login successful.",
            "user": user_data,
            "token": token
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Invalidates session token."""
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.strip().split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        delete_session(parts[1])
    return {"success": True, "message": "Logged out successfully."}

@app.get("/api/auth/me")
async def get_my_profile(request: Request):
    """Retrieves current user profile and scan statistics."""
    user = get_current_user_required(request)
    stats = get_user_dashboard_stats(user["id"])
    return {
        "success": True,
        "user": user,
        "summary": {
            "total_scans": stats["total_scans"],
            "safe_scans": stats["safe_scans"],
            "suspicious_scans": stats["suspicious_scans"],
            "dangerous_scans": stats["dangerous_scans"]
        }
    }


# ---------------------------------------------------------------------
# USER SCAN HISTORY ENDPOINTS (STRICT DATA ISOLATION)
# ---------------------------------------------------------------------

@app.get("/api/user/scans")
async def list_user_scans(
    request: Request,
    status: str = Query("ALL", description="Filter by SAFE, SUSPICIOUS, DANGEROUS, or ALL"),
    search: str = Query("", description="Search term for domain or URL")
):
    """Returns personal scan history strictly isolated for the logged-in user."""
    user = get_current_user_required(request)
    scans = get_user_scans(user["id"], status_filter=status, search_query=search)
    return {
        "success": True,
        "count": len(scans),
        "filter": status,
        "search": search,
        "scans": scans
    }

@app.get("/api/user/scans/{scan_id}")
async def get_single_scan_details(request: Request, scan_id: str):
    """Retrieves full forensic details of a past scan belonging to the current user."""
    user = get_current_user_required(request)
    scan = get_user_scan_by_id(user["id"], scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan record not found or access unauthorized."
        )
    return {
        "success": True,
        "scan": scan
    }


# ---------------------------------------------------------------------
# DYNAMIC QR SCANNING & DESTINATION ANALYSIS (AUTH-AWARE)
# ---------------------------------------------------------------------

@app.post("/api/scan-image")
async def scan_qr_image(request: Request, file: UploadFile = File(...)):
    """
    Decodes ANY valid QR code from an uploaded image dynamically.
    Saves the scan to the user's personal history.
    """
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        success, decoded_text, method = decode_qr_image(contents)
        if not success or not decoded_text:
            return JSONResponse(
                status_code=422,
                content={
                    "success": False,
                    "error": "No valid QR code could be decoded from this image.",
                    "details": method
                }
            )

        # Dynamic risk evaluation
        analysis = evaluate_destination(decoded_text, follow_redirects=True)
        target_for_tracking = analysis.get("final_url") or decoded_text

        # Global access tracking for Cybercell 24h threshold
        client_ip = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get("User-Agent", "UnknownAgent")
        client_id = f"{client_ip}_{user_agent}"
        access_stats = record_access(target_for_tracking, client_id, analysis_result=analysis)

        # Associate with logged-in user
        current_user = get_current_user_optional(request)
        saved_scan = None
        if current_user:
            saved_scan = save_user_scan(current_user["id"], analysis, action_taken="INSPECTED")

        return {
            "success": True,
            "decoded_text": decoded_text,
            "decode_method": method,
            "analysis": analysis,
            "access_tracking": access_stats,
            "saved_scan": saved_scan
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process image: {str(e)}")


@app.post("/api/analyze")
async def analyze_destination(request: Request, body: AnalyzeRequest):
    """
    Analyzes ANY destination URL/payload dynamically.
    Saves the scan to the user's personal history.
    """
    raw_payload = body.payload.strip()
    if not raw_payload:
        raise HTTPException(status_code=400, detail="Destination payload cannot be empty.")

    # Evaluate destination risk dynamically
    analysis = evaluate_destination(
        raw_payload,
        follow_redirects=body.follow_redirects if body.follow_redirects is not None else True
    )
    target_for_tracking = analysis.get("final_url") or raw_payload

    # Global access tracking for Cybercell 24h threshold
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "UnknownAgent")
    client_id = body.client_id or f"{client_ip}_{user_agent}"
    access_stats = record_access(target_for_tracking, client_id, analysis_result=analysis)

    # Associate with logged-in user
    current_user = get_current_user_optional(request)
    saved_scan = None
    if current_user:
        action = body.action_taken or "INSPECTED"
        saved_scan = save_user_scan(current_user["id"], analysis, action_taken=action)

    return {
        "success": True,
        "analysis": analysis,
        "access_tracking": access_stats,
        "saved_scan": saved_scan
    }


# ---------------------------------------------------------------------
# CYBERCELL INCIDENT REPORTS (GLOBAL 24H THRESHOLD)
# ---------------------------------------------------------------------

@app.get("/api/incidents")
async def list_cybercell_incidents():
    """Retrieves all triggered cybercell incident reports."""
    incidents = get_all_incidents()
    return {
        "success": True,
        "count": len(incidents),
        "incidents": incidents
    }

@app.get("/api/incidents/{incident_id}")
async def get_incident_dossier(incident_id: str):
    """Retrieves full cybercell incident report dossier by ID."""
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident report not found.")
    return {
        "success": True,
        "incident": incident
    }

@app.get("/api/stats")
async def get_system_stats():
    """Returns general platform monitoring stats."""
    return get_platform_stats()


# ---------------------------------------------------------------------
# MULTI-PAGE APPLICATION ROUTES & STATIC ASSETS
# ---------------------------------------------------------------------

frontend_dir = os.environ.get("FORESIGHT_FRONTEND_DIR")
if not frontend_dir or not os.path.isdir(frontend_dir):
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
    if not os.path.isdir(frontend_dir):
        candidate = os.path.abspath("frontend")
        if os.path.isdir(candidate):
            frontend_dir = candidate

pages_dir = os.path.join(frontend_dir, "pages") if frontend_dir else ""

if frontend_dir and os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/", response_class=RedirectResponse)
async def root():
    """First page must be Login."""
    return RedirectResponse(url="/login")

@app.get("/login", response_class=FileResponse)
async def page_login():
    """PAGE 1 — LOGIN."""
    file_path = os.path.join(pages_dir, "login.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Login page not found")

@app.get("/signup", response_class=FileResponse)
async def page_signup():
    """PAGE 2 — SIGN UP."""
    file_path = os.path.join(pages_dir, "signup.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Signup page not found")

@app.get("/scan", response_class=FileResponse)
async def page_scan():
    """PAGE 3 — SCAN QR (Main page after login)."""
    file_path = os.path.join(pages_dir, "scan.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Scan page not found")

@app.get("/result/{scan_id}", response_class=FileResponse)
async def page_result(scan_id: str):
    """PAGE 4 — ANALYSIS RESULT."""
    file_path = os.path.join(pages_dir, "result.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Result page not found")

@app.get("/history", response_class=FileResponse)
async def page_history():
    """PAGE 5 — SCAN HISTORY."""
    file_path = os.path.join(pages_dir, "history.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="History page not found")

@app.get("/profile", response_class=FileResponse)
async def page_profile():
    """PAGE 6 — PROFILE."""
    file_path = os.path.join(pages_dir, "profile.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Profile page not found")

@app.get("/reports", response_class=FileResponse)
async def page_reports():
    """PAGE 7 — REPORTS."""
    file_path = os.path.join(pages_dir, "reports.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Reports page not found")
