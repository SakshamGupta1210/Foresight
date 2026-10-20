"""
FORESIGHT: QR Code Destination Analysis & Risk Assessment
Main FastAPI Application Server with Multi-Page Routing
"""

import os
import io
from typing import Optional
from PIL import Image, UnidentifiedImageError
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
    delete_user_scan,
    clear_user_scans,
    change_user_password,
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

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: Optional[str] = None

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

@app.post("/api/auth/change-password")
async def handle_change_password(request: Request, body: ChangePasswordRequest):
    """Securely updates password after verifying current credentials."""
    user = get_current_user_required(request)
    if body.confirm_password is not None and body.new_password != body.confirm_password:
        raise HTTPException(status_code=400, detail="New password and Confirm Password do not match.")
    try:
        change_user_password(user["id"], body.current_password, body.new_password)
        return {"success": True, "message": "Password updated successfully."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to change password: {str(e)}")


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

@app.delete("/api/user/scans/{scan_id}")
async def delete_single_scan(request: Request, scan_id: str):
    """Deletes an individual scan record strictly owned by the authenticated user."""
    user = get_current_user_required(request)
    success = delete_user_scan(user["id"], scan_id)
    if not success:
        raise HTTPException(
            status_code=404,
            detail="Scan record not found or access unauthorized."
        )
    return {
        "success": True,
        "message": "Scan record deleted successfully.",
        "scan_id": scan_id
    }

@app.delete("/api/user/scans")
async def clear_all_scans(request: Request):
    """Permanently clears all personal scan history records for the current user."""
    user = get_current_user_required(request)
    deleted_count = clear_user_scans(user["id"])
    return {
        "success": True,
        "message": f"Successfully deleted {deleted_count} scan record(s).",
        "deleted_count": deleted_count
    }


# ---------------------------------------------------------------------
# DYNAMIC QR SCANNING & DESTINATION ANALYSIS (AUTH-AWARE)
# ---------------------------------------------------------------------

MAX_UPLOAD_SIZE = 15 * 1024 * 1024  # 15 MB

_IMAGE_MAGIC_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n",   # PNG
    b"\xff\xd8\xff",         # JPEG
    b"GIF87a", b"GIF89a",    # GIF
    b"BM",                   # BMP
    b"II*\x00", b"MM\x00*",  # TIFF
)

def _is_image_data(data: bytes) -> bool:
    """Verifies whether byte sequence matches known image formats or WEBP."""
    if data.startswith(_IMAGE_MAGIC_SIGNATURES):
        return True
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return True
    return False

@app.post("/api/scan-image")
async def scan_qr_image(request: Request, file: UploadFile = File(...)):
    """
    Decodes ANY valid QR code from an uploaded image dynamically.
    Provides structured, granular error feedback for unsupported, oversized,
    corrupted, or non-QR images.
    Saves the scan to the user's personal history.
    """
    try:
        contents = await file.read()
        if not contents or len(contents) == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error_code": "EMPTY_FILE",
                    "error": "Uploaded file is empty.",
                    "message": "Uploaded file is empty.",
                    "detail": "Uploaded file is empty.",
                    "details": "The submitted file contains 0 bytes."
                }
            )

        # 1. File Size Validation (15MB Limit)
        if len(contents) > MAX_UPLOAD_SIZE:
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "error_code": "FILE_TOO_LARGE",
                    "error": "The image is too large. Please choose a smaller file.",
                    "message": "The image is too large. Please choose a smaller file.",
                    "detail": "The image is too large. Please choose a smaller file.",
                    "details": f"File size ({len(contents)} bytes) exceeds the 15MB limit."
                }
            )

        # 2. File Format / Image Integrity Check
        # Check magic bytes; if not matching, check if PIL can interpret it
        is_known_format = _is_image_data(contents)
        if not is_known_format:
            try:
                with Image.open(io.BytesIO(contents)) as probe:
                    _ = probe.format
            except Exception:
                return JSONResponse(
                    status_code=415,
                    content={
                        "success": False,
                        "error_code": "UNSUPPORTED_FILE_TYPE",
                        "error": "Unsupported file type. Please upload a PNG, JPEG or WEBP image.",
                        "message": "Unsupported file type. Please upload a PNG, JPEG or WEBP image.",
                        "detail": "Unsupported file type. Please upload a PNG, JPEG or WEBP image.",
                        "details": f"Unrecognized file format (filename='{file.filename}', content_type='{file.content_type}')."
                    }
                )

        # 3. Attempt decoding with dual-engine decoder
        success, decoded_text, method = decode_qr_image(contents)

        if not success or not decoded_text:
            # Distinguish corrupted/unreadable images from valid images without QR
            if method and ("parsing error" in method.lower() or "invalid image" in method.lower()):
                return JSONResponse(
                    status_code=422,
                    content={
                        "success": False,
                        "error_code": "CORRUPTED_IMAGE",
                        "error": "We couldn't read this image. Please try another image.",
                        "message": "We couldn't read this image. Please try another image.",
                        "detail": "We couldn't read this image. Please try another image.",
                        "details": method
                    }
                )
            return JSONResponse(
                status_code=422,
                content={
                    "success": False,
                    "error_code": "NO_QR_DETECTED",
                    "error": "No QR code detected. Please upload a clear image containing a QR code.",
                    "message": "No QR code detected. Please upload a clear image containing a QR code.",
                    "detail": "No QR code detected. Please upload a clear image containing a QR code.",
                    "details": method or "No QR code detected in image"
                }
            )

        # 4. Dynamic risk evaluation for successfully decoded payload
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
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error_code": "SERVER_ERROR",
                "error": "Server error while processing image. Please try again.",
                "message": "Server error while processing image. Please try again.",
                "detail": "Server error while processing image. Please try again.",
                "details": str(e)
            }
        )


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

frontend_candidates = [
    os.environ.get("FORESIGHT_FRONTEND_DIR"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend")),
    os.path.abspath(os.path.join(os.getcwd(), "frontend")),
    os.path.abspath("frontend"),
    "/var/task/frontend",
]
frontend_dir = None
for cand in frontend_candidates:
    if cand and os.path.isdir(cand):
        frontend_dir = os.path.abspath(cand)
        break

pages_dir = os.path.join(frontend_dir, "pages") if frontend_dir else ""

if frontend_dir and os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# Explicit fallback routes for core static assets (prevents 404s on serverless)
@app.get("/static/css/styles.css")
async def static_styles():
    if frontend_dir:
        p = os.path.join(frontend_dir, "css", "styles.css")
        if os.path.exists(p):
            return FileResponse(p, media_type="text/css")
    raise HTTPException(status_code=404, detail="styles.css not found")

@app.get("/static/js/auth-guard.js")
async def static_auth_guard():
    if frontend_dir:
        p = os.path.join(frontend_dir, "js", "auth-guard.js")
        if os.path.exists(p):
            return FileResponse(p, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="auth-guard.js not found")

@app.get("/static/js/app.js")
async def static_app_js():
    if frontend_dir:
        p = os.path.join(frontend_dir, "js", "app.js")
        if os.path.exists(p):
            return FileResponse(p, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")

@app.get("/static/js/jsQR.js")
async def static_jsqr():
    if frontend_dir:
        p = os.path.join(frontend_dir, "js", "jsQR.js")
        if os.path.exists(p):
            return FileResponse(p, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="jsQR.js not found")

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
