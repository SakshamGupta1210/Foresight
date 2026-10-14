"""
FORESIGHT - Access Tracker, Authentication & Scan History Storage
Maintains global 24-hour unique access monitoring for Cybercell review,
secure user authentication (PBKDF2-HMAC-SHA256), and isolated personal scan histories.

Supported backends (checked in order):
  1. MongoDB  — set MONGODB_URI  (Vercel / cloud, persistent)
  2. SQLite   — set FORESIGHT_DB_PATH or defaults to foresight.db (local dev)
"""

import sqlite3
import hashlib
import secrets
import time
import json
import uuid
import re
from typing import Dict, Any, Optional, List, Tuple
from contextlib import contextmanager
import os
import tempfile

# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
_USE_MONGO = bool(MONGODB_URI)

if not _USE_MONGO:
    DB_PATH = os.environ.get("FORESIGHT_DB_PATH")
    if not DB_PATH:
        if os.environ.get("VERCEL"):
            DB_PATH = os.path.join(tempfile.gettempdir(), "foresight.db")
        else:
            DB_PATH = "foresight.db"
else:
    DB_PATH = None  # unused when MongoDB is active

# ---------------------------------------------------------------------------
# MongoDB helpers
# ---------------------------------------------------------------------------

_mongo_client = None
_mongo_database = None


def _get_mongo():
    """Returns (lazily created) pymongo database handle."""
    global _mongo_client, _mongo_database
    if _mongo_database is None:
        from pymongo import MongoClient
        _mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        _mongo_database = _mongo_client.get_default_database(default="foresight")
    return _mongo_database


def _mongo_next_id(counter_name: str) -> int:
    """Auto-increment integer ID via a 'counters' collection."""
    db = _get_mongo()
    result = db["counters"].find_one_and_update(
        {"_id": counter_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True  # pymongo ReturnDocument.AFTER = True
    )
    return result["seq"]


# ---------------------------------------------------------------------------
# SQLite helpers  (unchanged)
# ---------------------------------------------------------------------------

class _DictRow(dict):
    """Dict subclass with attribute-style access — mirrors sqlite3.Row."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


@contextmanager
def get_db():
    """Yields a SQLite connection (local dev only)."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# init_db  —  create tables / indexes on first run
# ---------------------------------------------------------------------------

_mongo_indexes_ready = False


def init_db():
    global _mongo_indexes_ready
    if _USE_MONGO:
        if not _mongo_indexes_ready:
            _mongo_init_indexes()
            _mongo_indexes_ready = True
        return

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS destination_accesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination_hash TEXT NOT NULL,
                destination_url TEXT NOT NULL,
                client_hash TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dest_time
            ON destination_accesses (destination_hash, timestamp);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dest_client
            ON destination_accesses (destination_hash, client_hash);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cybercell_incidents (
                incident_id TEXT PRIMARY KEY,
                destination_hash TEXT NOT NULL,
                destination_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_status TEXT NOT NULL,
                unique_access_count INTEGER NOT NULL,
                priority TEXT NOT NULL,
                triggered_at REAL NOT NULL,
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                dossier_json TEXT NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
            ON users (email);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_user
            ON user_sessions (user_id);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_status TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                redirects_json TEXT NOT NULL,
                heuristics_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                action_taken TEXT DEFAULT 'AVOID'
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_user_time
            ON user_scans (user_id, created_at DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_user_status
            ON user_scans (user_id, risk_status);
        """)

        conn.commit()


def _mongo_init_indexes():
    """Create MongoDB indexes on first use."""
    from pymongo import ASCENDING, DESCENDING
    db = _get_mongo()
    da = db["destination_accesses"]
    da.create_index([("destination_hash", ASCENDING), ("timestamp", ASCENDING)])
    da.create_index([("destination_hash", ASCENDING), ("client_hash", ASCENDING)])

    db["users"].create_index([("email", ASCENDING)], unique=True)
    db["user_sessions"].create_index([("user_id", ASCENDING)])
    db["user_sessions"].create_index([("expires_at", ASCENDING)])

    db["user_scans"].create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
    db["user_scans"].create_index([("user_id", ASCENDING), ("risk_status", ASCENDING)])

    db["cybercell_incidents"].create_index([("destination_hash", ASCENDING)], unique=True)
    db["cybercell_incidents"].create_index([("triggered_at", DESCENDING)])


# =====================================================================
# PASSWORD HASHING & AUTHENTICATION HELPERS
# =====================================================================

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and a 16-byte random salt."""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000)
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies password using constant-time string comparison."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)

def validate_email(email: str) -> bool:
    """Basic email format validator."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip()))


# =====================================================================
# USER REGISTRATION & LOGIN
# =====================================================================

def create_user(name: str, email: str, password: str) -> Tuple[Dict[str, Any], str]:
    """Registers a new user and creates an active session."""
    if _USE_MONGO:
        return _mongo_create_user(name, email, password)

    init_db()
    clean_name = name.strip()
    clean_email = email.strip().lower()

    if not clean_name:
        raise ValueError("Full name is required.")
    if not clean_email or not validate_email(clean_email):
        raise ValueError("A valid email address is required.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")

    pwd_hash, salt = hash_password(password)
    now = time.time()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (clean_email,))
        if cursor.fetchone():
            raise ValueError("An account with this email already exists.")

        cursor.execute("""
            INSERT INTO users (name, email, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (clean_name, clean_email, pwd_hash, salt, now))
        user_id = cursor.lastrowid
        conn.commit()

    token = create_session(user_id)
    user_data = {"id": user_id, "name": clean_name, "email": clean_email, "created_at": now}
    return user_data, token


def _mongo_create_user(name: str, email: str, password: str) -> Tuple[Dict[str, Any], str]:
    clean_name = name.strip()
    clean_email = email.strip().lower()

    if not clean_name:
        raise ValueError("Full name is required.")
    if not clean_email or not validate_email(clean_email):
        raise ValueError("A valid email address is required.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")

    db = _get_mongo()
    if db["users"].find_one({"email": clean_email}):
        raise ValueError("An account with this email already exists.")

    pwd_hash, salt = hash_password(password)
    now = time.time()
    user_id = _mongo_next_id("users")

    db["users"].insert_one({
        "id": user_id,
        "name": clean_name,
        "email": clean_email,
        "password_hash": pwd_hash,
        "salt": salt,
        "created_at": now
    })

    token = create_session(user_id)
    return {"id": user_id, "name": clean_name, "email": clean_email, "created_at": now}, token


def authenticate_user(email: str, password: str) -> Tuple[Dict[str, Any], str]:
    """Authenticates user credentials. Returns (user_dict, session_token)."""
    if _USE_MONGO:
        return _mongo_authenticate_user(email, password)

    init_db()
    clean_email = email.strip().lower()
    if not clean_email:
        raise ValueError("Email is required.")
    if not password:
        raise ValueError("Password is required.")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (clean_email,))
        row = cursor.fetchone()

        if not row:
            raise ValueError("No account found with this email address.")
        if not verify_password(password, row["password_hash"], row["salt"]):
            raise ValueError("Incorrect password.")

        user_id = row["id"]
        user_data = {"id": user_id, "name": row["name"], "email": row["email"], "created_at": row["created_at"]}

    token = create_session(user_id)
    return user_data, token


def _mongo_authenticate_user(email: str, password: str) -> Tuple[Dict[str, Any], str]:
    clean_email = email.strip().lower()
    if not clean_email:
        raise ValueError("Email is required.")
    if not password:
        raise ValueError("Password is required.")

    db = _get_mongo()
    row = db["users"].find_one({"email": clean_email})
    if not row:
        raise ValueError("No account found with this email address.")
    if not verify_password(password, row["password_hash"], row["salt"]):
        raise ValueError("Incorrect password.")

    user_id = row["id"]
    user_data = {"id": user_id, "name": row["name"], "email": row["email"], "created_at": row["created_at"]}
    token = create_session(user_id)
    return user_data, token


def create_session(user_id: int, days_valid: int = 7) -> str:
    """Creates a secure session token valid for days_valid days."""
    if _USE_MONGO:
        return _mongo_create_session(user_id, days_valid)

    init_db()
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + (days_valid * 86400)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, now, expires))
        conn.commit()

    return token


def _mongo_create_session(user_id: int, days_valid: int = 7) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + (days_valid * 86400)
    _get_mongo()["user_sessions"].insert_one({
        "_id": token,
        "user_id": user_id,
        "created_at": now,
        "expires_at": expires
    })
    return token


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile if session token is valid and unexpired."""
    if _USE_MONGO:
        return _mongo_get_user_by_token(token)

    if not token:
        return None
    init_db()
    now = time.time()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.name, u.email, u.created_at
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token, now))
        row = cursor.fetchone()
        if not row:
            return None
        return {"id": row["id"], "name": row["name"], "email": row["email"], "created_at": row["created_at"]}


def _mongo_get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    db = _get_mongo()
    now = time.time()
    session = db["user_sessions"].find_one({"_id": token, "expires_at": {"$gt": now}})
    if not session:
        return None
    user = db["users"].find_one({"id": session["user_id"]})
    if not user:
        return None
    return {"id": user["id"], "name": user["name"], "email": user["email"], "created_at": user["created_at"]}


def delete_session(token: str) -> bool:
    """Logs out by deleting the active session token."""
    if _USE_MONGO:
        if not token:
            return False
        result = _get_mongo()["user_sessions"].delete_one({"_id": token})
        return result.deleted_count > 0

    if not token:
        return False
    init_db()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        conn.commit()
        return cursor.rowcount > 0


# =====================================================================
# USER PERSONAL SCAN HISTORY & DATA ISOLATION
# =====================================================================

def save_user_scan(user_id: int, analysis_result: Dict[str, Any], action_taken: str = "AVOID") -> Dict[str, Any]:
    """Saves a successful QR analysis to the logged-in user's personal history."""
    if _USE_MONGO:
        return _mongo_save_user_scan(user_id, analysis_result, action_taken)

    init_db()
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()

    orig_url = analysis_result.get("original_url", "")
    final_url = analysis_result.get("final_url", orig_url)
    domain = analysis_result.get("domain", "")
    score = analysis_result.get("score", 0)
    status = analysis_result.get("status", "SAFE")
    reasons = json.dumps(analysis_result.get("reasons", []))
    redirects = json.dumps(analysis_result.get("redirects", {}))
    heuristics = json.dumps(analysis_result.get("heuristics", {}))

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_scans (
                scan_id, user_id, original_url, final_url, domain,
                risk_score, risk_status, reasons_json, redirects_json,
                heuristics_json, created_at, action_taken
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, user_id, orig_url, final_url, domain,
              score, status, reasons, redirects, heuristics, now, action_taken))
        conn.commit()

    return {
        "scan_id": scan_id, "user_id": user_id, "original_url": orig_url,
        "final_url": final_url, "domain": domain, "risk_score": score,
        "risk_status": status, "created_at": now, "action_taken": action_taken
    }


def _mongo_save_user_scan(user_id: int, analysis_result: Dict[str, Any], action_taken: str = "AVOID") -> Dict[str, Any]:
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()
    orig_url = analysis_result.get("original_url", "")
    final_url = analysis_result.get("final_url", orig_url)
    domain = analysis_result.get("domain", "")
    score = analysis_result.get("score", 0)
    status = analysis_result.get("status", "SAFE")

    doc = {
        "_id": scan_id,
        "scan_id": scan_id,
        "user_id": user_id,
        "original_url": orig_url,
        "final_url": final_url,
        "domain": domain,
        "risk_score": score,
        "risk_status": status,
        "reasons": analysis_result.get("reasons", []),
        "redirects": analysis_result.get("redirects", {}),
        "heuristics": analysis_result.get("heuristics", {}),
        "created_at": now,
        "action_taken": action_taken
    }
    _get_mongo()["user_scans"].insert_one(doc)
    return {
        "scan_id": scan_id, "user_id": user_id, "original_url": orig_url,
        "final_url": final_url, "domain": domain, "risk_score": score,
        "risk_status": status, "created_at": now, "action_taken": action_taken
    }


def get_user_scans(user_id: int, status_filter: str = "ALL", search_query: str = "") -> List[Dict[str, Any]]:
    """Retrieves personal scan history for a given user. Enforces strict user isolation."""
    if _USE_MONGO:
        return _mongo_get_user_scans(user_id, status_filter, search_query)

    init_db()
    query = "SELECT * FROM user_scans WHERE user_id = ?"
    params: List[Any] = [user_id]

    status_upper = status_filter.strip().upper()
    if status_upper in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        query += " AND risk_status = ?"
        params.append(status_upper)

    if search_query.strip():
        q = f"%{search_query.strip().lower()}%"
        query += " AND (LOWER(original_url) LIKE ? OR LOWER(final_url) LIKE ? OR LOWER(domain) LIKE ?)"
        params.extend([q, q, q])

    query += " ORDER BY created_at DESC"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [{
            "scan_id": r["scan_id"], "original_url": r["original_url"],
            "final_url": r["final_url"], "domain": r["domain"],
            "risk_score": r["risk_score"], "risk_status": r["risk_status"],
            "reasons": json.loads(r["reasons_json"]) if r["reasons_json"] else [],
            "redirects": json.loads(r["redirects_json"]) if r["redirects_json"] else {},
            "heuristics": json.loads(r["heuristics_json"]) if r["heuristics_json"] else {},
            "created_at": r["created_at"], "action_taken": r["action_taken"]
        } for r in rows]


def _mongo_get_user_scans(user_id: int, status_filter: str = "ALL", search_query: str = "") -> List[Dict[str, Any]]:
    from pymongo import DESCENDING
    db = _get_mongo()
    filt: Dict[str, Any] = {"user_id": user_id}
    status_upper = status_filter.strip().upper()
    if status_upper in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        filt["risk_status"] = status_upper
    if search_query.strip():
        q = search_query.strip()
        filt["$or"] = [
            {"original_url": {"$regex": q, "$options": "i"}},
            {"final_url": {"$regex": q, "$options": "i"}},
            {"domain": {"$regex": q, "$options": "i"}}
        ]
    rows = db["user_scans"].find(filt).sort("created_at", DESCENDING)
    return [{
        "scan_id": r["scan_id"], "original_url": r["original_url"],
        "final_url": r["final_url"], "domain": r["domain"],
        "risk_score": r["risk_score"], "risk_status": r["risk_status"],
        "reasons": r.get("reasons", []), "redirects": r.get("redirects", {}),
        "heuristics": r.get("heuristics", {}), "created_at": r["created_at"],
        "action_taken": r["action_taken"]
    } for r in rows]


def get_user_scan_by_id(user_id: int, scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full details of a specific scan. Prevents cross-user access."""
    if _USE_MONGO:
        return _mongo_get_user_scan_by_id(user_id, scan_id)

    init_db()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_scans WHERE user_id = ? AND scan_id = ?", (user_id, scan_id))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"], "user_id": row["user_id"],
            "original_url": row["original_url"], "final_url": row["final_url"],
            "domain": row["domain"], "risk_score": row["risk_score"],
            "risk_status": row["risk_status"],
            "reasons": json.loads(row["reasons_json"]) if row["reasons_json"] else [],
            "redirects": json.loads(row["redirects_json"]) if row["redirects_json"] else {},
            "heuristics": json.loads(row["heuristics_json"]) if row["heuristics_json"] else {},
            "created_at": row["created_at"], "action_taken": row["action_taken"]
        }


def _mongo_get_user_scan_by_id(user_id: int, scan_id: str) -> Optional[Dict[str, Any]]:
    row = _get_mongo()["user_scans"].find_one({"scan_id": scan_id, "user_id": user_id})
    if not row:
        return None
    return {
        "scan_id": row["scan_id"], "user_id": row["user_id"],
        "original_url": row["original_url"], "final_url": row["final_url"],
        "domain": row["domain"], "risk_score": row["risk_score"],
        "risk_status": row["risk_status"], "reasons": row.get("reasons", []),
        "redirects": row.get("redirects", {}), "heuristics": row.get("heuristics", {}),
        "created_at": row["created_at"], "action_taken": row["action_taken"]
    }


def get_user_dashboard_stats(user_id: int) -> Dict[str, Any]:
    """Calculates summary scan metrics for user's personal dashboard."""
    if _USE_MONGO:
        return _mongo_get_user_dashboard_stats(user_id)

    init_db()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) as total_scans,
                SUM(CASE WHEN risk_status = 'SAFE' THEN 1 ELSE 0 END) as safe_scans,
                SUM(CASE WHEN risk_status = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_scans,
                SUM(CASE WHEN risk_status = 'DANGEROUS' THEN 1 ELSE 0 END) as dangerous_scans
            FROM user_scans WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        total = row["total_scans"] or 0
        safe = row["safe_scans"] or 0
        suspicious = row["suspicious_scans"] or 0
        dangerous = row["dangerous_scans"] or 0

        cursor.execute("""
            SELECT scan_id, original_url, final_url, domain, risk_score, risk_status, created_at, action_taken
            FROM user_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5
        """, (user_id,))
        recent_rows = cursor.fetchall()
        recent_scans = [{
            "scan_id": r["scan_id"], "original_url": r["original_url"],
            "final_url": r["final_url"], "domain": r["domain"],
            "risk_score": r["risk_score"], "risk_status": r["risk_status"],
            "created_at": r["created_at"], "action_taken": r["action_taken"]
        } for r in recent_rows]

    return {"total_scans": total, "safe_scans": safe, "suspicious_scans": suspicious,
            "dangerous_scans": dangerous, "recent_scans": recent_scans}


def _mongo_get_user_dashboard_stats(user_id: int) -> Dict[str, Any]:
    from pymongo import DESCENDING
    db = _get_mongo()
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "total_scans": {"$sum": 1},
            "safe_scans": {"$sum": {"$cond": [{"$eq": ["$risk_status", "SAFE"]}, 1, 0]}},
            "suspicious_scans": {"$sum": {"$cond": [{"$eq": ["$risk_status", "SUSPICIOUS"]}, 1, 0]}},
            "dangerous_scans": {"$sum": {"$cond": [{"$eq": ["$risk_status", "DANGEROUS"]}, 1, 0]}}
        }}
    ]
    agg = list(db["user_scans"].aggregate(pipeline))
    counts = agg[0] if agg else {}
    recent_rows = list(db["user_scans"].find(
        {"user_id": user_id},
        {"scan_id": 1, "original_url": 1, "final_url": 1, "domain": 1,
         "risk_score": 1, "risk_status": 1, "created_at": 1, "action_taken": 1}
    ).sort("created_at", DESCENDING).limit(5))
    recent_scans = [{
        "scan_id": r["scan_id"], "original_url": r["original_url"],
        "final_url": r["final_url"], "domain": r["domain"],
        "risk_score": r["risk_score"], "risk_status": r["risk_status"],
        "created_at": r["created_at"], "action_taken": r["action_taken"]
    } for r in recent_rows]
    return {
        "total_scans": counts.get("total_scans", 0),
        "safe_scans": counts.get("safe_scans", 0),
        "suspicious_scans": counts.get("suspicious_scans", 0),
        "dangerous_scans": counts.get("dangerous_scans", 0),
        "recent_scans": recent_scans
    }


# =====================================================================
# GLOBAL 24-HOUR ACCESS TRACKING & CYBERCELL REPORTING
# =====================================================================

def hash_destination(url: str) -> str:
    """Computes consistent SHA-256 for a normalized destination URL."""
    clean = url.strip().lower()
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()

def hash_client(client_identifier: str) -> str:
    """Computes SHA-256 of client identifier for privacy-respecting uniqueness."""
    return hashlib.sha256(client_identifier.encode("utf-8")).hexdigest()


def record_access(destination_url: str, client_identifier: str, analysis_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Logs an access and evaluates the 24-hour unique user threshold."""
    if _USE_MONGO:
        return _mongo_record_access(destination_url, client_identifier, analysis_result)

    init_db()
    dest_hash = hash_destination(destination_url)
    client_h = hash_client(client_identifier)
    now = time.time()
    cutoff_24h = now - 86400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO destination_accesses (destination_hash, destination_url, client_hash, timestamp)
            VALUES (?, ?, ?, ?)
        """, (dest_hash, destination_url, client_h, now))
        conn.commit()

        cursor.execute("""
            SELECT COUNT(DISTINCT client_hash) as unique_count,
                   MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
            FROM destination_accesses
            WHERE destination_hash = ? AND timestamp >= ?
        """, (dest_hash, cutoff_24h))
        row = cursor.fetchone()
        unique_count = row["unique_count"] if row else 1
        first_seen = row["first_seen"] if (row and row["first_seen"]) else now
        last_seen = row["last_seen"] if (row and row["last_seen"]) else now

        threshold = 100
        is_triggered = unique_count >= threshold
        incident_info = None

        if is_triggered:
            score = analysis_result.get("score", 50) if analysis_result else 50
            status = analysis_result.get("status", "SUSPICIOUS") if analysis_result else "SUSPICIOUS"
            priority = ("CRITICAL / HIGH-PRIORITY" if status == "DANGEROUS"
                        else "ELEVATED / CYBERCELL REVIEW" if status == "SUSPICIOUS"
                        else "EARLY-WARNING / SURGE ANOMALY")

            cursor.execute("SELECT incident_id, triggered_at FROM cybercell_incidents WHERE destination_hash = ?", (dest_hash,))
            existing = cursor.fetchone()

            if existing:
                incident_id = existing["incident_id"]
                dossier = build_dossier(incident_id, destination_url, unique_count, first_seen, last_seen, priority, analysis_result)
                cursor.execute("""
                    UPDATE cybercell_incidents
                    SET unique_access_count=?, risk_score=?, risk_status=?, priority=?,
                        window_start=?, window_end=?, dossier_json=?
                    WHERE incident_id=?
                """, (unique_count, score, status, priority, first_seen, last_seen, json.dumps(dossier), incident_id))
            else:
                incident_id = f"CC-INC-2026-{uuid.uuid4().hex[:8].upper()}"
                dossier = build_dossier(incident_id, destination_url, unique_count, first_seen, last_seen, priority, analysis_result)
                cursor.execute("""
                    INSERT INTO cybercell_incidents (
                        incident_id, destination_hash, destination_url, final_url,
                        risk_score, risk_status, unique_access_count, priority,
                        triggered_at, window_start, window_end, dossier_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (incident_id, dest_hash, destination_url,
                      analysis_result.get("final_url", destination_url) if analysis_result else destination_url,
                      score, status, unique_count, priority, now, first_seen, last_seen, json.dumps(dossier)))

            conn.commit()
            incident_info = {"incident_id": incident_id, "priority": priority,
                             "triggered_at": now, "unique_count": unique_count, "dossier": dossier}

    return {
        "destination_url": destination_url, "unique_accesses_24h": unique_count,
        "threshold": threshold, "threshold_met": is_triggered,
        "progress_percentage": min(100, int((unique_count / threshold) * 100)),
        "first_seen_24h": first_seen, "last_seen_24h": last_seen,
        "incident_report": incident_info
    }


def _mongo_record_access(destination_url: str, client_identifier: str, analysis_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    db = _get_mongo()
    dest_hash = hash_destination(destination_url)
    client_h = hash_client(client_identifier)
    now = time.time()
    cutoff_24h = now - 86400

    db["destination_accesses"].insert_one({
        "destination_hash": dest_hash,
        "destination_url": destination_url,
        "client_hash": client_h,
        "timestamp": now
    })

    pipeline = [
        {"$match": {"destination_hash": dest_hash, "timestamp": {"$gte": cutoff_24h}}},
        {"$group": {
            "_id": "$client_hash",
            "first_seen": {"$min": "$timestamp"},
            "last_seen": {"$max": "$timestamp"}
        }},
        {"$group": {
            "_id": None,
            "unique_count": {"$sum": 1},
            "first_seen": {"$min": "$first_seen"},
            "last_seen": {"$max": "$last_seen"}
        }}
    ]
    agg = list(db["destination_accesses"].aggregate(pipeline))
    if agg:
        unique_count = agg[0]["unique_count"]
        first_seen = agg[0]["first_seen"]
        last_seen = agg[0]["last_seen"]
    else:
        unique_count = 1
        first_seen = now
        last_seen = now

    threshold = 100
    is_triggered = unique_count >= threshold
    incident_info = None

    if is_triggered:
        score = analysis_result.get("score", 50) if analysis_result else 50
        status = analysis_result.get("status", "SUSPICIOUS") if analysis_result else "SUSPICIOUS"
        priority = ("CRITICAL / HIGH-PRIORITY" if status == "DANGEROUS"
                    else "ELEVATED / CYBERCELL REVIEW" if status == "SUSPICIOUS"
                    else "EARLY-WARNING / SURGE ANOMALY")

        incident_id = f"CC-INC-2026-{uuid.uuid4().hex[:8].upper()}"
        dossier = build_dossier(incident_id, destination_url, unique_count, first_seen, last_seen, priority, analysis_result)

        existing = db["cybercell_incidents"].find_one({"destination_hash": dest_hash})
        if existing:
            incident_id = existing["incident_id"]
            dossier = build_dossier(incident_id, destination_url, unique_count, first_seen, last_seen, priority, analysis_result)
            db["cybercell_incidents"].update_one(
                {"destination_hash": dest_hash},
                {"$set": {
                    "unique_access_count": unique_count, "risk_score": score,
                    "risk_status": status, "priority": priority,
                    "window_start": first_seen, "window_end": last_seen,
                    "dossier": dossier
                }}
            )
        else:
            db["cybercell_incidents"].insert_one({
                "_id": incident_id,
                "incident_id": incident_id,
                "destination_hash": dest_hash,
                "destination_url": destination_url,
                "final_url": analysis_result.get("final_url", destination_url) if analysis_result else destination_url,
                "risk_score": score,
                "risk_status": status,
                "unique_access_count": unique_count,
                "priority": priority,
                "triggered_at": now,
                "window_start": first_seen,
                "window_end": last_seen,
                "dossier": dossier
            })

        incident_info = {"incident_id": incident_id, "priority": priority,
                         "triggered_at": now, "unique_count": unique_count, "dossier": dossier}

    return {
        "destination_url": destination_url, "unique_accesses_24h": unique_count,
        "threshold": threshold, "threshold_met": is_triggered,
        "progress_percentage": min(100, int((unique_count / threshold) * 100)),
        "first_seen_24h": first_seen, "last_seen_24h": last_seen,
        "incident_report": incident_info
    }


def build_dossier(incident_id: str, destination_url: str, unique_count: int,
                  first_seen: float, last_seen: float, priority: str,
                  analysis_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Builds a comprehensive cybersecurity incident report dossier."""
    result = analysis_result or {}
    redirects = result.get("redirects", {})
    return {
        "incident_id": incident_id,
        "classification": "CYBERCELL INCIDENT ALERT",
        "system_tagline": "Know the risk before you take the step.",
        "trigger_condition": "100+ Unique Accesses in 24-Hour Rolling Window",
        "priority_level": priority,
        "destination_profile": {
            "raw_payload": destination_url,
            "final_landing_url": result.get("final_url", destination_url),
            "domain": result.get("domain", ""),
            "hostname": result.get("hostname", ""),
            "scheme": result.get("scheme", "")
        },
        "risk_assessment": {
            "score": result.get("score", 0),
            "status": result.get("status", "UNKNOWN"),
            "recommendation": result.get("recommendation", ""),
            "identified_reasons": result.get("reasons", [])
        },
        "redirect_forensics": {
            "total_hops": redirects.get("hop_count", 0),
            "destination_drift_detected": redirects.get("destination_drift", False),
            "initial_domain": redirects.get("initial_domain", ""),
            "final_domain": redirects.get("final_domain", ""),
            "hop_trace": redirects.get("hops", [])
        },
        "access_metrics_24h": {
            "unique_access_count": unique_count,
            "threshold": 100,
            "first_access_epoch": first_seen,
            "latest_access_epoch": last_seen,
            "window_duration_hours": 24.0
        },
        "cybercell_instructions": (
            "This QR destination has reached the high-velocity threshold (>=100 unique scans in 24h). "
            "If classified as DANGEROUS or SUSPICIOUS, initiate emergency domain triage, DNS sinkholing, "
            "or payment provider alerting."
        )
    }


def get_all_incidents() -> List[Dict[str, Any]]:
    """Fetches all active cybercell incident reports."""
    if _USE_MONGO:
        from pymongo import DESCENDING
        rows = _get_mongo()["cybercell_incidents"].find().sort("triggered_at", DESCENDING)
        return [{
            "incident_id": r["incident_id"], "destination_url": r["destination_url"],
            "final_url": r["final_url"], "risk_score": r["risk_score"],
            "risk_status": r["risk_status"], "unique_access_count": r["unique_access_count"],
            "priority": r["priority"], "triggered_at": r["triggered_at"],
            "window_start": r["window_start"], "window_end": r["window_end"],
            "dossier": r.get("dossier", {})
        } for r in rows]

    init_db()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cybercell_incidents ORDER BY triggered_at DESC")
        rows = cursor.fetchall()
        return [{
            "incident_id": r["incident_id"], "destination_url": r["destination_url"],
            "final_url": r["final_url"], "risk_score": r["risk_score"],
            "risk_status": r["risk_status"], "unique_access_count": r["unique_access_count"],
            "priority": r["priority"], "triggered_at": r["triggered_at"],
            "window_start": r["window_start"], "window_end": r["window_end"],
            "dossier": json.loads(r["dossier_json"]) if r["dossier_json"] else {}
        } for r in rows]


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single cybercell incident by ID."""
    if _USE_MONGO:
        r = _get_mongo()["cybercell_incidents"].find_one({"incident_id": incident_id})
        if not r:
            return None
        return {
            "incident_id": r["incident_id"], "destination_url": r["destination_url"],
            "final_url": r["final_url"], "risk_score": r["risk_score"],
            "risk_status": r["risk_status"], "unique_access_count": r["unique_access_count"],
            "priority": r["priority"], "triggered_at": r["triggered_at"],
            "window_start": r["window_start"], "window_end": r["window_end"],
            "dossier": r.get("dossier", {})
        }

    init_db()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cybercell_incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "incident_id": row["incident_id"], "destination_url": row["destination_url"],
            "final_url": row["final_url"], "risk_score": row["risk_score"],
            "risk_status": row["risk_status"], "unique_access_count": row["unique_access_count"],
            "priority": row["priority"], "triggered_at": row["triggered_at"],
            "window_start": row["window_start"], "window_end": row["window_end"],
            "dossier": json.loads(row["dossier_json"]) if row["dossier_json"] else {}
        }


def get_platform_stats() -> Dict[str, Any]:
    """Returns general platform monitoring stats (used by /api/stats endpoint)."""
    if _USE_MONGO:
        db = _get_mongo()
        total_scans = db["destination_accesses"].count_documents({})
        unique_destinations = len(db["destination_accesses"].distinct("destination_hash"))
        incident_count = db["cybercell_incidents"].count_documents({})
        total_users = db["users"].count_documents({})
    else:
        init_db()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM destination_accesses")
            total_scans = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(DISTINCT destination_hash) as c FROM destination_accesses")
            unique_destinations = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM cybercell_incidents")
            incident_count = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM users")
            total_users = cursor.fetchone()["c"]

    return {
        "total_scans_recorded": total_scans,
        "unique_destinations_monitored": unique_destinations,
        "cybercell_incidents_triggered": incident_count,
        "registered_users": total_users
    }


def simulate_surge(destination_url: str, count: int = 105, analysis_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Internal helper used strictly by test suites to verify the 100-access Cybercell trigger."""
    if _USE_MONGO:
        db = _get_mongo()
        dest_hash = hash_destination(destination_url)
        now = time.time()
        docs = []
        for i in range(count):
            fake_client = f"client_synthetic_{i}_{uuid.uuid4().hex[:6]}"
            client_h = hash_client(fake_client)
            staggered_time = now - (i * 45)
            docs.append({
                "destination_hash": dest_hash,
                "destination_url": destination_url,
                "client_hash": client_h,
                "timestamp": staggered_time
            })
        if docs:
            db["destination_accesses"].insert_many(docs)
        return record_access(destination_url, f"trigger_verifier_{uuid.uuid4().hex[:6]}", analysis_result)

    init_db()
    dest_hash = hash_destination(destination_url)
    now = time.time()

    with get_db() as conn:
        cursor = conn.cursor()
        records = []
        for i in range(count):
            fake_client = f"client_synthetic_{i}_{uuid.uuid4().hex[:6]}"
            client_h = hash_client(fake_client)
            staggered_time = now - (i * 45)
            records.append((dest_hash, destination_url, client_h, staggered_time))

        cursor.executemany("""
            INSERT INTO destination_accesses (destination_hash, destination_url, client_hash, timestamp)
            VALUES (?, ?, ?, ?)
        """, records)
        conn.commit()

    return record_access(destination_url, f"trigger_verifier_{uuid.uuid4().hex[:6]}", analysis_result)
