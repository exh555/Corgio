import os
import re
import time
import shutil
import sys
import hmac
import hashlib
import logging
import ipaddress
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import asyncio

from backend import database
from backend import downloader
from backend import updater
from backend import privacy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
APP_VERSION = "1.0.0"
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,32}$")

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
MAX_TRACKED_IPS = 1024
_login_attempts: dict = {}

MIME_MAP = {
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".opus": "audio/ogg",
}

MAX_SSE_STREAMS = 10
_active_sse_streams = 0

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "media-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def _safe_compare_digest(a: str, b: str) -> bool:
    """Constant-time string comparison safe against non-ASCII UTF-8 characters (F3)."""
    return database._safe_compare_digest(a, b)


def _get_configured_auth_token() -> str:
    return os.environ.get("CORGIO_AUTH_TOKEN", "").strip()


def _compute_session_token(raw_secret: str) -> str:
    return hmac.new(raw_secret.encode("utf-8"), b"corgio-session-v1", hashlib.sha256).hexdigest()


def _issue_session_token(acct: dict, ttl_seconds: int = 86400 * 30) -> str:
    now_ts = int(time.time())
    exp_ts = now_ts + ttl_seconds
    username = acct["username"]
    payload = f"{username}:{now_ts}:{exp_ts}"
    sig = hmac.new(
        acct["session_secret"].encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{sig}"


def _verify_session_cookie(cookie_val: str, acct: dict) -> bool:
    if not cookie_val or not acct:
        return False
    parts = cookie_val.rsplit(":", 3)
    if len(parts) != 4:
        return False
    username, iat_str, exp_str, sig = parts
    try:
        exp_ts = int(exp_str)
    except ValueError:
        return False

    if int(time.time()) > exp_ts:
        return False

    if not _safe_compare_digest(username.strip().lower(), acct["username"].strip().lower()):
        return False

    payload = f"{username}:{iat_str}:{exp_str}"
    expected_sig = hmac.new(
        acct["session_secret"].encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return _safe_compare_digest(sig, expected_sig)


def _is_auth_required() -> bool:
    if _get_configured_auth_token():
        return True
    if os.environ.get("DISABLE_AUTH", "").lower() in ("1", "true", "yes"):
        return False
    acct = database.get_auth_account()
    return bool(acct.get("auth_enabled", True))


def _get_auth_method(request: Request) -> Optional[str]:
    """
    Returns 'disabled', 'token', 'session', or None if unauthenticated.
    """
    if not _is_auth_required():
        return "disabled"

    secret = _get_configured_auth_token()
    if secret:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            candidate = auth_header[7:].strip()
            if _safe_compare_digest(candidate, secret):
                return "token"

        api_key = request.headers.get("x-api-key", "").strip()
        if api_key and _safe_compare_digest(api_key, secret):
            return "token"

    cookie_val = request.cookies.get("corgio_session", "")
    if cookie_val:
        acct = database.get_auth_account()
        if _verify_session_cookie(cookie_val, acct):
            return "session"
        if secret:
            expected_cookie = _compute_session_token(secret)
            if _safe_compare_digest(cookie_val, expected_cookie):
                return "token"

    return None


def _is_request_authenticated(request: Request) -> bool:
    return _get_auth_method(request) is not None


def reset_login_rate_limits():
    _login_attempts.clear()


def _prune_login_attempts(now_ts: float):
    """Prunes expired lockout/attempt records and bounds dict size to MAX_TRACKED_IPS (F8)."""
    expired = [
        ip
        for ip, info in list(_login_attempts.items())
        if info.get("locked_until", 0) <= now_ts
        and (now_ts - info.get("last_ts", now_ts)) > LOGIN_LOCKOUT_SECONDS
    ]
    for ip in expired:
        _login_attempts.pop(ip, None)

    while len(_login_attempts) >= MAX_TRACKED_IPS:
        oldest_ip = next(iter(_login_attempts))
        _login_attempts.pop(oldest_ip, None)


def _is_trusted_proxy(client_host: str) -> bool:
    trusted_raw = os.environ.get("TRUSTED_PROXIES", "").strip()
    if not trusted_raw:
        return False
    trusted = {p.strip() for p in trusted_raw.split(",") if p.strip()}
    return "*" in trusted or client_host in trusted


def _get_client_ip(request: Request) -> str:
    client_host = request.client.host if (request.client and request.client.host) else "unknown"
    if _is_trusted_proxy(client_host):
        xff = request.headers.get("x-forwarded-for", "").strip()
        if xff:
            first_ip = xff.split(",")[0].strip()
            if first_ip:
                return first_ip
    return client_host


def _should_set_secure_cookie(request: Request) -> bool:
    """Determines whether the Secure flag should be set on the session cookie (F7)."""
    if os.environ.get("COOKIE_SECURE", "").lower() in ("1", "true", "yes"):
        return True
    if request.url.scheme == "https":
        return True
    client_host = request.client.host if (request.client and request.client.host) else ""
    if _is_trusted_proxy(client_host):
        if request.headers.get("x-forwarded-proto", "").strip().lower() == "https":
            return True
    return False


def _is_allowed_host(host_header: str) -> bool:
    """
    Defends against DNS rebinding (H2) by allowing localhost, private LAN IP literals,
    single-label local hostnames (e.g. 'unraid', 'tower'), .local mDNS names, and
    any hostnames explicitly configured in ALLOWED_HOSTS.
    """
    if not host_header:
        return False

    raw = host_header.strip().lower()
    # Handle IPv6 bracketed host [::1]:8080
    if raw.startswith("["):
        if "]" not in raw:
            return False
        host_only = raw[1 : raw.index("]")]
    else:
        host_only = raw.split(":", 1)[0]

    if not host_only:
        return False

    extra_allowed = {
        h.strip().lower()
        for h in os.environ.get("ALLOWED_HOSTS", "").split(",")
        if h.strip()
    }
    if "*" in extra_allowed or host_only in extra_allowed or raw in extra_allowed:
        return True

    if host_only in ("localhost", "127.0.0.1", "::1", "testserver"):
        return True

    # Allow single-label local hostnames (e.g. 'unraid', 'tower', 'corgio-downloader') or .local mDNS
    if "." not in host_only or host_only.endswith((".local", ".lan", ".home", ".internal")):
        return True

    # Allow direct private/loopback IP literals (e.g. 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    try:
        ip_obj = ipaddress.ip_address(host_only)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return True
    except ValueError:
        pass

    return False


def apply_logging_settings(enable_access_logs: bool):
    logger = logging.getLogger("uvicorn.access")
    logger.disabled = not enable_access_logs


def _model_to_dict(model_obj: BaseModel) -> dict:
    if hasattr(model_obj, "model_dump"):
        return model_obj.model_dump()
    return model_obj.dict()


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    database.recover_interrupted_downloads()
    downloader.cleanup_all_work_dirs()

    yt_ver = updater.get_yt_dlp_version(refresh=True)
    updater.get_ffmpeg_version(refresh=True)
    py_ver = sys.version.split()[0]

    database.add_activity_log(
        "SYSTEM",
        f"Application server started successfully. Python: {py_ver} | yt-dlp: {yt_ver}",
    )
    if os.environ.get("RESET_PASSWORD", "").lower() in ("1", "true", "yes") or (
        os.environ.get("CORGIO_RESET_PASSWORD", "").lower() in ("1", "true", "yes")
    ):
        database.add_activity_log(
            "AUTH",
            "Admin credentials reset to initial defaults via RESET_PASSWORD environment variable.",
        )

    # F11: Emit explicit startup security warnings if auth or SSRF protections are disabled via env
    err_logger = logging.getLogger("uvicorn.error")
    if os.environ.get("DISABLE_AUTH", "").lower() in ("1", "true", "yes"):
        warn_msg = "SECURITY WARNING: Authentication is disabled via DISABLE_AUTH=true. Do not expose this instance to untrusted networks."
        err_logger.warning(warn_msg)
        database.add_activity_log("SECURITY", warn_msg)

    if os.environ.get("ALLOW_PRIVATE_URLS", "").lower() in ("1", "true", "yes"):
        warn_msg = "SECURITY WARNING: Private/LAN URL SSRF protection is disabled via ALLOW_PRIVATE_URLS=true."
        err_logger.warning(warn_msg)
        database.add_activity_log("SECURITY", warn_msg)

    settings = database.get_settings()
    enable_access_logs = settings.get("enable_access_logs", False)
    apply_logging_settings(enable_access_logs)
    yield


app = FastAPI(title="Corgio API", lifespan=lifespan)

# Configure CORS only if explicitly requested via CORS_ORIGINS env var (same-origin by default)
cors_origins_env = os.environ.get("CORS_ORIGINS", "").strip()
allowed_cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else []
if allowed_cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-Requested-With", "Authorization", "X-API-Key"],
    )


@app.middleware("http")
async def security_and_privacy_middleware(request: Request, call_next):
    # 1. Host Header Validation (DNS Rebinding Defense - H2)
    host_header = request.headers.get("host", "")
    if not _is_allowed_host(host_header):
        return JSONResponse(status_code=400, content={"detail": "Invalid Host header"})

    path = request.url.path
    method = request.method.upper()

    # 2. CSRF Defense on State-Changing API Requests (H2)
    if path.startswith("/api/") and method in ("POST", "DELETE", "PUT", "PATCH"):
        sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if sec_fetch_site == "cross-site":
            return JSONResponse(
                status_code=403, content={"detail": "Cross-site state-changing requests are blocked"}
            )

        origin = request.headers.get("origin", "").strip()
        if origin:
            if origin == "null":
                return JSONResponse(status_code=403, content={"detail": "Invalid Origin header"})
            parsed_origin = urlparse(origin)
            if parsed_origin.netloc.lower() != host_header.strip().lower():
                if origin not in allowed_cors_origins:
                    return JSONResponse(status_code=403, content={"detail": "Origin mismatch"})

        # Require custom header X-Requested-With: Corgio (blocks simple form/no-cors CSRF)
        x_req_with = request.headers.get("x-requested-with", "").strip()
        if x_req_with not in ("Corgio", "CorgioDL"):
            return JSONResponse(
                status_code=403,
                content={"detail": "Missing required X-Requested-With security header"},
            )

    # 3. Authentication & Forced First-Launch Password Change Enforcement (H1, F1)
    if path.startswith("/api/") and path not in ("/api/auth/login", "/api/auth/status"):
        auth_method = _get_auth_method(request)
        if auth_method is None:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

        # F1: When authenticated via user account session, enforce must_change_password server-side
        if auth_method == "session" and path not in ("/api/auth/logout", "/api/auth/account"):
            acct = database.get_auth_account()
            if acct.get("must_change_password", False):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Password change required before accessing workspace"},
                )

    response = await call_next(request)

    # 4. Global Security & Privacy Headers (M4, M5, H2, F2)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", DEFAULT_CSP)

    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


# Request Models
class DownloadRequest(BaseModel):
    url: str
    format: Optional[str] = "mp4"
    speed_limit: Optional[str] = None
    subtitles: Optional[bool] = False
    custom_args: Optional[str] = None


class SettingsRequest(BaseModel):
    theme: Optional[str] = "light"
    palette: Optional[str] = "pembroke"
    default_format: Optional[str] = "mp4"
    default_speed_limit: Optional[str] = ""
    default_subtitles: Optional[bool] = False
    custom_args: Optional[str] = ""
    download_subfolder: Optional[str] = ""
    enable_access_logs: Optional[bool] = False


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    remember: Optional[bool] = True
    token: Optional[str] = None


class AccountUpdateRequest(BaseModel):
    current_password: str
    new_username: Optional[str] = None
    new_password: str
    confirm_password: Optional[str] = None


# Authentication & Account Management Endpoints (H1, F1, F3, F7, F8)
@app.get("/api/auth/status")
def get_auth_status(request: Request):
    acct = database.get_auth_account()
    auth_req = _is_auth_required()
    is_authed = _is_request_authenticated(request)
    # F1: Only reveal must_change_password state to authenticated sessions
    must_change = bool(acct.get("must_change_password", False)) if is_authed else False

    return {
        "auth_required": auth_req,
        "authenticated": is_authed,
        "username": acct.get("username", "admin") if is_authed else None,
        "must_change_password": must_change,
    }


@app.post("/api/auth/login")
def login_session(req: LoginRequest, request: Request, response: Response):
    client_ip = _get_client_ip(request)
    now_ts = time.time()
    _prune_login_attempts(now_ts)

    # 1. Brute-force rate limit check per client IP (checked BEFORE PBKDF2 - F3, F8)
    attempt_info = _login_attempts.get(client_ip)
    if attempt_info and attempt_info.get("locked_until", 0) > now_ts:
        wait_secs = max(1, int(attempt_info["locked_until"] - now_ts))
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed sign-in attempts. Please wait {wait_secs}s before trying again.",
        )

    secret = _get_configured_auth_token()
    acct = database.get_auth_account()

    authenticated_via_token = False
    authenticated_via_account = False

    try:
        if req.token and secret and _safe_compare_digest(req.token.strip(), secret):
            authenticated_via_token = True
        elif req.username is not None and req.password is not None:
            if database.verify_user_credentials(req.username, req.password):
                authenticated_via_account = True
        elif req.token and not secret:
            # Allow single-field password fallback against default username if someone sends token
            if database.verify_user_credentials(acct.get("username", "admin"), req.token):
                authenticated_via_account = True
    except Exception:
        authenticated_via_token = False
        authenticated_via_account = False

    if not authenticated_via_token and not authenticated_via_account:
        info = _login_attempts.get(client_ip, {"count": 0, "locked_until": 0, "last_ts": now_ts})
        if info.get("locked_until", 0) <= now_ts and info.get("count", 0) >= MAX_LOGIN_ATTEMPTS:
            info = {"count": 0, "locked_until": 0, "last_ts": now_ts}
        info["count"] = info.get("count", 0) + 1
        info["last_ts"] = now_ts
        if info["count"] >= MAX_LOGIN_ATTEMPTS:
            info["locked_until"] = now_ts + LOGIN_LOCKOUT_SECONDS
            _login_attempts[client_ip] = info
            database.add_activity_log(
                "SECURITY",
                f"Sign-in temporarily locked for {LOGIN_LOCKOUT_SECONDS}s after {MAX_LOGIN_ATTEMPTS} failed attempts from {client_ip}.",
            )
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed sign-in attempts. Locked for {LOGIN_LOCKOUT_SECONDS}s.",
            )
        _login_attempts[client_ip] = info
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Clear rate limit state on successful login
    _login_attempts.pop(client_ip, None)

    remember = True if req.remember is None else bool(req.remember)
    ttl_seconds = (86400 * 30) if remember else 86400

    # F7: Always issue a time-bounded session token signed with acct['session_secret'] so logout revokes it
    session_val = _issue_session_token(acct, ttl_seconds=ttl_seconds)

    cookie_kwargs = {
        "key": "corgio_session",
        "value": session_val,
        "httponly": True,
        "samesite": "strict",
        "secure": _should_set_secure_cookie(request),
        "path": "/",
    }
    if remember:
        cookie_kwargs["max_age"] = ttl_seconds

    response.set_cookie(**cookie_kwargs)
    database.add_activity_log("AUTH", f"User '{acct['username']}' signed in.")

    return {
        "status": "ok",
        "authenticated": True,
        "username": acct.get("username", "admin"),
        "must_change_password": bool(acct.get("must_change_password", False)),
    }


@app.post("/api/auth/logout")
def logout_session(response: Response):
    database.rotate_session_secret()
    response.delete_cookie(key="corgio_session", path="/")
    return {"status": "ok"}


@app.post("/api/auth/account")
def update_account_credentials(req: AccountUpdateRequest, request: Request, response: Response):
    acct = database.get_auth_account()

    if not req.current_password or not database.verify_user_credentials(
        acct["username"], req.current_password
    ):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    target_username = (req.new_username or acct["username"]).strip()
    if not USERNAME_RE.match(target_username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 2–32 characters (letters, numbers, _, ., -)",
        )

    if not req.new_password or len(req.new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="New password must be at least 6 characters long",
        )
    if len(req.new_password) > 128:
        raise HTTPException(status_code=400, detail="New password cannot exceed 128 characters")

    if req.confirm_password is not None and req.new_password != req.confirm_password:
        raise HTTPException(
            status_code=400, detail="New password and confirmation do not match"
        )

    updated_acct = database.update_user_credentials(target_username, req.new_password)
    ttl_seconds = 86400 * 30
    session_val = _issue_session_token(updated_acct, ttl_seconds=ttl_seconds)
    response.set_cookie(
        key="corgio_session",
        value=session_val,
        httponly=True,
        samesite="strict",
        secure=_should_set_secure_cookie(request),
        max_age=ttl_seconds,
        path="/",
    )
    database.add_activity_log(
        "AUTH", f"Account credentials updated for user '{updated_acct['username']}'."
    )
    return {
        "status": "ok",
        "message": "Account credentials updated successfully",
        "username": updated_acct["username"],
        "must_change_password": False,
    }


# API Routes
@app.get("/api/status")
def get_status():
    """Returns versions and system info without leaking internal host paths by default (L4)."""
    dl_dir = downloader.DOWNLOAD_DIR
    total, used, free = shutil.disk_usage(dl_dir) if os.path.exists(dl_dir) else (0, 0, 0)

    expose_paths = os.environ.get("EXPOSE_HOST_PATHS", "").lower() in ("1", "true", "yes")
    display_dir = os.path.abspath(dl_dir) if expose_paths else "/downloads"

    return {
        "app_version": APP_VERSION,
        "yt_dlp_version": updater.get_yt_dlp_version(),
        "ffmpeg_version": updater.get_ffmpeg_version(),
        "ffmpeg_friendly_version": updater.get_ffmpeg_friendly_version(),
        "downloads_dir": display_dir,
        "disk_space": {
            "total": total,
            "used": used,
            "free": free,
            "percent_used": round((used / total) * 100, 1) if total > 0 else 0,
        },
    }


@app.post("/api/download")
def start_video_download(req: DownloadRequest):
    """Starts a download task in the background"""
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        download_id = downloader.start_download(req.url, _model_to_dict(req))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    database.add_activity_log(
        "DOWNLOAD_TRIGGERED", f"Triggered download of URL: {req.url.strip()}", download_id
    )
    return {"id": download_id, "status": "started"}


@app.get("/api/downloads")
def list_downloads():
    """Lists all downloads in the database"""
    return database.get_all_downloads()


@app.get("/api/active")
def list_active_downloads():
    """Lists current active downloads and progress"""
    return downloader.get_active_downloads()


@app.post("/api/downloads/{download_id}/stop")
def stop_video_download(download_id: str):
    """Stops an active download process"""
    stopped = downloader.stop_download(download_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="Active download not found or already completed")
    return {"status": "stopped"}


@app.post("/api/downloads/{download_id}/retry")
def retry_video_download(download_id: str):
    """Retries a failed or stopped download"""
    info = database.get_download(download_id)
    if not info:
        raise HTTPException(status_code=404, detail="Download record not found")

    if download_id in downloader.active_processes or download_id in downloader.active_threads:
        raise HTTPException(status_code=400, detail="Download is already running")

    url = info.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Invalid URL in download record")

    settings = {}
    if info.get("download_options"):
        try:
            import json
            settings = json.loads(info["download_options"])
        except Exception:
            pass

    if not settings:
        db_settings = database.get_settings()
        fmt = info.get("format")
        if fmt not in downloader.ALLOWED_FORMATS:
            fmt = db_settings.get("default_format", "mp4")
        settings = {
            "url": url,
            "format": fmt,
            "speed_limit": db_settings.get("default_speed_limit", ""),
            "subtitles": db_settings.get("default_subtitles", False),
            "custom_args": db_settings.get("custom_args", ""),
        }

    try:
        downloader.start_download(url, settings, download_id=download_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    database.add_activity_log("DOWNLOAD_RETRIED", f"Retried download of URL: {url}", download_id)
    return {"id": download_id, "status": "started"}


@app.post("/api/downloads/{download_id}/play")
def record_video_play(download_id: str):
    """Increments play count and logs a server-verified PLAY event (L2 defense against log forgery)."""
    info = database.get_download(download_id)
    if not info:
        raise HTTPException(status_code=404, detail="Download record not found")

    database.increment_play_count(download_id)
    label = info.get("title") or info.get("filename") or download_id
    database.add_activity_log("PLAY", f"Played media in browser player: {label}", download_id)
    return {"status": "success"}


@app.delete("/api/downloads/{download_id}")
def delete_video_download(download_id: str, delete_file: bool = Query(False)):
    """
    Privacy-focused deletion: halts active downloader/encoder processes, waits for thread termination,
    removes temporary work files, thumbnails, optionally the media file, and purges all in-memory
    and SQLite logs without leaving a deletion tombstone.
    """
    info = database.get_download(download_id)
    if (
        not info
        and download_id not in downloader.active_threads
        and download_id not in downloader.download_progress
    ):
        raise HTTPException(status_code=404, detail="Download record not found")

    # 1. Halt any running yt-dlp / ffmpeg processes, join thread, wipe work dir, thumbnail, & memory logs
    downloader.purge_download_state(download_id)

    # 2. Delete final media file & empty domain directory if requested (strictly confined to DOWNLOAD_DIR - M1)
    if delete_file and info:
        parent_dir = None
        filepath = info.get("filepath")
        if filepath and downloader.is_path_within(filepath, downloader.DOWNLOAD_DIR):
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass
            parent_dir = os.path.dirname(filepath)
        else:
            domain = info.get("domain") or database.extract_base_domain(info.get("url"))
            if domain:
                settings = database.get_settings()
                subfolder = settings.get("download_subfolder", "").strip()
                try:
                    parent_dir = downloader.resolve_safe_download_dir(subfolder, domain)
                except ValueError:
                    parent_dir = None

        if parent_dir:
            try:
                curr_dir = os.path.realpath(parent_dir)
                download_dir_real = os.path.realpath(downloader.DOWNLOAD_DIR)
                while (
                    os.path.exists(curr_dir)
                    and curr_dir != download_dir_real
                    and os.path.commonpath([download_dir_real, curr_dir]) == download_dir_real
                ):
                    remaining = [
                        f
                        for f in os.listdir(curr_dir)
                        if f not in (".DS_Store", ".thumbnails", ".work")
                    ]
                    if not remaining:
                        parent_next = os.path.dirname(curr_dir)
                        shutil.rmtree(curr_dir, ignore_errors=True)
                        curr_dir = parent_next
                    else:
                        break
            except Exception:
                pass

    # 3. Purge database record & all associated activity logs (with secure_delete + WAL truncate)
    database.delete_download(download_id)
    return {"status": "deleted"}


@app.get("/api/logs/{download_id}")
def get_download_logs(download_id: str):
    """Get raw logs for a download id"""
    logs = downloader.get_logs(download_id)
    if not logs:
        info = database.get_download(download_id)
        if info:
            if info.get("status") == "completed":
                return [
                    "[system] Raw downloader and encoder logs were automatically purged upon completion for privacy."
                ]
            if info.get("error_log"):
                return [f"[system] Download status ({info.get('status')}): {info['error_log']}"]
        return ["[system] No logs found for this download."]
    return logs


@app.get("/api/stream-logs/{download_id}")
def stream_download_logs(download_id: str):
    """Server-Sent Events endpoint to stream raw logs in real time (bounded by MAX_SSE_STREAMS - L1)"""
    global _active_sse_streams
    if _active_sse_streams >= MAX_SSE_STREAMS:
        raise HTTPException(status_code=429, detail="Too many active log streams")

    async def log_generator():
        global _active_sse_streams
        _active_sse_streams += 1
        sent_index = 0
        try:
            while True:
                active = (
                    download_id in downloader.active_processes
                    or download_id in downloader.active_threads
                )
                logs = downloader.get_logs(download_id)

                if sent_index < len(logs):
                    for i in range(sent_index, len(logs)):
                        yield f"data: {logs[i]}\n\n"
                    sent_index = len(logs)

                if not active and sent_index >= len(logs):
                    if sent_index == 0:
                        fallback_lines = get_download_logs(download_id)
                        for line in fallback_lines:
                            yield f"data: {line}\n\n"
                    yield "data: [system] Log stream ended.\n\n"
                    break

                await asyncio.sleep(0.5)
        finally:
            _active_sse_streams = max(0, _active_sse_streams - 1)

    return StreamingResponse(log_generator(), media_type="text/event-stream")


@app.post("/api/scan")
def scan_library():
    """Scans downloads folder for untracked videos"""
    res = downloader.scan_downloads_folder()
    return {
        "status": "success",
        "added_count": res["added"],
        "missing_count": res["missing"],
        "restored_count": res["restored"],
        "busy": res.get("busy", False),
    }


@app.get("/api/check-updates")
def check_for_updates():
    """Checks for yt-dlp and ffmpeg updates (only invoked on explicit user action - M8)"""
    yt_res = updater.check_yt_dlp_update()
    ffmpeg_res = updater.check_ffmpeg_update()
    return {
        "yt_dlp": yt_res,
        "ffmpeg": ffmpeg_res,
    }


@app.post("/api/update")
async def update_components(background_tasks: BackgroundTasks):
    """Runs full engine updater in background and records live logs to stream & audit table"""
    if updater.is_update_in_progress():
        return {
            "status": "already_running",
            "message": "Engine update is already in progress.",
        }

    background_tasks.add_task(updater.run_full_engine_update)
    return {
        "status": "update_started",
        "message": "Engine update started in background.",
    }


@app.get("/api/update/status")
def get_engine_update_status():
    """Returns the current state and progress step of the component updater"""
    return updater.get_update_status()


@app.get("/api/update/logs")
def get_engine_update_logs():
    """Returns the full history of the latest component update logs"""
    return {
        "logs": updater.get_update_logs(),
        "status": updater.get_update_status(),
    }


@app.get("/api/update/stream")
def stream_engine_update_logs():
    """Server-Sent Events endpoint to stream engine update console logs in real time"""
    global _active_sse_streams
    if _active_sse_streams >= MAX_SSE_STREAMS:
        raise HTTPException(status_code=429, detail="Too many active log streams")

    async def log_generator():
        global _active_sse_streams
        _active_sse_streams += 1
        sent_index = 0
        try:
            while True:
                active = updater.is_update_in_progress()
                logs = updater.get_update_logs()

                if sent_index < len(logs):
                    for i in range(sent_index, len(logs)):
                        yield f"data: {logs[i]}\n\n"
                    sent_index = len(logs)

                if not active and sent_index >= len(logs):
                    yield "data: [system] Update log stream ended.\n\n"
                    break

                await asyncio.sleep(0.3)
        finally:
            _active_sse_streams = max(0, _active_sse_streams - 1)

    return StreamingResponse(log_generator(), media_type="text/event-stream")


@app.get("/api/thumbnail/{download_id}.jpg")
def serve_thumbnail(download_id: str):
    """Serves local video thumbnail with sandbox CSP and nosniff"""
    safe_id = os.path.basename(download_id)
    thumb_path = os.path.join(downloader.THUMBNAIL_DIR, f"{safe_id}.jpg")
    headers = {
        "Content-Security-Policy": "sandbox",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    }
    if os.path.exists(thumb_path) and downloader.is_path_within(thumb_path, downloader.THUMBNAIL_DIR):
        return FileResponse(thumb_path, media_type="image/jpeg", headers=headers)

    fallback = os.path.join(FRONTEND_DIR, "fallback-icon.svg")
    if os.path.exists(fallback):
        return FileResponse(fallback, media_type="image/svg+xml", headers=headers)

    raise HTTPException(status_code=404, detail="Thumbnail not found")


@app.get("/api/video/{download_id}")
def serve_video(download_id: str, download: bool = Query(False)):
    """
    Serves the actual media file after verifying path containment inside DOWNLOAD_DIR
    and enforcing an allowlisted media MIME type + sandbox CSP (M1, M4).
    """
    info = database.get_download(download_id)
    if not info or not info.get("filepath"):
        raise HTTPException(status_code=404, detail="Video file not found in database")

    filepath = os.path.realpath(info["filepath"])
    if not downloader.is_path_within(filepath, downloader.DOWNLOAD_DIR):
        raise HTTPException(status_code=403, detail="Access denied: file outside download directory")

    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="Video file not found on disk")

    ext = os.path.splitext(filepath)[1].lower()
    media_type = MIME_MAP.get(ext)
    if not media_type:
        raise HTTPException(status_code=415, detail="Unsupported media file type")

    headers = {
        "Content-Security-Policy": "sandbox",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    }
    if download:
        dl_name = os.path.basename(info.get("filename") or filepath)
        return FileResponse(filepath, media_type=media_type, filename=dl_name, headers=headers)
    return FileResponse(filepath, media_type=media_type, headers=headers)


@app.get("/api/settings")
def get_app_settings():
    """Retrieves saved application settings"""
    return database.get_settings()


@app.post("/api/settings")
def save_app_settings(settings: SettingsRequest):
    """Saves application settings after validating format, speed limit, subfolder, and custom CLI options"""
    if settings.default_format and settings.default_format not in downloader.ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported default format")

    if settings.default_speed_limit and not downloader.SPEED_LIMIT_RE.match(settings.default_speed_limit.strip()):
        raise HTTPException(status_code=400, detail="Invalid default speed limit format")

    if settings.custom_args:
        try:
            downloader.parse_and_validate_custom_args(settings.custom_args)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    if settings.download_subfolder:
        try:
            downloader.resolve_safe_download_dir(settings.download_subfolder, "test")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    database.save_settings(_model_to_dict(settings))
    apply_logging_settings(settings.enable_access_logs or False)
    return {"status": "success", "message": "Settings saved successfully"}


@app.get("/api/activity-logs")
def get_activity_logs():
    """Retrieves all activity logs"""
    return database.get_activity_logs()


@app.post("/api/activity-logs/clear")
def clear_all_activity_logs():
    """Completely clears all activity logs without leaving a new log entry behind"""
    database.clear_activity_logs()
    return {"status": "success", "message": "Logs cleared"}


# Mount frontend files
os.makedirs(FRONTEND_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def read_index():
    """Serve the SPA index page"""
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Welcome. Place index.html inside the frontend/ folder."}
