import sqlite3
import os
import json
import hmac
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse
from backend import privacy

# Read DB_PATH from environment variable, default to './downloads.db'
DB_PATH = os.environ.get("DB_PATH", "./downloads.db")

# Module-level re-entrant lock to serialize writes and WAL checkpoints safely across threads
db_lock = threading.RLock()

# In-memory cache for auth_account to avoid synchronous DDL/commits on every HTTP request (F10)
_cached_auth_account = None
_cached_auth_db_path = None

MAX_ACTIVITY_LOGS = int(os.environ.get("MAX_ACTIVITY_LOGS", "500"))
PBKDF2_ITERATIONS = 600_000
DEFAULT_ADMIN_USER = os.environ.get("INITIAL_USERNAME", "admin").strip() or "admin"
DEFAULT_ADMIN_PASS = os.environ.get("INITIAL_PASSWORD", "corgio") or "corgio"


def _safe_compare_digest(a: str, b: str) -> bool:
    """Constant-time string comparison safe against non-ASCII UTF-8 characters (F3)."""
    return hmac.compare_digest(
        (a or "").encode("utf-8", errors="surrogatepass"),
        (b or "").encode("utf-8", errors="surrogatepass"),
    )


def _invalidate_auth_cache():
    global _cached_auth_account, _cached_auth_db_path
    _cached_auth_account = None
    _cached_auth_db_path = None

ALLOWED_DOWNLOAD_COLUMNS = {
    "title",
    "url",
    "filename",
    "filepath",
    "status",
    "progress",
    "speed",
    "eta",
    "duration",
    "file_size",
    "thumbnail_url",
    "format",
    "date_added",
    "error_log",
    "play_count",
    "domain",
    "metadata_json",
    "download_options",
    "download_log",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _escape_like(val: str) -> str:
    """Escapes SQLite LIKE wildcards (%, _, \\) for safe literal substring matching."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _hash_password(password: str, salt_hex: str) -> str:
    """Computes a 600,000-iteration PBKDF2-HMAC-SHA256 password hash using standard library hashlib."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ITERATIONS,
    )
    return dk.hex()


def _ensure_auth_table_and_seed(cursor: sqlite3.Cursor, allow_reset: bool = False):
    """Creates the single-admin auth_account table and seeds initial default credentials if needed."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_account (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            must_change_password INTEGER DEFAULT 1,
            session_secret TEXT NOT NULL,
            auth_enabled INTEGER DEFAULT 1,
            updated_at TEXT
        )
    """)

    cursor.execute("SELECT * FROM auth_account WHERE id = 1")
    existing = cursor.fetchone()

    init_user = os.environ.get("INITIAL_USERNAME", DEFAULT_ADMIN_USER).strip() or "admin"
    init_pass = os.environ.get("INITIAL_PASSWORD", DEFAULT_ADMIN_PASS) or "corgio"
    reset_requested = allow_reset and (
        os.environ.get("RESET_PASSWORD", "").lower() in ("1", "true", "yes")
        or os.environ.get("CORGIO_RESET_PASSWORD", "").lower() in ("1", "true", "yes")
    )

    if not existing:
        salt_hex = secrets.token_hex(16)
        pwd_hash = _hash_password(init_pass, salt_hex)
        session_secret = secrets.token_hex(32)
        cursor.execute(
            """
            INSERT INTO auth_account (
                id, username, password_salt, password_hash,
                must_change_password, session_secret, auth_enabled, updated_at
            )
            VALUES (1, ?, ?, ?, 1, ?, 1, ?)
            """,
            (init_user, salt_hex, pwd_hash, session_secret, utc_now_iso()),
        )
    elif reset_requested:
        salt_hex = secrets.token_hex(16)
        pwd_hash = _hash_password(init_pass, salt_hex)
        session_secret = secrets.token_hex(32)
        cursor.execute(
            """
            UPDATE auth_account
            SET username = ?,
                password_salt = ?,
                password_hash = ?,
                must_change_password = 1,
                session_secret = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (init_user, salt_hex, pwd_hash, session_secret, utc_now_iso()),
        )


def _enforce_db_permissions():
    """Enforces 0600 permissions on SQLite database files so other host users cannot read history."""
    for suffix in ("", "-wal", "-shm"):
        p = f"{DB_PATH}{suffix}"
        if os.path.exists(p):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass


def extract_base_domain(url):
    if not url:
        return "unknown"
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if not netloc:
            if "://" not in url:
                parsed = urlparse("http://" + url)
                netloc = parsed.netloc.lower()
        netloc = netloc.split(":")[0]
        parts = netloc.split(".")
        if len(parts) <= 2:
            return netloc or "unknown"
        two_part_tlds = {"co.uk", "com.au", "co.jp", "org.uk", "net.au", "gov.uk", "co.in"}
        last_two = ".".join(parts[-2:])
        if last_two in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        else:
            return last_two
    except Exception:
        return "unknown"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _checkpoint_and_compact(conn: sqlite3.Connection):
    """Truncates the WAL file and compacts freed pages via VACUUM when possible."""
    try:
        if not conn.in_transaction:
            conn.execute("VACUUM")
    except sqlite3.OperationalError:
        pass
    try:
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if row and row[0] != 0:
            conn.execute("PRAGMA wal_checkpoint(RESTART)")
    except sqlite3.OperationalError:
        pass
    _enforce_db_permissions()


def init_db():
    with db_lock:
        _invalidate_auth_cache()
        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, mode=0o700, exist_ok=True)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.execute("PRAGMA secure_delete = ON")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id TEXT PRIMARY KEY,
                title TEXT,
                url TEXT,
                filename TEXT,
                filepath TEXT,
                status TEXT,
                progress REAL DEFAULT 0.0,
                speed TEXT DEFAULT '0 KB/s',
                eta TEXT DEFAULT '00:00',
                duration INTEGER DEFAULT 0,
                file_size INTEGER DEFAULT 0,
                thumbnail_url TEXT,
                format TEXT,
                date_added TEXT,
                error_log TEXT,
                play_count INTEGER DEFAULT 0,
                domain TEXT,
                metadata_json TEXT,
                download_options TEXT,
                download_log TEXT
            )
        """)

        for col_stmt in (
            "ALTER TABLE downloads ADD COLUMN play_count INTEGER DEFAULT 0",
            "ALTER TABLE downloads ADD COLUMN domain TEXT",
            "ALTER TABLE downloads ADD COLUMN metadata_json TEXT",
            "ALTER TABLE downloads ADD COLUMN download_options TEXT",
            "ALTER TABLE downloads ADD COLUMN download_log TEXT",
        ):
            try:
                cursor.execute(col_stmt)
            except sqlite3.OperationalError:
                pass

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                message TEXT,
                download_id TEXT,
                timestamp TEXT
            )
        """)

        defaults = {
            "theme": "light",
            "palette": "pembroke",
            "default_format": "mp4",
            "default_speed_limit": "",
            "default_subtitles": "false",
            "custom_args": "",
            "download_subfolder": "",
            "enable_access_logs": "false",
        }
        for key, val in defaults.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))

        _ensure_auth_table_and_seed(cursor, allow_reset=True)

        conn.commit()
        conn.close()
        _enforce_db_permissions()


def recover_interrupted_downloads():
    """Marks any downloads left in 'downloading' or 'pending' state as 'stopped' on startup."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE downloads
            SET status = 'stopped',
                speed = '0 KB/s',
                eta = '00:00',
                error_log = 'Interrupted by server restart'
            WHERE status IN ('downloading', 'pending')
            """
        )
        conn.commit()
        conn.close()


def _sanitize_options_json(download_options):
    if not download_options or not isinstance(download_options, str):
        return download_options
    try:
        opts = json.loads(download_options)
        if isinstance(opts, dict) and "url" in opts and isinstance(opts["url"], str):
            opts["url"] = privacy.sanitize_url_for_storage(opts["url"])
            return json.dumps(opts)
    except Exception:
        pass
    return privacy.redact_urls_in_text(download_options)


def add_download(download_id, url, title=None, status="pending", download_options=None):
    safe_url = privacy.sanitize_url_for_storage(url)
    safe_title = privacy.redact_urls_in_text(title) if title else safe_url
    safe_options = _sanitize_options_json(download_options)
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        date_added = utc_now_iso()
        domain = extract_base_domain(safe_url)
        cursor.execute("""
            INSERT INTO downloads (id, url, title, status, date_added, domain, download_options)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (download_id, safe_url, safe_title, status, date_added, domain, safe_options))
        conn.commit()
        conn.close()


def update_download(download_id, **kwargs):
    if not kwargs:
        return

    fields = []
    values = []
    for key, val in kwargs.items():
        if key not in ALLOWED_DOWNLOAD_COLUMNS:
            raise ValueError(f"Disallowed column in update_download: {key}")
        if key == "url" and isinstance(val, str):
            val = privacy.sanitize_url_for_storage(val)
        elif key == "error_log" and isinstance(val, str):
            val = privacy.redact_urls_in_text(val)
        elif key == "download_options" and isinstance(val, str):
            val = _sanitize_options_json(val)
        fields.append(f"{key} = ?")
        values.append(val)
    values.append(download_id)

    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"UPDATE downloads SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, tuple(values))
        conn.commit()
        conn.close()


def get_download(download_id):
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM downloads WHERE id = ?", (download_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None


def get_all_downloads():
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM downloads ORDER BY date_added DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]


def delete_download(download_id):
    """
    Completely purges a download record and all associated activity logs from SQLite,
    overwriting freed database pages (PRAGMA secure_delete = ON) and truncating the WAL.
    """
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT url, filename, title FROM downloads WHERE id = ?", (download_id,))
        row = cursor.fetchone()

        cursor.execute("DELETE FROM downloads WHERE id = ?", (download_id,))
        cursor.execute("DELETE FROM activity_logs WHERE download_id = ?", (download_id,))

        escaped_id = _escape_like(str(download_id))
        cursor.execute(
            "DELETE FROM activity_logs WHERE message LIKE ? ESCAPE '\\'",
            (f"%{escaped_id}%",),
        )
        if row:
            if row["url"]:
                escaped_url = _escape_like(str(row["url"]))
                cursor.execute(
                    "DELETE FROM activity_logs WHERE message LIKE ? ESCAPE '\\'",
                    (f"%{escaped_url}%",),
                )
            if row["filename"]:
                escaped_fn = _escape_like(str(row["filename"]))
                cursor.execute(
                    "DELETE FROM activity_logs WHERE message LIKE ? ESCAPE '\\'",
                    (f"%{escaped_fn}%",),
                )

        conn.commit()
        _checkpoint_and_compact(conn)
        conn.close()


def add_activity_log(event_type, message, download_id=None):
    safe_msg = privacy.redact_urls_in_text(str(message))[:1000]
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = utc_now_iso()
        cursor.execute("""
            INSERT INTO activity_logs (event_type, message, download_id, timestamp)
            VALUES (?, ?, ?, ?)
        """, (str(event_type)[:50], safe_msg, download_id, timestamp))

        # Automatically prune oldest activity logs beyond MAX_ACTIVITY_LOGS
        cursor.execute(
            """
            DELETE FROM activity_logs
            WHERE id NOT IN (
                SELECT id FROM activity_logs ORDER BY id DESC LIMIT ?
            )
            """,
            (MAX_ACTIVITY_LOGS,),
        )
        conn.commit()
        conn.close()


def get_activity_logs():
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]


def clear_activity_logs():
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM activity_logs")
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'activity_logs'")
        except sqlite3.OperationalError:
            pass
        conn.commit()
        _checkpoint_and_compact(conn)
        conn.close()


def increment_play_count(download_id):
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE downloads 
            SET play_count = COALESCE(play_count, 0) + 1 
            WHERE id = ?
        """, (download_id,))
        conn.commit()
        conn.close()


def get_settings():
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM settings")
        rows = cursor.fetchall()
        conn.close()

        settings = {}
        for row in rows:
            val = row["value"]
            if val == "true":
                settings[row["key"]] = True
            elif val == "false":
                settings[row["key"]] = False
            else:
                settings[row["key"]] = val
        return settings


def save_settings(settings_dict):
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        for key, val in settings_dict.items():
            if isinstance(val, bool):
                val_str = "true" if val else "false"
            else:
                val_str = str(val) if val is not None else ""
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, val_str))
        conn.commit()
        conn.close()


def get_auth_account() -> dict:
    """Retrieves the single admin account record, using an in-memory cache (F10)."""
    global _cached_auth_account, _cached_auth_db_path
    with db_lock:
        if (
            _cached_auth_account is not None
            and _cached_auth_db_path == DB_PATH
            and os.path.exists(DB_PATH)
        ):
            return dict(_cached_auth_account)

        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, mode=0o700, exist_ok=True)

        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_auth_table_and_seed(cursor, allow_reset=False)
        conn.commit()

        cursor.execute("SELECT * FROM auth_account WHERE id = 1")
        row = cursor.fetchone()
        conn.close()

        acct = dict(row)
        acct["must_change_password"] = bool(acct.get("must_change_password", 1))
        acct["auth_enabled"] = bool(acct.get("auth_enabled", 1))
        _cached_auth_account = dict(acct)
        _cached_auth_db_path = DB_PATH
        return acct


def verify_user_credentials(username: str, password: str) -> bool:
    """
    Verifies username and password against stored salted PBKDF2-HMAC-SHA256 hash
    using UTF-8 byte constant-time comparison to prevent timing attacks and TypeError on non-ASCII (F3).
    """
    acct = get_auth_account()
    candidate_user = (username or "").strip().lower()
    stored_user = (acct.get("username") or "").strip().lower()

    computed_hash = _hash_password(password or "", acct["password_salt"])
    hash_ok = _safe_compare_digest(computed_hash, acct["password_hash"])
    user_ok = _safe_compare_digest(candidate_user, stored_user)
    return bool(user_ok and hash_ok)


def update_user_credentials(new_username: str, new_password: str) -> dict:
    """
    Updates the admin username and password with a new random 16-byte salt,
    clears the must_change_password flag, and rotates session_secret to
    invalidate any other active sessions.
    """
    clean_user = new_username.strip()
    with db_lock:
        _invalidate_auth_cache()
        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_auth_table_and_seed(cursor, allow_reset=False)

        salt_hex = secrets.token_hex(16)
        pwd_hash = _hash_password(new_password, salt_hex)
        new_session_secret = secrets.token_hex(32)
        now_str = utc_now_iso()

        cursor.execute(
            """
            UPDATE auth_account
            SET username = ?,
                password_salt = ?,
                password_hash = ?,
                must_change_password = 0,
                session_secret = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (clean_user, salt_hex, pwd_hash, new_session_secret, now_str),
        )
        conn.commit()
        conn.close()
        _enforce_db_permissions()
    return get_auth_account()


def rotate_session_secret() -> str:
    """Rotates the session signing secret, immediately invalidating all issued session cookies."""
    with db_lock:
        _invalidate_auth_cache()
        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_auth_table_and_seed(cursor, allow_reset=False)
        new_secret = secrets.token_hex(32)
        cursor.execute(
            "UPDATE auth_account SET session_secret = ?, updated_at = ? WHERE id = 1",
            (new_secret, utc_now_iso()),
        )
        conn.commit()
        conn.close()
        get_auth_account()
        return new_secret
