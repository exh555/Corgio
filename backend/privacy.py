"""
Privacy helpers shared by the downloader, database, and API layers.

- sanitize_url_for_storage(): strips userinfo credentials and URL fragments, and redacts
  sensitive query parameter values (signed CDN tokens, API keys, session IDs) before a URL
  is persisted to SQLite, written to activity logs, or streamed to the browser console.
- redact_urls_in_text(): applies the same sanitization to every http(s) URL found in a
  free-form log line (e.g. yt-dlp "[generic] Extracting URL: ..." output).
"""

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

REDACTED = "REDACTED"

SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "authorization",
    "auth_token",
    "key",
    "api_key",
    "apikey",
    "sig",
    "signature",
    "policy",
    "key-pair-id",
    "awsaccesskeyid",
    "hdnea",
    "hdnts",
    "hdntl",
    "session",
    "sessionid",
    "session_id",
    "sid",
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "client_secret",
    "jwt",
    "ticket",
    "code",
    "credential",
    "credentials",
}

SENSITIVE_KEY_PREFIXES = ("x-amz-", "x-goog-", "x-oss-", "x-ms-")
SENSITIVE_KEY_SUBSTRINGS = ("token", "secret", "passw", "signature")

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _is_sensitive_key(key: str) -> bool:
    k = (key or "").strip().lower()
    if not k:
        return False
    if k in SENSITIVE_QUERY_KEYS:
        return True
    if k.startswith(SENSITIVE_KEY_PREFIXES):
        return True
    return any(s in k for s in SENSITIVE_KEY_SUBSTRINGS)


def sanitize_url_for_storage(url: str) -> str:
    """
    Returns a privacy-safe copy of url suitable for persistence and display.
    The original query string is preserved byte-for-byte unless a sensitive parameter
    had to be redacted, so ordinary URLs remain retryable.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url

    if not parts.scheme or not parts.netloc:
        return url

    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if any(_is_sensitive_key(k) for k, _ in pairs):
            query = urlencode(
                [(k, REDACTED if _is_sensitive_key(k) else v) for k, v in pairs],
                safe=",:/",
            )

    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def url_was_redacted(url: str) -> bool:
    return bool(url) and REDACTED in url


def redact_urls_in_text(text: str) -> str:
    """Sanitizes every http(s) URL embedded inside a free-form text/log line."""
    if not text or "://" not in text:
        return text
    return _URL_IN_TEXT_RE.sub(lambda m: sanitize_url_for_storage(m.group(0)), text)
