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
    # Sensitive CDN, playback IP, and stream integrity parameters (F-06)
    "ip",
    "lsig",
    "pot",
    "n",
    "ei",
    "s",
    "st",
    "e",
    "md5",
    "hash",
    "hmac",
    "exp",
    "expire",
    "acl",
}

SENSITIVE_KEY_PREFIXES = ("x-amz-", "x-goog-", "x-oss-", "x-ms-")
SENSITIVE_KEY_SUBSTRINGS = ("token", "secret", "passw", "signature", "sig", "hash", "hmac")

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_PATH_TOKEN_RE = re.compile(r"/(hdnts|hdnea|hdntl|token|sig|hmac)=[^/]+/", re.IGNORECASE)
_BEARER_RE = re.compile(r"(Authorization:\s*Bearer\s+)[^\s\r\n]+", re.IGNORECASE)
_COOKIE_HEADER_RE = re.compile(r"((?:Set-)?Cookie:\s*)[^\r\n]+", re.IGNORECASE)
_SID_COOKIE_RE = re.compile(r"((?:SID|HSID|SSID|APISID|SAPISID|LOGIN_INFO)=)[^;\s\r\n]+", re.IGNORECASE)


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

    path = parts.path
    if path and "=" in path:
        path = _PATH_TOKEN_RE.sub(r"/\1=REDACTED/", path)

    return urlunsplit((parts.scheme, netloc, path, query, ""))


def url_was_redacted(url: str) -> bool:
    return bool(url) and REDACTED in url


def redact_urls_in_text(text: str) -> str:
    """Sanitizes every http(s) URL, authorization header, and session cookie in free-form text."""
    if not text:
        return text
    res = text
    if "://" in res:
        res = _URL_IN_TEXT_RE.sub(lambda m: sanitize_url_for_storage(m.group(0)), res)
    res = _BEARER_RE.sub(r"\1REDACTED", res)
    res = _COOKIE_HEADER_RE.sub(r"\1REDACTED", res)
    res = _SID_COOKIE_RE.sub(r"\1REDACTED", res)
    return res
