import subprocess
import threading
import os
import re
import uuid
import json
import shutil
import sys
import shlex
import signal
import socket
import ipaddress
import time
import selectors
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from backend import database
from backend import updater
from backend import privacy

sanitize_url_for_storage = privacy.sanitize_url_for_storage

DOWNLOAD_DIR = os.environ.get("DOWNLOAD_DIR", "./downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

THUMBNAIL_DIR = os.path.join(DOWNLOAD_DIR, ".thumbnails")
os.makedirs(THUMBNAIL_DIR, exist_ok=True)

WORK_DIR = os.path.join(DOWNLOAD_DIR, ".work")
os.makedirs(WORK_DIR, exist_ok=True)

MAX_CONCURRENT_DOWNLOADS = max(1, int(os.environ.get("MAX_CONCURRENT_DOWNLOADS", "3")))
MAX_QUEUED_DOWNLOADS = max(1, int(os.environ.get("MAX_QUEUED_DOWNLOADS", "25")))
MIN_FREE_DISK_BYTES = max(0, int(os.environ.get("MIN_FREE_DISK_MB", "100"))) * 1024 * 1024
FAILED_LOG_RETENTION_SEC = 300  # Purge failed/stopped raw logs from RAM after 5 minutes

# Keep track of active download threads, subprocesses, logs, progress, and cancellation state
active_processes = {}
active_threads = {}
logs_queue = {}
logs_expiry_timers = {}
download_progress = {}
cancelled_downloads = set()
purged_downloads = set()
state_lock = threading.RLock()
scan_lock = threading.Lock()
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)

ALLOWED_FORMATS = {"mp4", "best", "audio"}
SPEED_LIMIT_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?[KMGkmg]?$")

# Strict canonical allowlist for custom yt-dlp flags (C1/F13 defense: blocks abbreviations, attached short args, --alias, --exec, --no-check-certificates, etc.)
ALLOWED_BOOLEAN_FLAGS = {
    "--geo-bypass",
    "--no-geo-bypass",
    "--embed-chapters",
    "--no-embed-chapters",
    "--embed-metadata",
    "--no-embed-metadata",
    "--add-metadata",
    "--write-subs",
    "--no-write-subs",
    "--write-auto-subs",
    "--no-write-auto-subs",
    "--embed-subs",
    "--no-embed-subs",
    "--no-playlist",
    "--yes-playlist",
    "--ignore-errors",
    "--restrict-filenames",
    "--windows-filenames",
    "--no-mtime",
    "--mtime",
    "--extract-audio",
    "--keep-video",
    "--no-keep-video",
}

ALLOWED_VALUE_FLAGS = {
    "--sub-langs": re.compile(r"^[a-zA-Z0-9,._*-]{1,64}$"),
    "--playlist-items": re.compile(r"^[0-9:,-]{1,64}$"),
    "--playlist-start": re.compile(r"^[1-9][0-9]{0,4}$"),
    "--playlist-end": re.compile(r"^[1-9][0-9]{0,4}$"),
    "--max-downloads": re.compile(r"^[1-9][0-9]{0,4}$"),
    "--concurrent-fragments": re.compile(r"^(?:[1-9]|1[0-6])$"),
    "-N": re.compile(r"^(?:[1-9]|1[0-6])$"),
    "--retries": re.compile(r"^(?:[1-9][0-9]?|infinite)$"),
    "-R": re.compile(r"^(?:[1-9][0-9]?|infinite)$"),
    "--fragment-retries": re.compile(r"^(?:[1-9][0-9]?|infinite)$"),
    "--sleep-interval": re.compile(r"^[0-9]{1,3}(?:\.[0-9]+)?$"),
    "--max-sleep-interval": re.compile(r"^[0-9]{1,3}(?:\.[0-9]+)?$"),
    "--audio-format": re.compile(r"^(?:mp3|m4a|wav|flac|opus|aac|vorbis|alac|best)$"),
    "--audio-quality": re.compile(r"^(?:[0-9]|10|[0-9]{2,3}[Kk])$"),
    "--remux-video": re.compile(r"^(?:mp4|mkv|webm|mov|avi)$"),
    "--recode-video": re.compile(r"^(?:mp4|mkv|webm|mov|avi)$"),
    "--extractor-args": re.compile(r"^[a-zA-Z0-9_]+:[a-zA-Z0-9_,:;=+/.@-]{1,1024}$"),
    "--limit-rate": SPEED_LIMIT_RE,
    "-r": SPEED_LIMIT_RE,
}

# Anchored regex patterns to extract yt-dlp progress and output paths safely (M1 defense)
progress_re = re.compile(
    r"^\[download\]\s+(\d+(?:\.\d+)?)%\s+of\s+([~\d\.]+\w+)\s+at\s+([^\s]+)\s+ETA\s+([^\s]+)"
)
destination_re = re.compile(r"^\[download\] Destination: (.+)$")
merge_re = re.compile(r'^\[Merger\] Merging formats into "(.+)"$')
audio_re = re.compile(r"^\[(?:ExtractAudio|ffmpeg)\] Destination: (.+)$")

MEDIA_EXTENSIONS = {".mp4", ".mkv", ".webm", ".avi", ".mov", ".mp3", ".m4a", ".flac", ".wav", ".opus"}

BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".localdomain",
)


def is_path_within(child_path: str, parent_dir: str) -> bool:
    """Verifies that child_path resolves strictly inside parent_dir."""
    if not child_path or not parent_dir:
        return False
    try:
        parent_real = os.path.realpath(parent_dir)
        child_real = os.path.realpath(child_path)
        return (
            child_real != parent_real
            and os.path.commonpath([parent_real, child_real]) == parent_real
        )
    except Exception:
        return False


def _is_restricted_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        return not ip_obj.is_global
    except ValueError:
        return False


def validate_download_url(url: str) -> str:
    """
    Validates that the URL is a well-formed public HTTP/HTTPS URL, contains no whitespace
    or control characters, cannot be parsed as a CLI option, and does not target internal/SSRF addresses.
    Unwraps search engine redirection wrappers (e.g. Google /url?q=...).
    """
    if not url or not url.strip():
        raise ValueError("URL cannot be empty")
    clean = url.strip()
    if clean.startswith("-"):
        raise ValueError("Invalid URL: cannot start with '-'")
    if any(ord(c) <= 32 or ord(c) == 127 for c in clean):
        raise ValueError("Invalid URL: cannot contain whitespace or control characters")

    # Unwrap search engine redirectors (e.g. google.com/url?q=...)
    try:
        parsed_redir = urlparse(clean)
        if parsed_redir.hostname and parsed_redir.hostname.endswith("google.com") and parsed_redir.path == "/url":
            qs = parse_qs(parsed_redir.query)
            target = qs.get("q", [None])[0] or qs.get("url", [None])[0]
            if target and (target.startswith("http://") or target.startswith("https://")):
                clean = target.strip()
    except Exception:
        pass

    parsed = urlparse(clean)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise ValueError("Invalid URL: only http:// and https:// URLs are supported")

    allow_private = os.environ.get("ALLOW_PRIVATE_URLS", "").lower() in ("1", "true", "yes")
    if not allow_private:
        host = parsed.hostname.lower().rstrip(".")
        if (
            host in ("localhost", "metadata.google.internal", "metadata")
            or host.endswith(BLOCKED_HOST_SUFFIXES)
        ):
            raise ValueError("URL targets a restricted internal or local hostname")

        # Check literal IP address
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if is_ip_literal:
            if _is_restricted_ip(host):
                raise ValueError("URL targets a restricted private, loopback, or link-local IP address")
        else:
            # Resolve DNS and fail closed if unresolvable or if any IP points to non-global address
            try:
                addr_info = socket.getaddrinfo(host, None)
                if not addr_info:
                    raise ValueError("URL host could not be resolved via DNS")
                for entry in addr_info:
                    resolved_ip = entry[4][0]
                    if _is_restricted_ip(resolved_ip):
                        raise ValueError(
                            "URL resolves to a restricted internal, loopback, or private network address"
                        )
            except socket.gaierror:
                raise ValueError("URL host cannot be resolved via DNS")

    return clean


def is_explicit_playlist_url(raw_url: str) -> bool:
    """
    Detects whether a URL is an intentional, dedicated playlist or album container
    (e.g., YouTube playlist, SoundCloud set, Bandcamp album) rather than a single
    video or article page that merely embeds a related/recommendation carousel.
    """
    try:
        parsed = urlparse(raw_url)
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        netloc = (parsed.netloc or "").lower()

        # YouTube pure playlist: /playlist?list=... (and NOT /watch with ?v=)
        if any(h in netloc for h in ("youtube.com", "youtu.be")):
            if "/playlist" in path and "list=" in query:
                return True
            return False

        # SoundCloud sets
        if "soundcloud.com" in netloc and "/sets/" in path:
            return True

        # Album containers on supported audio/music platforms (F-18)
        MUSIC_ALBUM_DOMAINS = ("bandcamp.com", "soundcloud.com", "music.apple.com", "spotify.com")
        if "/album/" in path and any(d in netloc for d in MUSIC_ALBUM_DOMAINS):
            return True

        return False
    except Exception:
        return False


def is_youtube_url(raw_url: str) -> bool:
    """Detects whether a URL belongs to YouTube or youtu.be."""
    try:
        parsed = urlparse(raw_url)
        netloc = (parsed.netloc or "").lower()
        return any(h in netloc for h in ("youtube.com", "youtu.be"))
    except Exception:
        return False


def get_js_runtime_info() -> str:
    """Returns detected JavaScript runtime name and version for status inspection."""
    for name in ("deno", "node", "nodejs", "bun"):
        path = shutil.which(name)
        if path:
            try:
                out = subprocess.check_output([path, "--version"], text=True, timeout=2).strip()
                first_line = out.splitlines()[0] if out else ""
                return f"{name} {first_line}"
            except Exception:
                return f"{name} ({path})"
    return "None detected"


def get_cookies_path() -> str:
    """
    Resolves available cookies.txt file path from environment or persistent config directory.
    Returns path string if file exists and is non-empty, otherwise empty string.
    """
    env_path = os.environ.get("COOKIES_FILE", "").strip()
    if env_path and os.path.isfile(env_path) and os.path.getsize(env_path) > 0:
        return env_path

    # Standard Docker/Unraid persistent configuration location
    config_cookies = "/config/cookies.txt"
    if os.path.isfile(config_cookies) and os.path.getsize(config_cookies) > 0:
        return config_cookies

    # Local development or project root fallback
    local_cookies = os.path.join(os.getcwd(), "cookies.txt")
    if os.path.isfile(local_cookies) and os.path.getsize(local_cookies) > 0:
        return local_cookies

    return ""


def get_cookies_status() -> dict:
    """Returns telemetry information on whether a valid cookies.txt file is loaded."""
    path = get_cookies_path()
    if path:
        try:
            stat = os.stat(path)
            display_path = "/config/cookies.txt" if "/config" in path else os.path.basename(path)
            return {
                "active": True,
                "path": display_path,
                "filename": os.path.basename(path),
                "size_bytes": stat.st_size,
                "mtime": stat.st_mtime,
            }
        except Exception:
            return {"active": False, "path": "", "filename": "", "size_bytes": 0, "mtime": 0}
    return {"active": False, "path": "", "filename": "", "size_bytes": 0, "mtime": 0}


def get_js_runtime_args(
    url: str = "",
    has_cookies: bool = False,
    custom_has_extractor_args: bool = False,
) -> list:
    """
    Detects if a supported JavaScript runtime (deno, node, bun) is available
    to enable yt-dlp's EJS solver for YouTube signature deciphering and n-challenges.
    Prioritizes Deno (yt-dlp default-enabled engine).
    Leaves YouTube player client negotiation to default and embedded clients without forcing
    the Android client, avoiding unauthenticated GVS PO token restrictions on adaptive formats.
    """
    args = []
    deno_bin = shutil.which("deno")
    if deno_bin:
        args.extend(["--js-runtimes", f"deno:{deno_bin}"])
    else:
        node_bin = shutil.which("node") or shutil.which("nodejs")
        if node_bin:
            args.extend(["--js-runtimes", f"node:{node_bin}"])
        else:
            bun_bin = shutil.which("bun")
            if bun_bin:
                args.extend(["--js-runtimes", f"bun:{bun_bin}"])

    return args


def parse_and_validate_custom_args(custom_args_str: str) -> list:
    """
    Strictly validates custom CLI options against an exact canonical allowlist of safe flags
    and per-flag value regexes. Rejects prefix abbreviations, attached short flags, --alias,
    --exec, file paths, and extra positional arguments.
    """
    if not custom_args_str or not custom_args_str.strip():
        return []
    try:
        tokens = shlex.split(custom_args_str.strip())
    except ValueError as e:
        raise ValueError(f"Invalid custom CLI options syntax: {str(e)}")

    validated = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("-"):
            raise ValueError(
                f"Positional argument '{token}' is not allowed in custom CLI flags."
            )

        if "=" in token:
            flag_name, flag_val = token.split("=", 1)
            if flag_name not in ALLOWED_VALUE_FLAGS:
                raise ValueError(
                    f"CLI option '{flag_name}' is not in the allowed safe flags list."
                )
            validator = ALLOWED_VALUE_FLAGS[flag_name]
            if not validator.match(flag_val):
                raise ValueError(
                    f"Invalid value '{flag_val}' for CLI option '{flag_name}'."
                )
            validated.extend([flag_name, flag_val])
            i += 1
        elif token in ALLOWED_BOOLEAN_FLAGS:
            validated.append(token)
            i += 1
        elif token in ALLOWED_VALUE_FLAGS:
            if i + 1 >= len(tokens):
                raise ValueError(f"CLI option '{token}' requires a value.")
            flag_val = tokens[i + 1]
            validator = ALLOWED_VALUE_FLAGS[token]
            if not validator.match(flag_val):
                raise ValueError(
                    f"Invalid value '{flag_val}' for CLI option '{token}'."
                )
            validated.extend([token, flag_val])
            i += 2
        else:
            raise ValueError(
                f"CLI option '{token}' is not permitted for container security and privacy."
            )

    return validated


def resolve_safe_download_dir(subfolder: str, domain: str) -> str:
    """Resolves a target download directory guaranteed to reside within DOWNLOAD_DIR."""
    base_real = os.path.realpath(DOWNLOAD_DIR)
    safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", (domain or "unknown").strip()) or "unknown"
    if safe_domain in (".", ".."):
        safe_domain = "unknown"

    parts = [base_real]
    if subfolder and subfolder.strip():
        raw_sub = subfolder.strip().lstrip("/\\")
        norm_sub = os.path.normpath(raw_sub)
        sub_parts = [
            p for p in norm_sub.split(os.sep) if p and p not in (".", "..", ".thumbnails", ".work")
        ]
        if sub_parts:
            parts.extend(sub_parts)

    parts.append(safe_domain)
    target_real = os.path.realpath(os.path.join(*parts))

    if os.path.commonpath([base_real, target_real]) != base_real:
        raise ValueError("Invalid download subfolder path: outside allowed download directory")

    return target_real


def cleanup_all_work_dirs():
    """Cleans up any leftover temporary work directories on server startup."""
    if os.path.exists(WORK_DIR):
        for entry in os.listdir(WORK_DIR):
            entry_path = os.path.join(WORK_DIR, entry)
            try:
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path, ignore_errors=True)
                else:
                    os.remove(entry_path)
            except Exception:
                pass


def _schedule_log_expiry(download_id: str, delay_sec: int = FAILED_LOG_RETENTION_SEC):
    """Schedules automatic removal of failed/stopped raw console logs from RAM."""
    def _expire():
        with state_lock:
            logs_queue.pop(download_id, None)
            logs_expiry_timers.pop(download_id, None)

    with state_lock:
        old_timer = logs_expiry_timers.pop(download_id, None)
        if old_timer:
            old_timer.cancel()
        timer = threading.Timer(delay_sec, _expire)
        timer.daemon = True
        logs_expiry_timers[download_id] = timer
        timer.start()


def _cancel_log_expiry(download_id: str):
    with state_lock:
        timer = logs_expiry_timers.pop(download_id, None)
        if timer:
            timer.cancel()


def _append_log(download_id: str, line: str):
    """Appends a sanitized log line only if the download has not been purged (F2)."""
    safe_line = privacy.redact_urls_in_text(line)
    with state_lock:
        if download_id in purged_downloads:
            return
        logs = logs_queue.get(download_id)
        if logs is not None:
            logs.append(safe_line)
            if len(logs) > 2000:
                logs.pop(0)


def _safe_update_db(download_id: str, **kwargs):
    """Updates the download record in SQLite atomically only if it has not been purged."""
    with state_lock:
        if download_id in purged_downloads:
            return
        if kwargs.get("status") in ("completed", "failed", "stopped") and "download_log" not in kwargs:
            current_logs = list(logs_queue.get(download_id, []))
            if current_logs:
                kwargs["download_log"] = "\n".join(current_logs)
        database.update_download(download_id, **kwargs)


def _safe_activity_log(download_id: str, event_type: str, message: str):
    """Records an activity log atomically only if the download has not been purged."""
    with state_lock:
        if download_id in purged_downloads:
            return
        database.add_activity_log(event_type, message, download_id)


def _kill_process_tree(process: subprocess.Popen):
    """Terminates a subprocess and all its child processes (including ffmpeg/ffprobe)."""
    if not process or process.poll() is not None:
        return
    try:
        pgid = os.getpgid(process.pid)
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        try:
            process.terminate()
        except Exception:
            pass

    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


def get_active_downloads():
    with state_lock:
        return [
            {
                "id": dl_id,
                "progress": data.get("progress", 0.0),
                "speed": data.get("speed", "0 KB/s"),
                "eta": data.get("eta", "00:00"),
                "status": data.get("status", "downloading"),
                "stage": data.get("stage", "downloading"),
                "title": data.get("title", "Unknown"),
                "url": data.get("url", ""),
                "domain": data.get("domain", ""),
                "format": data.get("format", "mp4"),
            }
            for dl_id, data in download_progress.items()
            if dl_id not in purged_downloads
        ]


def get_logs(download_id):
    with state_lock:
        return list(logs_queue.get(download_id, []))


def stop_download(download_id):
    """Stops an active download (and any child ffmpeg encoder processes)."""
    with state_lock:
        is_active = (
            download_id in active_processes
            or download_id in active_threads
            or download_id in download_progress
        )
        if not is_active:
            return False
        cancelled_downloads.add(download_id)
        process = active_processes.get(download_id)
        if download_id in download_progress:
            download_progress[download_id]["status"] = "stopped"

    if process:
        _kill_process_tree(process)

    _safe_update_db(download_id, status="stopped", error_log="Stopped by user")

    job_work_dir = os.path.join(WORK_DIR, os.path.basename(download_id))
    if os.path.exists(job_work_dir):
        shutil.rmtree(job_work_dir, ignore_errors=True)

    _schedule_log_expiry(download_id)
    return True


def purge_download_state(download_id):
    """
    Completely halts any active downloader/encoder processes for download_id,
    waits for the worker thread to exit, and purges all in-memory logs, progress,
    temporary downloader/encoder work files, and thumbnails.
    """
    _cancel_log_expiry(download_id)
    with state_lock:
        purged_downloads.add(download_id)
        cancelled_downloads.add(download_id)
        process = active_processes.get(download_id)
        thread = active_threads.get(download_id)
        prog_data = download_progress.get(download_id) or {}
        tracked_final_path = prog_data.get("final_filepath")

    if process:
        _kill_process_tree(process)

    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=5.0)

    with state_lock:
        active_processes.pop(download_id, None)
        active_threads.pop(download_id, None)
        logs_queue.pop(download_id, None)
        prog_after = download_progress.pop(download_id, None) or {}
        if not tracked_final_path:
            tracked_final_path = prog_after.get("final_filepath")

    safe_id = os.path.basename(download_id)
    job_work_dir = os.path.join(WORK_DIR, safe_id)
    if os.path.exists(job_work_dir):
        shutil.rmtree(job_work_dir, ignore_errors=True)

    if tracked_final_path and is_path_within(tracked_final_path, DOWNLOAD_DIR):
        if os.path.exists(tracked_final_path):
            try:
                os.remove(tracked_final_path)
            except Exception:
                pass

    thumb_path = os.path.join(THUMBNAIL_DIR, f"{safe_id}.jpg")
    if os.path.exists(thumb_path):
        try:
            os.remove(thumb_path)
        except Exception:
            pass

    if not (thread and thread.is_alive()):
        with state_lock:
            cancelled_downloads.discard(download_id)
            purged_downloads.discard(download_id)


def scrub_container_metadata(file_path: str, ffmpeg_bin: str = None) -> bool:
    """
    Performs a fast stream-copy remux using ffmpeg with -map_metadata -1 -map_chapters -1
    to scrub all container tags, comments, and chapter metadata without re-encoding (F-11).
    """
    if not ffmpeg_bin:
        ffmpeg_bin = updater.get_ffmpeg_binary("ffmpeg")
    if not ffmpeg_bin or not os.path.exists(file_path):
        return False
    ext = os.path.splitext(file_path)[1]
    tmp_out = f"{file_path}.clean{ext}"
    try:
        cmd = [
            ffmpeg_bin,
            "-y",
            "-loglevel", "error",
            "-nostdin",
            "-protocol_whitelist", "file",
            "-i", os.path.realpath(file_path),
            "-map", "0",
            "-map_metadata", "-1",
            "-map_chapters", "-1",
            "-c", "copy",
            os.path.realpath(tmp_out),
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        if res.returncode == 0 and os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
            os.replace(tmp_out, file_path)
            return True
        else:
            if os.path.exists(tmp_out):
                try:
                    os.remove(tmp_out)
                except OSError:
                    pass
            return False
    except Exception:
        if os.path.exists(tmp_out):
            try:
                os.remove(tmp_out)
            except OSError:
                pass
        return False


def generate_video_thumbnail(video_path, thumbnail_path, duration=0, seek_sec=None, download_id=None):
    """
    Uses ffmpeg with restricted file protocol whitelist to extract a thumbnail frame.
    Supports custom seek_sec (e.g. from user player frame capture).
    """
    try:
        ffmpeg_bin = updater.get_ffmpeg_binary("ffmpeg")
        if not ffmpeg_bin:
            return False
        if download_id and _is_cancelled_or_purged(download_id):
            return False

        if seek_sec is None:
            seek_sec = 5
            if duration and 0 < duration < 6:
                seek_sec = max(0, int(duration // 3))

        try:
            seek_num = max(0.0, float(seek_sec))
        except (ValueError, TypeError):
            seek_num = 5.0

        hours = int(seek_num // 3600)
        mins = int((seek_num % 3600) // 60)
        secs = seek_num % 60
        seek_str = f"{hours:02d}:{mins:02d}:{secs:06.3f}"

        if download_id:
            _append_log(download_id, f"[encoder] Extracting thumbnail frame at {seek_str} via ffmpeg...")

        sub_env = updater.get_yt_dlp_env()
        cmd = [
            ffmpeg_bin,
            "-nostdin",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-ss",
            seek_str,
            "-i",
            video_path,
            "-map_metadata",
            "-1",
            "-vframes",
            "1",
            "-q:v",
            "4",
            "--",
            thumbnail_path,
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            start_new_session=True,
            env=sub_env,
        )
        if result.returncode == 0 and os.path.exists(thumbnail_path) and os.path.getsize(thumbnail_path) > 0:
            return True

        if seek_sec > 0 and not (download_id and _is_cancelled_or_purged(download_id)):
            cmd_fallback = [
                ffmpeg_bin,
                "-nostdin",
                "-y",
                "-hide_banner",
                "-loglevel",
                "error",
                "-protocol_whitelist",
                "file,pipe",
                "-ss",
                "00:00:00",
                "-i",
                video_path,
                "-map_metadata",
                "-1",
                "-vframes",
                "1",
                "-q:v",
                "4",
                "--",
                thumbnail_path,
            ]
            res2 = subprocess.run(
                cmd_fallback,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                start_new_session=True,
                env=sub_env,
            )
            if res2.returncode == 0 and os.path.exists(thumbnail_path) and os.path.getsize(thumbnail_path) > 0:
                return True

        if download_id:
            _append_log(download_id, "[encoder] Thumbnail extraction skipped or unsupported for this media stream.")
        return False
    except Exception:
        if download_id:
            _append_log(download_id, "[encoder] Thumbnail generation encountered an error.")
        return False


def get_video_duration(video_path):
    try:
        ffprobe_bin = updater.get_ffmpeg_binary("ffprobe")
        if not ffprobe_bin:
            return 0
        cmd = [
            ffprobe_bin,
            "-v",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            "--",
            video_path,
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=15,
            start_new_session=True,
            env=updater.get_yt_dlp_env(),
        )
        duration = float(result.stdout.strip())
        return int(duration)
    except Exception:
        return 0


def get_video_metadata(video_path):
    try:
        ffprobe_bin = updater.get_ffmpeg_binary("ffprobe")
        if not ffprobe_bin:
            return {}
        cmd = [
            ffprobe_bin,
            "-v",
            "quiet",
            "-protocol_whitelist",
            "file,pipe",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            "--",
            video_path,
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=15,
            start_new_session=True,
            env=updater.get_yt_dlp_env(),
        )
        data = json.loads(result.stdout)

        video_stream = next((s for s in data.get("streams", []) if s.get("codec_type") == "video"), {})
        audio_stream = next((s for s in data.get("streams", []) if s.get("codec_type") == "audio"), {})
        format_info = data.get("format", {})

        width = video_stream.get("width")
        height = video_stream.get("height")

        fps = None
        for key in ("r_frame_rate", "avg_frame_rate"):
            fps_eval = video_stream.get(key, "")
            if fps_eval and "/" in fps_eval:
                try:
                    num, den = map(int, fps_eval.split("/"))
                    if den and num > 0:
                        fps = round(num / den, 2)
                        break
                except (ValueError, ZeroDivisionError):
                    pass

        bitrate = None
        raw_bitrate = format_info.get("bit_rate") or video_stream.get("bit_rate")
        if raw_bitrate:
            try:
                bitrate = int(raw_bitrate)
            except (ValueError, TypeError):
                bitrate = None
        if not bitrate:
            try:
                dur = float(format_info.get("duration") or 0)
                if dur > 0 and os.path.exists(video_path):
                    bitrate = round((os.path.getsize(video_path) * 8) / dur)
            except Exception:
                bitrate = None

        raw_duration = format_info.get("duration")
        duration = int(float(raw_duration)) if raw_duration else 0

        return {
            "uploader": "Local File",
            "upload_date": datetime.fromtimestamp(os.path.getmtime(video_path)).strftime("%Y-%m-%d"),
            "width": width,
            "height": height,
            "fps": fps,
            "vcodec": video_stream.get("codec_name"),
            "acodec": audio_stream.get("codec_name"),
            "bitrate": bitrate,
            "duration": duration,
            "description": format_info.get("tags", {}).get("comment", "Local imported media file."),
        }
    except Exception:
        return {}


def _is_cancelled_or_purged(download_id: str) -> bool:
    with state_lock:
        return download_id in cancelled_downloads or download_id in purged_downloads


def run_yt_dlp_download(download_id, url, settings):
    safe_url = privacy.sanitize_url_for_storage(url)
    domain_initial = database.extract_base_domain(safe_url)
    format_initial = (settings or {}).get("format") or "mp4"
    if format_initial not in ALLOWED_FORMATS:
        format_initial = "mp4"

    with state_lock:
        if download_id in purged_downloads:
            return
        logs_queue[download_id] = []
        download_progress[download_id] = {
            "progress": 0.0,
            "speed": "0 KB/s",
            "eta": "00:00",
            "status": "downloading",
            "stage": "metadata",
            "title": safe_url,
            "url": safe_url,
            "domain": domain_initial,
            "format": format_initial,
            "final_filepath": None,
        }

    safe_id = os.path.basename(download_id)
    job_work_dir = os.path.join(WORK_DIR, safe_id)
    local_thumb_path = os.path.join(THUMBNAIL_DIR, f"{safe_id}.jpg")
    final_filepath = None
    title = safe_url
    duration = 0
    metadata_json = "{}"
    download_succeeded = False
    acquired_sem = False

    try:
        download_semaphore.acquire()
        acquired_sem = True

        if _is_cancelled_or_purged(download_id):
            return

        os.makedirs(job_work_dir, exist_ok=True)
        yt_env = updater.get_yt_dlp_env()
        db_settings = database.get_settings()
        cookies_path = get_cookies_path()

        # 1. Fetch metadata first (fast check, isolated from user config/plugins/cache)
        _append_log(download_id, "[system] Fetching metadata...")
        detected_playlist = False
        is_explicit_playlist = is_explicit_playlist_url(url)
        info_cmd = [
            sys.executable,
            "-m",
            "yt_dlp",
            "--ignore-config",
            "--no-plugin-dirs",
            "--no-cache-dir",
            "--dump-json",
            "--skip-download",
        ]
        if cookies_path:
            info_cmd.extend(["--cookies", cookies_path])
        else:
            info_cmd.append("--no-cookies")

        if not is_explicit_playlist:
            info_cmd.append("--no-playlist")

        # Parse user custom flags for metadata probe to support custom extractor-args/PO tokens
        meta_custom_args_val = settings.get("custom_args")
        if meta_custom_args_val is None:
            meta_custom_args_val = db_settings.get("custom_args", "")
        meta_custom_args = []
        if meta_custom_args_val:
            try:
                meta_custom_args = parse_and_validate_custom_args(meta_custom_args_val)
            except ValueError:
                meta_custom_args = []
        meta_has_ext = any(a == "--extractor-args" for a in meta_custom_args)

        info_cmd.extend(
            get_js_runtime_args(
                url,
                has_cookies=bool(cookies_path),
                custom_has_extractor_args=meta_has_ext,
            )
        )
        if meta_custom_args:
            info_cmd.extend(meta_custom_args)
        info_cmd.extend(["--", url])
        try:
            info_proc = subprocess.Popen(
                info_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                env=yt_env,
            )
            with state_lock:
                active_processes[download_id] = info_proc

            try:
                stdout_data, stderr_data = info_proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                _kill_process_tree(info_proc)
                stdout_data, stderr_data = "", "Metadata fetch timed out"

            if _is_cancelled_or_purged(download_id):
                return

            if info_proc.returncode == 0 and stdout_data:
                lines = [ln.strip() for ln in stdout_data.splitlines() if ln.strip()]
                if lines:
                    first_line = lines[0]
                    info_data = json.loads(first_line)
                    if len(lines) > 1 or bool(info_data.get("playlist")) or info_data.get("_type") == "playlist":
                        detected_playlist = True
                else:
                    info_data = {}
                raw_title = info_data.get("title") or safe_url
                title = privacy.redact_urls_in_text(raw_title)
                duration = int(info_data.get("duration") or 0)

                raw_date = info_data.get("upload_date", "") or ""
                upload_date = ""
                if len(raw_date) == 8:
                    upload_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]}"

                meta_extracted = {
                    "uploader": info_data.get("uploader"),
                    "uploader_url": privacy.sanitize_url_for_storage(info_data.get("uploader_url"))
                    if info_data.get("uploader_url")
                    else None,
                    "upload_date": upload_date,
                    "description": privacy.redact_urls_in_text(info_data.get("description"))
                    if info_data.get("description")
                    else None,
                    "width": info_data.get("width"),
                    "height": info_data.get("height"),
                    "fps": info_data.get("fps"),
                    "vcodec": info_data.get("vcodec"),
                    "acodec": info_data.get("acodec"),
                }
                metadata_json = json.dumps(meta_extracted)

                _safe_update_db(
                    download_id,
                    title=title,
                    duration=duration,
                    status="downloading",
                    metadata_json=metadata_json,
                )
                with state_lock:
                    if download_id in download_progress:
                        download_progress[download_id]["title"] = title
                _append_log(download_id, f"[system] Metadata retrieved: {title}")
            else:
                stderr_lines = [
                    ln.strip()
                    for ln in (stderr_data or "").splitlines()
                    if ln.strip() and not ln.strip().startswith("Deprecated Feature: Support for Python version")
                ]
                err_snippet = (stderr_lines[-1] if stderr_lines else "No metadata returned")[:140]
                _append_log(download_id, f"[system] Metadata check skipped or timed out: {err_snippet}")
        except Exception:
            _append_log(download_id, "[system] Metadata check skipped.")

        if _is_cancelled_or_purged(download_id):
            return

        with state_lock:
            if download_id in download_progress:
                download_progress[download_id]["stage"] = "downloading"

        # 2. Build yt-dlp arguments (isolated work directory, no config/plugins/cache)
        cmd = [
            sys.executable,
            "-m",
            "yt_dlp",
            "--ignore-config",
            "--no-plugin-dirs",
            "--newline",
            "--progress",
            "--no-cache-dir",
        ]
        if cookies_path:
            cmd.extend(["--cookies", cookies_path])
            _append_log(download_id, f"[system] Stream authentication: active ({os.path.basename(cookies_path)})")
        else:
            cmd.append("--no-cookies")

        if not is_explicit_playlist:
            cmd.append("--no-playlist")

        # Format selection (strictly restricted to ALLOWED_FORMATS)
        format_opt = settings.get("format") or db_settings.get("default_format", "mp4")
        if format_opt not in ALLOWED_FORMATS:
            format_opt = "mp4"

        if format_opt == "mp4":
            cmd.extend(["-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best[ext=mp4]/best"])
            cmd.extend(["--merge-output-format", "mp4"])
        elif format_opt == "best":
            cmd.extend(["-f", "bestvideo+bestaudio/best"])
        elif format_opt == "audio":
            cmd.extend(["-x", "--audio-format", "mp3", "--audio-quality", "0"])

        # Speed limit (strictly validated against SPEED_LIMIT_RE)
        speed_limit = settings.get("speed_limit")
        if speed_limit is None:
            speed_limit = db_settings.get("default_speed_limit", "")
        speed_limit = str(speed_limit or "").strip()
        if speed_limit:
            if not SPEED_LIMIT_RE.match(speed_limit):
                _safe_update_db(download_id, status="failed", error_log="Invalid speed limit format")
                return
            cmd.extend(["-r", speed_limit])

        # Subtitles
        subtitles = settings.get("subtitles")
        if subtitles is None:
            subtitles = db_settings.get("default_subtitles", False)
        if subtitles:
            cmd.extend(["--write-subs", "--embed-subs"])

        # Resolve final destination directory
        domain_folder = database.extract_base_domain(safe_url)
        subfolder = db_settings.get("download_subfolder", "").strip()
        try:
            target_dir = resolve_safe_download_dir(subfolder, domain_folder)
        except ValueError:
            target_dir = resolve_safe_download_dir("", domain_folder)

        os.makedirs(target_dir, exist_ok=True)
        _append_log(download_id, f"[system] Target domain folder: {domain_folder}")

        # Direct all downloads and ffmpeg encoding into the isolated per-job work directory first
        # Format: %(title)s [%(id)s] [%(resolution,format_id)s] [<short_id>].%(ext)s
        # Guarantees multi-resolution and concurrent duplicate jobs never clobber each other.
        short_id = download_id[:6]
        output_template = os.path.join(
            job_work_dir, f"%(title)s [%(id)s] [%(resolution,format_id)s] [{short_id}].%(ext)s"
        )
        cmd.extend(["-o", output_template])
        # Priority 1: Fetch official creator thumbnail from source platform
        cmd.extend(["--write-thumbnail", "--convert-thumbnails", "jpg"])

        # User custom arguments override (validated against strict canonical allowlist)
        validated_args = []
        custom_args_val = settings.get("custom_args")
        if custom_args_val is None:
            custom_args_val = db_settings.get("custom_args", "")
        if custom_args_val:
            try:
                validated_args = parse_and_validate_custom_args(custom_args_val)
                if any(a in ("--yes-playlist", "--playlist-items") for a in validated_args):
                    is_explicit_playlist = True
                    if "--no-playlist" in cmd:
                        cmd.remove("--no-playlist")
                cmd.extend(validated_args)
            except ValueError as e:
                _safe_update_db(download_id, status="failed", error_log=str(e))
                _append_log(download_id, f"[system] Error: {str(e)}")
                return

        # Add JavaScript challenge runtime and extractor args unless overridden by user
        has_user_js = any(a == "--js-runtimes" for a in validated_args)
        has_user_ext = any(a == "--extractor-args" for a in validated_args)
        js_args = get_js_runtime_args(
            url,
            has_cookies=bool(cookies_path),
            custom_has_extractor_args=has_user_ext,
        )
        if js_args:
            filtered_js = []
            skip_next = False
            for arg in js_args:
                if skip_next:
                    skip_next = False
                    continue
                if arg == "--js-runtimes" and has_user_js:
                    skip_next = True
                    continue
                if arg == "--extractor-args" and has_user_ext:
                    skip_next = True
                    continue
                filtered_js.append(arg)
            if filtered_js:
                cmd.extend(filtered_js)
        runtime_info = get_js_runtime_info()
        if "None" not in runtime_info:
            _append_log(download_id, f"[system] JavaScript challenge solver active: {runtime_info}")

        # Strip container metadata by default unless user explicitly passed --embed-metadata or --add-metadata (F2)
        if not any(a in ("--embed-metadata", "--add-metadata") for a in validated_args):
            if "--no-embed-metadata" not in validated_args:
                cmd.append("--no-embed-metadata")
            cmd.extend(["--postprocessor-args", "ffmpeg:-map_metadata -1"])

        # Multi-video page / carousel safeguard:
        # If yt-dlp detected multiple entries (e.g. CNN/news article pages with embedded carousels)
        # on a single-video URL, restrict download to primary video (item 1)
        if not is_explicit_playlist and not any(a in ("--yes-playlist", "--playlist-items", "--playlist-start", "--playlist-end", "--max-downloads") for a in validated_args):
            if detected_playlist:
                cmd.extend(["--playlist-items", "1"])
                _append_log(download_id, "[system] Multi-video page detected: downloading primary video (--playlist-items 1)")

        # Append end-of-options delimiter and raw URL
        cmd.extend(["--", url])

        _append_log(download_id, "[system] Running downloader & encoder pipeline...")
        _safe_activity_log(
            download_id,
            "DOWNLOAD_START",
            f"Started download for URL: {safe_url} (format: {format_opt})",
        )

        work_filepath = None
        last_db_progress_update = 0.0

        if _is_cancelled_or_purged(download_id):
            return

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
            env=yt_env,
        )

        with state_lock:
            active_processes[download_id] = process

        sel = selectors.DefaultSelector()
        sel.register(process.stdout, selectors.EVENT_READ)
        last_activity = time.monotonic()
        WATCHDOG_TIMEOUT_SEC = 300.0  # 5 minutes without process output
        timed_out = False
        disk_exhausted = False

        try:
            while True:
                if _is_cancelled_or_purged(download_id):
                    _kill_process_tree(process)
                    return

                events = sel.select(timeout=1.5)
                if not events:
                    if process.poll() is not None:
                        break
                    now = time.monotonic()
                    if now - last_activity > WATCHDOG_TIMEOUT_SEC:
                        timed_out = True
                        _append_log(download_id, "[system] Error: Download stalled (no data received for 300 seconds). Aborting.")
                        _kill_process_tree(process)
                        break
                    continue

                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue

                last_activity = time.monotonic()
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("Deprecated Feature: Support for Python version"):
                    continue
                _append_log(download_id, clean_line)

                # Monitor remaining disk space on work partition
                if MIN_FREE_DISK_BYTES > 0:
                    try:
                        free_space = shutil.disk_usage(job_work_dir).free
                        if free_space < MIN_FREE_DISK_BYTES:
                            disk_exhausted = True
                            _append_log(download_id, f"[system] Error: Aborted due to low disk space (< {MIN_FREE_DISK_BYTES // (1024*1024)}MB free).")
                            _kill_process_tree(process)
                            break
                    except Exception:
                        pass

                prog_match = progress_re.search(clean_line)
                if prog_match:
                    progress = float(prog_match.group(1))
                    speed = prog_match.group(3)
                    eta = prog_match.group(4)

                    with state_lock:
                        if download_id in download_progress:
                            download_progress[download_id]["progress"] = progress
                            download_progress[download_id]["speed"] = speed
                            download_progress[download_id]["eta"] = eta

                    now = time.monotonic()
                    if now - last_db_progress_update >= 1.5 or progress >= 100.0:
                        last_db_progress_update = now
                        _safe_update_db(
                            download_id,
                            progress=progress,
                            speed=speed,
                            eta=eta,
                            status="downloading",
                        )

                dest_match = destination_re.match(clean_line)
                if dest_match:
                    candidate = dest_match.group(1).strip()
                    if is_path_within(candidate, job_work_dir):
                        work_filepath = candidate

                merge_match = merge_re.match(clean_line)
                if merge_match:
                    candidate = merge_match.group(1).strip()
                    if is_path_within(candidate, job_work_dir):
                        work_filepath = candidate
                    with state_lock:
                        if download_id in download_progress:
                            download_progress[download_id]["stage"] = "encoding"

                audio_match = audio_re.match(clean_line)
                if audio_match:
                    candidate = audio_match.group(1).strip()
                    if is_path_within(candidate, job_work_dir):
                        work_filepath = candidate
                    with state_lock:
                        if download_id in download_progress:
                            download_progress[download_id]["stage"] = "encoding"

                if any(
                    clean_line.startswith(tag)
                    for tag in ("[Merger]", "[ExtractAudio]", "[Fixup", "[EmbedSubtitle]", "[ffmpeg]")
                ):
                    with state_lock:
                        if download_id in download_progress:
                            download_progress[download_id]["stage"] = "encoding"
        finally:
            try:
                sel.unregister(process.stdout)
                sel.close()
            except Exception:
                pass

        process.wait()

        if download_id in purged_downloads:
            return

        if download_id in cancelled_downloads:
            _safe_update_db(download_id, status="stopped", error_log="Stopped by user")
            _append_log(download_id, "[system] Download stopped by user request.")
            return

        if timed_out:
            _safe_update_db(download_id, status="failed", error_log="Download stalled (watchdog timeout)")
            _safe_activity_log(download_id, "DOWNLOAD_FAILED", f"Download stalled (watchdog timeout) for ID {download_id}")
            return

        if disk_exhausted:
            _safe_update_db(download_id, status="failed", error_log="Low disk space")
            _safe_activity_log(download_id, "DOWNLOAD_FAILED", f"Download aborted due to low disk space for ID {download_id}")
            return

        # Collect all valid, non-empty media files completed in job_work_dir
        candidates = []
        if os.path.exists(job_work_dir):
            for f in os.listdir(job_work_dir):
                candidate_path = os.path.realpath(os.path.join(job_work_dir, f))
                if (
                    os.path.isfile(candidate_path)
                    and is_path_within(candidate_path, job_work_dir)
                    and os.path.splitext(f)[1].lower() in MEDIA_EXTENSIONS
                    and os.path.getsize(candidate_path) > 0
                ):
                    candidates.append(candidate_path)

        if candidates:
            # Sort by mtime so earlier downloaded items are processed in chronological order
            candidates.sort(key=lambda p: os.path.getmtime(p))

            # Strip container tags and chapters via stream copy unless user explicitly requested metadata embedding (F-11)
            if not any(a in ("--embed-metadata", "--add-metadata") for a in validated_args):
                _append_log(download_id, "[encoder] Scrubbing container metadata and tags via stream copy...")
                for c_path in candidates:
                    scrub_container_metadata(c_path)

            primary_path = candidates[0]
            filename = os.path.basename(primary_path)
            final_filepath = os.path.realpath(os.path.join(target_dir, filename))

            # Collision defense: if destination file already exists on disk, append unique download suffix
            if os.path.exists(final_filepath):
                stem, ext = os.path.splitext(filename)
                short_id = download_id[:6]
                if short_id not in stem:
                    filename = f"{stem} [{short_id}]{ext}"
                else:
                    filename = f"{stem}_{download_id[:10]}{ext}"
                final_filepath = os.path.realpath(os.path.join(target_dir, filename))

            if not is_path_within(final_filepath, DOWNLOAD_DIR):
                raise ValueError("Resolved output file path is outside allowed download directory")

            with state_lock:
                if download_id in purged_downloads:
                    return
                if download_id in download_progress:
                    download_progress[download_id]["stage"] = "encoding"
                    download_progress[download_id]["final_filepath"] = final_filepath

            shutil.move(primary_path, final_filepath)

            if _is_cancelled_or_purged(download_id):
                return

            file_size = os.path.getsize(final_filepath)
            file_ext = os.path.splitext(filename)[1].replace(".", "").lower()

            if duration == 0 and not _is_cancelled_or_purged(download_id):
                duration = get_video_duration(final_filepath)

            # Post-download ffprobe inspection: enrich missing codecs, fps, and bitrate
            probed_meta = get_video_metadata(final_filepath)
            try:
                current_meta = json.loads(metadata_json) if metadata_json and metadata_json != "{}" else {}
            except Exception:
                current_meta = {}

            if probed_meta:
                if duration == 0 and probed_meta.get("duration"):
                    duration = probed_meta["duration"]
                if probed_meta.get("vcodec") and (not current_meta.get("vcodec") or current_meta.get("vcodec") in ("none", "N/A")):
                    current_meta["vcodec"] = probed_meta["vcodec"]
                if probed_meta.get("acodec") and (not current_meta.get("acodec") or current_meta.get("acodec") in ("none", "N/A")):
                    current_meta["acodec"] = probed_meta["acodec"]
                if probed_meta.get("fps") and not current_meta.get("fps"):
                    current_meta["fps"] = probed_meta["fps"]
                if probed_meta.get("width") and not current_meta.get("width"):
                    current_meta["width"] = probed_meta["width"]
                if probed_meta.get("height") and not current_meta.get("height"):
                    current_meta["height"] = probed_meta["height"]
                if probed_meta.get("bitrate"):
                    current_meta["bitrate"] = probed_meta["bitrate"]

            metadata_json = json.dumps(current_meta)

            if _is_cancelled_or_purged(download_id):
                return

            local_thumb_rel_url = f"/api/thumbnail/{safe_id}.jpg"
            thumb_success = False

            # Priority 1: Check if yt-dlp extracted an official creator thumbnail in work dir
            creator_thumb = None
            if os.path.exists(job_work_dir):
                for f in os.listdir(job_work_dir):
                    f_path = os.path.join(job_work_dir, f)
                    if os.path.isfile(f_path) and os.path.splitext(f)[1].lower() in (".jpg", ".jpeg", ".webp", ".png"):
                        if os.path.getsize(f_path) > 0:
                            creator_thumb = f_path
                            break

            if creator_thumb:
                try:
                    ffmpeg_bin = updater.get_ffmpeg_binary("ffmpeg")
                    if ffmpeg_bin:
                        sub_env = updater.get_yt_dlp_env()
                        c_cmd = [
                            ffmpeg_bin,
                            "-nostdin",
                            "-y",
                            "-hide_banner",
                            "-loglevel",
                            "error",
                            "-protocol_whitelist",
                            "file,pipe",
                            "-i",
                            creator_thumb,
                            "-q:v",
                            "3",
                            "--",
                            local_thumb_path,
                        ]
                        c_res = subprocess.run(
                            c_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=15,
                            env=sub_env,
                        )
                        if c_res.returncode == 0 and os.path.exists(local_thumb_path) and os.path.getsize(local_thumb_path) > 0:
                            thumb_success = True
                            _append_log(download_id, "[system] Saved official creator thumbnail from source platform.")
                    if not thumb_success and creator_thumb.lower().endswith((".jpg", ".jpeg")):
                        shutil.copyfile(creator_thumb, local_thumb_path)
                        thumb_success = True
                        _append_log(download_id, "[system] Saved official creator thumbnail from source platform.")
                except Exception as e:
                    _append_log(download_id, f"[system] Creator thumbnail notice: {e}")

            # Priority 2: Fallback to ffmpeg video frame extraction at 5 seconds
            if not thumb_success and file_ext in ["mp4", "mkv", "webm", "avi", "mov"]:
                thumb_success = generate_video_thumbnail(
                    final_filepath, local_thumb_path, duration=duration, download_id=download_id
                )

            if _is_cancelled_or_purged(download_id):
                return

            with state_lock:
                if download_id in download_progress:
                    download_progress[download_id]["stage"] = "cleaning"

            final_thumbnail = local_thumb_rel_url if thumb_success else "/static/fallback-icon.svg"

            is_partial = process.returncode not in (0, 101)
            err_notice = f"Completed with partial warnings (code {process.returncode})" if is_partial else None

            _append_log(download_id, f"[system] Download completed successfully. Saved to: {filename}")
            if is_partial:
                _append_log(download_id, f"[system] Process exited with code {process.returncode}; successfully retained finished media.")

            with state_lock:
                current_logs = list(logs_queue.get(download_id, []))
            app_settings = database.get_settings()
            persist_logs = app_settings.get("persist_download_logs", True)
            saved_log = "\n".join(current_logs) if (current_logs and persist_logs) else None

            _safe_update_db(
                download_id,
                filename=filename,
                filepath=final_filepath,
                status="completed",
                progress=100.0,
                speed="0 KB/s",
                eta="00:00",
                file_size=file_size,
                duration=duration,
                thumbnail_url=final_thumbnail,
                format=file_ext,
                metadata_json=metadata_json,
                download_log=saved_log,
                error_log=err_notice,
            )
            _safe_activity_log(download_id, "DOWNLOAD_COMPLETE", f"Completed download: {filename}")
            download_succeeded = True

            # If there are additional media files in candidates (e.g. multi-video playlist download),
            # safely promote each additional file into the media library instead of discarding it
            for extra_path in candidates[1:]:
                if not os.path.exists(extra_path):
                    continue
                extra_filename = os.path.basename(extra_path)
                extra_final_path = os.path.realpath(os.path.join(target_dir, extra_filename))
                if not is_path_within(extra_final_path, DOWNLOAD_DIR):
                    continue
                shutil.move(extra_path, extra_final_path)

                extra_id = uuid.uuid4().hex[:12]
                extra_size = os.path.getsize(extra_final_path)
                extra_ext = os.path.splitext(extra_filename)[1].replace(".", "").lower()
                extra_duration = get_video_duration(extra_final_path)
                extra_thumb_path = os.path.join(THUMBNAIL_DIR, f"{extra_id}.jpg")
                extra_thumb_success = False
                if extra_ext in ["mp4", "mkv", "webm", "avi", "mov"]:
                    extra_thumb_success = generate_video_thumbnail(
                        extra_final_path, extra_thumb_path, duration=extra_duration, download_id=extra_id
                    )
                extra_thumb_url = f"/api/thumbnail/{extra_id}.jpg" if extra_thumb_success else "/static/fallback-icon.svg"
                raw_extra_title = os.path.splitext(extra_filename)[0]
                extra_title = re.sub(r"\s*\[[a-zA-Z0-9_-]{6,}\]$", "", raw_extra_title)

                extra_probed = get_video_metadata(extra_final_path)
                extra_meta_json = json.dumps(extra_probed) if extra_probed else "{}"
                if extra_duration == 0 and extra_probed.get("duration"):
                    extra_duration = extra_probed["duration"]

                database.add_download(extra_id, safe_url, title=extra_title, status="completed")
                extra_log = (
                    f"[system] Downloaded as part of playlist item from {safe_url}\n[system] File: {extra_filename}"
                    if persist_logs
                    else None
                )
                database.update_download(
                    extra_id,
                    filename=extra_filename,
                    filepath=extra_final_path,
                    duration=extra_duration,
                    file_size=extra_size,
                    thumbnail_url=extra_thumb_url,
                    format=extra_ext,
                    progress=100.0,
                    speed="0 KB/s",
                    eta="00:00",
                    metadata_json=extra_meta_json,
                    download_log=extra_log,
                )
                _append_log(download_id, f"[system] Playlist item completed: {extra_filename}")
                _safe_activity_log(extra_id, "DOWNLOAD_COMPLETE", f"Completed playlist item: {extra_filename}")
        else:
            err_msg = f"Downloader exited with code {process.returncode}" if process.returncode != 0 else "Could not locate completed media file"
            _safe_update_db(
                download_id,
                status="failed",
                error_log=err_msg,
            )
            _append_log(download_id, f"[system] Error: {err_msg}")
            _safe_activity_log(
                download_id,
                "DOWNLOAD_FAILED",
                f"Download failed for video ID {download_id}: {err_msg}",
            )

    except Exception:
        if not _is_cancelled_or_purged(download_id):
            _safe_update_db(download_id, status="failed", error_log="Internal download processing error")
            _append_log(download_id, "[system] Subprocess execution error.")
            _safe_activity_log(download_id, "DOWNLOAD_FAILED", f"Download error for ID {download_id}")

    finally:
        if acquired_sem:
            download_semaphore.release()

        # Always remove isolated work directory and any intermediate downloader/encoder files
        if os.path.exists(job_work_dir):
            shutil.rmtree(job_work_dir, ignore_errors=True)

        with state_lock:
            was_purged = download_id in purged_downloads
            was_cancelled = download_id in cancelled_downloads
            active_processes.pop(download_id, None)
            active_threads.pop(download_id, None)
            download_progress.pop(download_id, None)
            if download_succeeded or was_purged:
                logs_queue.pop(download_id, None)
            else:
                _schedule_log_expiry(download_id)

        # M3 defense: if purged while finalization was in flight, ensure final_filepath, thumbnail, and DB rows are wiped
        if was_purged:
            if final_filepath and is_path_within(final_filepath, DOWNLOAD_DIR) and os.path.exists(final_filepath):
                try:
                    os.remove(final_filepath)
                except Exception:
                    pass
            if os.path.exists(local_thumb_path):
                try:
                    os.remove(local_thumb_path)
                except Exception:
                    pass
            database.delete_download(download_id)
        elif was_cancelled and not download_succeeded:
            if final_filepath and is_path_within(final_filepath, DOWNLOAD_DIR) and os.path.exists(final_filepath):
                try:
                    os.remove(final_filepath)
                except Exception:
                    pass
            if os.path.exists(local_thumb_path):
                try:
                    os.remove(local_thumb_path)
                except Exception:
                    pass

        with state_lock:
            cancelled_downloads.discard(download_id)
            purged_downloads.discard(download_id)


def start_download(url, settings, download_id=None):
    if privacy.url_was_redacted(url):
        raise ValueError(
            "Cannot retry automatically because the original URL contained sensitive tokens that were redacted for privacy. Please submit a fresh URL."
        )
    clean_url = validate_download_url(url)

    # Enforce bounded queue depth so unbounded threads cannot be spawned (F12)
    with state_lock:
        active_count = sum(
            1 for dl_id, t in active_threads.items() if t.is_alive() and dl_id != download_id
        )
        if active_count >= MAX_QUEUED_DOWNLOADS:
            raise ValueError(
                f"Download queue is full (maximum {MAX_QUEUED_DOWNLOADS} active/queued jobs)"
            )

    # Check free disk space before queueing download (L1 defense)
    if os.path.exists(DOWNLOAD_DIR) and MIN_FREE_DISK_BYTES > 0:
        _, _, free_bytes = shutil.disk_usage(DOWNLOAD_DIR)
        if free_bytes < MIN_FREE_DISK_BYTES:
            raise ValueError("Insufficient free disk space in downloads directory")

    # Validate format & speed limit upfront
    fmt = (settings or {}).get("format")
    if fmt and fmt not in ALLOWED_FORMATS:
        raise ValueError(f"Unsupported format '{fmt}'. Allowed formats: mp4, best, audio")

    spd = (settings or {}).get("speed_limit")
    if spd and not SPEED_LIMIT_RE.match(str(spd).strip()):
        raise ValueError("Invalid speed limit format (examples: 5M, 500K)")

    # Validate custom_args upfront before creating DB record
    custom_args_val = (settings or {}).get("custom_args")
    if custom_args_val is None:
        custom_args_val = database.get_settings().get("custom_args", "")
    if custom_args_val:
        parse_and_validate_custom_args(custom_args_val)

    safe_url = privacy.sanitize_url_for_storage(clean_url)
    stored_settings = dict(settings) if isinstance(settings, dict) else {}
    if "url" in stored_settings:
        stored_settings["url"] = safe_url

    if download_id is None:
        download_id = uuid.uuid4().hex[:12]
        options_json = json.dumps(stored_settings) if stored_settings else None
        database.add_download(download_id, safe_url, status="pending", download_options=options_json)
    else:
        _cancel_log_expiry(download_id)
        with state_lock:
            cancelled_downloads.discard(download_id)
            purged_downloads.discard(download_id)
            logs_queue.pop(download_id, None)
        options_json = json.dumps(stored_settings) if stored_settings else None
        database.update_download(
            download_id,
            status="pending",
            progress=0.0,
            speed="0 KB/s",
            eta="00:00",
            error_log=None,
            download_options=options_json,
        )

    thread = threading.Thread(
        target=run_yt_dlp_download, args=(download_id, clean_url, settings or {}), daemon=True
    )
    with state_lock:
        active_threads[download_id] = thread
    thread.start()

    return download_id


def scan_downloads_folder():
    """
    Scans the downloads folder and synchronizes it with the database.
    Guarded by a non-blocking lock so concurrent scans cannot pile up.
    """
    if not scan_lock.acquire(blocking=False):
        return {"added": 0, "missing": 0, "restored": 0, "busy": True}

    try:
        if not os.path.exists(DOWNLOAD_DIR):
            return {"added": 0, "missing": 0, "restored": 0}

        video_extensions = [".mp4", ".mkv", ".webm", ".avi", ".mov", ".mp3", ".m4a"]
        added_count = 0
        missing_count = 0
        restored_count = 0

        db_rows = database.get_all_downloads()

        db_by_path = {}
        for row in db_rows:
            if row.get("filepath"):
                abs_path = os.path.realpath(row["filepath"])
                db_by_path[abs_path] = {
                    "id": row["id"],
                    "status": row["status"],
                    "filename": row["filename"] or os.path.basename(row["filepath"]),
                    "filepath": row["filepath"],
                }

        for root, dirs, files in os.walk(DOWNLOAD_DIR, followlinks=False):
            for excluded in (".thumbnails", ".work"):
                if excluded in dirs:
                    dirs.remove(excluded)

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in video_extensions:
                    candidate_path = os.path.join(root, file)
                    if os.path.islink(candidate_path):
                        continue
                    filepath = os.path.realpath(candidate_path)
                    if not is_path_within(filepath, DOWNLOAD_DIR):
                        continue

                    if filepath not in db_by_path:
                        download_id = uuid.uuid4().hex[:12]
                        file_size = os.path.getsize(filepath)
                        duration = get_video_duration(filepath)

                        local_thumb_rel_url = f"/api/thumbnail/{download_id}.jpg"
                        local_thumb_path = os.path.join(THUMBNAIL_DIR, f"{download_id}.jpg")

                        thumb_success = False
                        if ext in [".mp4", ".mkv", ".webm", ".avi", ".mov"]:
                            thumb_success = generate_video_thumbnail(
                                filepath, local_thumb_path, duration=duration
                            )

                        thumbnail_url = local_thumb_rel_url if thumb_success else "/static/fallback-icon.svg"

                        mtime = os.path.getmtime(filepath)
                        date_added = datetime.fromtimestamp(mtime).isoformat()

                        rel = os.path.relpath(filepath, os.path.realpath(DOWNLOAD_DIR))
                        parts = rel.split(os.sep)
                        domain = "local"
                        if len(parts) >= 2:
                            parent = parts[-2]
                            if "." in parent:
                                domain = parent

                        local_metadata = get_video_metadata(filepath)
                        local_metadata_json = json.dumps(local_metadata)

                        with database.db_lock:
                            conn = database.get_db_connection()
                            cursor = conn.cursor()
                            cursor.execute(
                                """
                                INSERT INTO downloads (id, url, title, filename, filepath, status, progress, duration, file_size, thumbnail_url, format, date_added, domain, metadata_json)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    download_id,
                                    f"local://{file}",
                                    os.path.splitext(file)[0],
                                    file,
                                    filepath,
                                    "completed",
                                    100.0,
                                    duration,
                                    file_size,
                                    thumbnail_url,
                                    ext.replace(".", ""),
                                    date_added,
                                    domain,
                                    local_metadata_json,
                                ),
                            )
                            conn.commit()
                            conn.close()

                        database.add_activity_log(
                            "SCAN_ADD",
                            f"Imported new file during scan: {file}",
                            download_id,
                        )
                        added_count += 1

        for abs_path, item in db_by_path.items():
            dl_id = item["id"]
            status = item["status"]
            filename = item["filename"]

            if status in ("completed", "missing"):
                file_exists = os.path.exists(abs_path) and is_path_within(abs_path, DOWNLOAD_DIR)

                if status == "completed" and not file_exists:
                    database.update_download(dl_id, status="missing")
                    database.add_activity_log(
                        "SCAN_MISSING",
                        f"File not found on disk, marked as missing: {filename}",
                        dl_id,
                    )
                    missing_count += 1
                elif status == "missing" and file_exists:
                    database.update_download(dl_id, status="completed")
                    database.add_activity_log(
                        "SCAN_RESTORE",
                        f"Missing file restored on disk: {filename}",
                        dl_id,
                    )
                    restored_count += 1

        return {
            "added": added_count,
            "missing": missing_count,
            "restored": restored_count,
        }
    finally:
        scan_lock.release()
