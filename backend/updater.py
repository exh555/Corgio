import os
import re
import hmac
import hashlib
import platform
import subprocess
import shutil
import sys
import tarfile
import tempfile
import threading
import urllib.request
import json
import datetime
from typing import Optional

_cached_yt_dlp_version = None
_cached_ffmpeg_version = None
_update_lock = threading.Lock()

_update_logs = []
_update_logs_lock = threading.Lock()
_update_status = {
    "in_progress": False,
    "success": None,
    "current_step": "idle",
    "started_at": None,
    "finished_at": None,
}


def append_update_log(msg: str):
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    with _update_logs_lock:
        _update_logs.append(formatted)
        if len(_update_logs) > 1000:
            _update_logs.pop(0)


def clear_update_logs():
    with _update_logs_lock:
        _update_logs.clear()


def get_update_logs() -> list:
    with _update_logs_lock:
        return list(_update_logs)


def is_update_in_progress() -> bool:
    with _update_logs_lock:
        return bool(_update_status.get("in_progress", False))


def get_update_status() -> dict:
    with _update_logs_lock:
        return {
            **_update_status,
            "log_count": len(_update_logs),
        }

SAFE_SUBPROCESS_ENV_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PYTHONPATH",
)

YTDLP_FFMPEG_BASE_URL = "https://github.com/yt-dlp/FFmpeg-Builds/releases/latest/download"
YTDLP_FFMPEG_API_URL = "https://api.github.com/repos/yt-dlp/FFmpeg-Builds/releases/latest"


def get_yt_dlp_pkg_dir() -> str:
    custom = os.environ.get("YT_DLP_PKG_DIR", "").strip()
    if custom:
        return os.path.abspath(custom)
    db_path = os.environ.get("DB_PATH", "./downloads.db")
    base_dir = os.path.dirname(os.path.abspath(db_path))
    return os.path.join(base_dir, ".yt-dlp-pkg")


def get_ffmpeg_bin_dir() -> str:
    custom = os.environ.get("FFMPEG_BIN_DIR", "").strip()
    if custom:
        return os.path.abspath(custom)
    db_path = os.environ.get("DB_PATH", "./downloads.db")
    base_dir = os.path.dirname(os.path.abspath(db_path))
    return os.path.join(base_dir, ".ffmpeg-bin")


def get_ffmpeg_binary(name: str = "ffmpeg") -> Optional[str]:
    """Resolves ffmpeg or ffprobe, prioritizing the persistent /config/.ffmpeg-bin overlay."""
    bin_dir = get_ffmpeg_bin_dir()
    overlay_bin = os.path.join(bin_dir, name)
    if os.path.isfile(overlay_bin) and os.access(overlay_bin, os.X_OK):
        return overlay_bin
    return shutil.which(name)


def get_yt_dlp_env() -> dict:
    """
    Returns a sanitized environment dictionary for yt-dlp and ffmpeg subprocesses (F5)
    built from an explicit allowlist of safe environment variables plus isolated
    /config/.yt-dlp-pkg (PYTHONPATH) and /config/.ffmpeg-bin (PATH) overlays.
    Secrets like CORGIO_AUTH_TOKEN and INITIAL_PASSWORD are never passed to subprocesses.
    """
    env = {k: os.environ[k] for k in SAFE_SUBPROCESS_ENV_KEYS if k in os.environ}
    env.setdefault("PATH", os.defpath)
    env["PYTHONNOUSERSITE"] = "1"

    pkg_dir = get_yt_dlp_pkg_dir()
    if os.path.isdir(pkg_dir):
        existing_py = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{pkg_dir}{os.pathsep}{existing_py}" if existing_py else pkg_dir

    ffmpeg_dir = get_ffmpeg_bin_dir()
    if os.path.isdir(ffmpeg_dir):
        existing_path = env.get("PATH", "")
        env["PATH"] = f"{ffmpeg_dir}{os.pathsep}{existing_path}" if existing_path else ffmpeg_dir

    return env


def _get_ytdlp_ffmpeg_asset_name() -> Optional[str]:
    """Returns the official yt-dlp/FFmpeg-Builds static archive name for Linux x86_64 / arm64."""
    if not sys.platform.startswith("linux"):
        return None
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "ffmpeg-master-latest-linux64-gpl.tar.xz"
    if machine in ("aarch64", "arm64"):
        return "ffmpeg-master-latest-linuxarm64-gpl.tar.xz"
    return None


def get_yt_dlp_version(refresh: bool = False) -> str:
    global _cached_yt_dlp_version
    if _cached_yt_dlp_version and not refresh:
        return _cached_yt_dlp_version
    try:
        result = subprocess.run(
            [sys.executable, "-m", "yt_dlp", "--ignore-config", "--no-plugin-dirs", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10,
            env=get_yt_dlp_env(),
        )
        _cached_yt_dlp_version = result.stdout.strip()
        return _cached_yt_dlp_version
    except Exception:
        return "unknown"


def get_ffmpeg_version(refresh: bool = False) -> str:
    global _cached_ffmpeg_version
    if _cached_ffmpeg_version and not refresh:
        return _cached_ffmpeg_version
    try:
        ffmpeg_bin = get_ffmpeg_binary("ffmpeg") or "ffmpeg"
        result = subprocess.run(
            [ffmpeg_bin, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10,
            env=get_yt_dlp_env(),
        )
        first_line = result.stdout.split("\n")[0] if result.stdout else "Unknown"
        _cached_ffmpeg_version = first_line.strip()
        return _cached_ffmpeg_version
    except Exception:
        return "unknown"


def format_ffmpeg_version(raw: str) -> str:
    """Format technical FFmpeg version strings into a friendly human-readable format."""
    if not raw or raw == "unknown":
        return "Unknown"
    s = re.sub(r"^ffmpeg\s+version\s+", "", raw, flags=re.IGNORECASE)
    s = re.split(r"\s+Copyright", s, flags=re.IGNORECASE)[0].strip()
    if not s:
        return raw

    # Git snapshot builds, e.g. N-127989-gc6f044e604-20261023 or N-127989-20261023
    m = re.match(r"^N-\d+(?:-g([0-9a-f]+))?-(\d{4})(\d{2})(\d{2})$", s, re.IGNORECASE)
    if m:
        h = m.group(1)[:7] if m.group(1) else ""
        d = f"{m.group(2)}-{m.group(3)}-{m.group(4)}"
        return f"Master · {d} ({h})" if h else f"Master · {d}"

    # Autobuild or git date patterns, e.g. autobuild-2026-10-23
    m2 = re.match(r"^(?:autobuild|git)-(\d{4})-(\d{2})-(\d{2})(?:-([0-9a-f]+))?", s, re.IGNORECASE)
    if m2:
        d = f"{m2.group(1)}-{m2.group(2)}-{m2.group(3)}"
        h = m2.group(4)[:7] if m2.group(4) else ""
        return f"Master · {d} ({h})" if h else f"Master · {d}"

    # Standard / distro release versions, e.g. 7.1, 7.1-ytdlp, n7.1
    if re.match(r"^\d+\.\d+", s):
        return f"v{s}"
    if re.match(r"^n\d+\.\d+", s, re.IGNORECASE):
        return f"v{s[1:]}"

    return s


def get_ffmpeg_friendly_version(refresh: bool = False) -> str:
    raw = get_ffmpeg_version(refresh=refresh)
    return format_ffmpeg_version(raw)


def are_runtime_updates_allowed() -> bool:
    """
    Returns True if in-app engine updates are permitted.
    Can be explicitly disabled via DISABLE_RUNTIME_UPDATES=1 or gated via REQUIRE_OPT_IN_UPDATES=1 (F-09).
    """
    if os.environ.get("DISABLE_RUNTIME_UPDATES", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("REQUIRE_OPT_IN_UPDATES", "").lower() in ("1", "true", "yes"):
        return os.environ.get("ENABLE_COMPONENT_UPDATES", "").lower() in ("1", "true", "yes")
    return True


def update_yt_dlp():
    log_output = []
    success = False
    if not are_runtime_updates_allowed():
        msg = "Runtime updates are disabled or not explicitly enabled by administrator configuration."
        append_update_log(f"[yt-dlp] {msg}")
        return {
            "success": False,
            "new_version": get_yt_dlp_version(),
            "log": msg,
        }

    if not _update_lock.acquire(blocking=False):
        msg = "Another component update is already in progress."
        append_update_log(f"[yt-dlp] {msg}")
        return {
            "success": False,
            "new_version": get_yt_dlp_version(),
            "log": msg,
        }

    try:
        pkg_dir = get_yt_dlp_pkg_dir()
        os.makedirs(pkg_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(pkg_dir, 0o700)
        except OSError:
            pass

        try:
            msg = "Starting isolated yt-dlp package update via pip..."
            log_output.append(msg)
            append_update_log(f"[yt-dlp] {msg}")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-cache-dir",
                    "--only-binary",
                    ":all:",
                    "--upgrade",
                    "--target",
                    pkg_dir,
                    "--no-deps",
                    "yt-dlp",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=get_yt_dlp_env(),
            )

            for line in process.stdout:
                line_str = line.strip()
                if line_str:
                    log_output.append(line_str)
                    append_update_log(f"[yt-dlp] {line_str}")

            process.wait(timeout=60)
            if process.returncode == 0:
                new_version = get_yt_dlp_version(refresh=True)
                msg = f"yt-dlp updated successfully! Current version: {new_version}"
                log_output.append(msg)
                append_update_log(f"[yt-dlp] {msg}")
                success = True
            else:
                msg = f"pip install exited with code {process.returncode}"
                log_output.append(msg)
                append_update_log(f"[yt-dlp] {msg}")
        except Exception as e:
            msg = f"Error during update process: {str(e)}"
            log_output.append(msg)
            append_update_log(f"[yt-dlp] {msg}")

        return {
            "success": success,
            "new_version": get_yt_dlp_version(refresh=True),
            "log": "\n".join(log_output),
        }
    finally:
        _update_lock.release()


def _fetch_remote_ffmpeg_sha256(asset_name: str) -> Optional[str]:
    """Downloads checksums.sha256 from yt-dlp/FFmpeg-Builds and returns the expected SHA-256 hex digest."""
    checksum_url = f"{YTDLP_FFMPEG_BASE_URL}/checksums.sha256"
    req = urllib.request.Request(
        checksum_url,
        headers={"User-Agent": "Corgio-Updater/1.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        text = response.read().decode("utf-8", errors="replace")
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                digest = parts[0].strip().lower()
                fname = parts[-1].strip().lstrip("*")
                if fname == asset_name and len(digest) == 64:
                    return digest
    return None


def update_ffmpeg():
    """
    Updates ffmpeg and ffprobe in-place without requiring root privileges on Linux (x86_64 / arm64)
    by downloading the official SHA-256 verified yt-dlp/FFmpeg-Builds static release into
    /config/.ffmpeg-bin (0700). Falls back to OS package managers if running as root on other platforms.
    """
    log_output = []
    success = False

    if not are_runtime_updates_allowed():
        msg = "Runtime updates are disabled or not explicitly enabled by administrator configuration."
        append_update_log(f"[ffmpeg] {msg}")
        return {
            "success": False,
            "version": get_ffmpeg_version(),
            "log": msg,
        }

    if not _update_lock.acquire(blocking=False):
        msg = "Another component update is already in progress."
        append_update_log(f"[ffmpeg] {msg}")
        return {
            "success": False,
            "version": get_ffmpeg_version(),
            "log": msg,
        }

    try:
        asset_name = _get_ytdlp_ffmpeg_asset_name()
        if asset_name:
            bin_dir = get_ffmpeg_bin_dir()
            os.makedirs(bin_dir, mode=0o700, exist_ok=True)
            try:
                os.chmod(bin_dir, 0o700)
            except OSError:
                pass

            stamp_file = os.path.join(bin_dir, ".sha256")
            installed_sha = ""
            if os.path.isfile(stamp_file):
                try:
                    with open(stamp_file, "r", encoding="utf-8") as sf:
                        installed_sha = sf.read().strip().lower()
                except OSError:
                    pass

            try:
                msg = f"Checking official yt-dlp/FFmpeg-Builds checksum for {asset_name}..."
                log_output.append(msg)
                append_update_log(f"[ffmpeg] {msg}")
                expected_sha = _fetch_remote_ffmpeg_sha256(asset_name)
                if not expected_sha:
                    raise RuntimeError("Could not retrieve official SHA-256 checksum for FFmpeg build")

                append_update_log(f"[ffmpeg] Target release checksum: {expected_sha[:16]}...")

                if (
                    installed_sha
                    and hmac.compare_digest(installed_sha, expected_sha)
                    and os.path.isfile(os.path.join(bin_dir, "ffmpeg"))
                    and os.path.isfile(os.path.join(bin_dir, "ffprobe"))
                ):
                    ver = get_ffmpeg_friendly_version(refresh=True)
                    raw_ver = get_ffmpeg_version()
                    msg = f"FFmpeg is already at the latest verified build ({ver})."
                    log_output.append(msg)
                    append_update_log(f"[ffmpeg] {msg}")
                    return {
                        "success": True,
                        "version": ver,
                        "raw_version": raw_ver,
                        "log": "\n".join(log_output),
                    }

                archive_url = f"{YTDLP_FFMPEG_BASE_URL}/{asset_name}"
                msg = f"Downloading official build from {archive_url}..."
                log_output.append(msg)
                append_update_log(f"[ffmpeg] {msg}")

                staging_dir = tempfile.mkdtemp(prefix=".staging_", dir=bin_dir)
                try:
                    archive_path = os.path.join(staging_dir, asset_name)
                    hasher = hashlib.sha256()

                    req = urllib.request.Request(
                        archive_url,
                        headers={"User-Agent": "Corgio-Updater/1.0"},
                    )
                    with urllib.request.urlopen(req, timeout=120) as resp, open(archive_path, "wb") as out_f:
                        content_len_header = resp.headers.get("Content-Length")
                        total_bytes = int(content_len_header) if content_len_header and content_len_header.isdigit() else 0
                        downloaded_bytes = 0
                        last_reported_bytes = 0

                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            hasher.update(chunk)
                            out_f.write(chunk)
                            downloaded_bytes += len(chunk)

                            # Log download progress every ~5 MB
                            if total_bytes > 0:
                                if downloaded_bytes - last_reported_bytes >= 5 * 1024 * 1024:
                                    pct = int((downloaded_bytes / total_bytes) * 100)
                                    mb_done = downloaded_bytes / (1024 * 1024)
                                    mb_tot = total_bytes / (1024 * 1024)
                                    append_update_log(f"[ffmpeg] Downloading: {mb_done:.1f} MB / {mb_tot:.1f} MB ({pct}%)")
                                    last_reported_bytes = downloaded_bytes
                            else:
                                if downloaded_bytes - last_reported_bytes >= 10 * 1024 * 1024:
                                    mb_done = downloaded_bytes / (1024 * 1024)
                                    append_update_log(f"[ffmpeg] Downloaded {mb_done:.1f} MB...")
                                    last_reported_bytes = downloaded_bytes

                    computed_sha = hasher.hexdigest().lower()
                    append_update_log(f"[ffmpeg] Download complete ({downloaded_bytes / (1024 * 1024):.1f} MB). Verifying SHA-256...")

                    if not hmac.compare_digest(computed_sha, expected_sha):
                        raise RuntimeError(
                            f"SHA-256 checksum mismatch! Expected {expected_sha}, got {computed_sha}"
                        )

                    msg = "SHA-256 checksum verified. Extracting ffmpeg and ffprobe binaries..."
                    log_output.append(msg)
                    append_update_log(f"[ffmpeg] {msg}")

                    extracted_bins = {}
                    with tarfile.open(archive_path, mode="r:xz") as tf:
                        for member in tf.getmembers():
                            if not member.isfile():
                                continue
                            norm_name = member.name.replace("\\", "/").rstrip("/")
                            for target_bin in ("ffmpeg", "ffprobe"):
                                if norm_name.endswith(f"/bin/{target_bin}"):
                                    src_f = tf.extractfile(member)
                                    if src_f is None:
                                        continue
                                    stage_bin_path = os.path.join(staging_dir, target_bin)
                                    with open(stage_bin_path, "wb") as dst_f:
                                        shutil.copyfileobj(src_f, dst_f)
                                    os.chmod(stage_bin_path, 0o755)
                                    extracted_bins[target_bin] = stage_bin_path

                    if "ffmpeg" not in extracted_bins or "ffprobe" not in extracted_bins:
                        raise RuntimeError("Archive did not contain expected bin/ffmpeg and bin/ffprobe binaries")

                    # Smoke-check extracted binaries before replacing working binaries (F4)
                    append_update_log("[ffmpeg] Running pre-flight smoke tests on extracted binaries...")
                    for target_bin, stage_bin_path in extracted_bins.items():
                        smoke = subprocess.run(
                            [stage_bin_path, "-version"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=10,
                            env=get_yt_dlp_env(),
                        )
                        if smoke.returncode != 0:
                            raise RuntimeError(f"Staged {target_bin} binary failed execution smoke check")

                    for target_bin, stage_bin_path in extracted_bins.items():
                        final_bin_path = os.path.join(bin_dir, target_bin)
                        os.replace(stage_bin_path, final_bin_path)

                    with open(stamp_file, "w", encoding="utf-8") as sf:
                        sf.write(expected_sha)
                    os.chmod(stamp_file, 0o600)

                    new_ver = get_ffmpeg_friendly_version(refresh=True)
                    raw_ver = get_ffmpeg_version()
                    msg = f"FFmpeg updated successfully to {new_ver} ({raw_ver})"
                    log_output.append(msg)
                    append_update_log(f"[ffmpeg] {msg}")
                    success = True
                finally:
                    shutil.rmtree(staging_dir, ignore_errors=True)
            except Exception as e:
                msg = f"FFmpeg static overlay update failed: {str(e)}"
                log_output.append(msg)
                append_update_log(f"[ffmpeg] {msg}")
                success = False

            return {
                "success": success,
                "version": get_ffmpeg_friendly_version(refresh=True),
                "raw_version": get_ffmpeg_version(),
                "log": "\n".join(log_output),
            }

        # Non-Linux or unsupported arch fallback
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            msg = "FFmpeg static overlay builds target Linux (x86_64 / arm64). Using host FFmpeg installation."
            log_output.append(msg)
            append_update_log(f"[ffmpeg] {msg}")
            return {
                "success": True,
                "version": get_ffmpeg_friendly_version(refresh=True),
                "raw_version": get_ffmpeg_version(),
                "log": "\n".join(log_output),
            }

        apt_path = shutil.which("apt-get")
        apk_path = shutil.which("apk")

        try:
            msg = "Checking for ffmpeg updates via system package manager..."
            log_output.append(msg)
            append_update_log(f"[ffmpeg] {msg}")
            if apt_path:
                subprocess.run(["apt-get", "update"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                process = subprocess.Popen(
                    ["apt-get", "install", "--only-upgrade", "-y", "--no-install-recommends", "ffmpeg"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in process.stdout:
                    l = line.strip()
                    if l:
                        log_output.append(l)
                        append_update_log(f"[ffmpeg] {l}")
                process.wait(timeout=120)
                success = process.returncode == 0
                subprocess.run(["apt-get", "clean"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                shutil.rmtree("/var/lib/apt/lists", ignore_errors=True)
            elif apk_path:
                process = subprocess.Popen(
                    ["apk", "add", "--no-cache", "--upgrade", "ffmpeg"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in process.stdout:
                    l = line.strip()
                    if l:
                        log_output.append(l)
                        append_update_log(f"[ffmpeg] {l}")
                process.wait(timeout=120)
                success = process.returncode == 0
            else:
                msg = "Using host FFmpeg installation."
                log_output.append(msg)
                append_update_log(f"[ffmpeg] {msg}")
                success = True
        except Exception:
            msg = "Error during ffmpeg update."
            log_output.append(msg)
            append_update_log(f"[ffmpeg] {msg}")
            success = False

        return {
            "success": success,
            "version": get_ffmpeg_friendly_version(refresh=True),
            "raw_version": get_ffmpeg_version(),
            "log": "\n".join(log_output),
        }
    finally:
        _update_lock.release()


def run_full_engine_update() -> dict:
    """Coordinates updating yt-dlp and FFmpeg sequentially with unified live logging and state."""
    global _update_status
    with _update_logs_lock:
        _update_status["in_progress"] = True
        _update_status["success"] = None
        _update_status["current_step"] = "yt-dlp"
        _update_status["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _update_status["finished_at"] = None
    clear_update_logs()

    append_update_log("[system] Starting core engine update process (yt-dlp & FFmpeg)...")

    yt_res = {"success": False, "new_version": "unknown", "log": ""}
    ff_res = {"success": False, "version": "unknown", "log": ""}
    try:
        append_update_log("[yt-dlp] Checking and updating yt-dlp...")
        yt_res = update_yt_dlp()

        with _update_logs_lock:
            _update_status["current_step"] = "ffmpeg"

        append_update_log("[ffmpeg] Checking and updating FFmpeg...")
        ff_res = update_ffmpeg()

        overall_success = bool(yt_res.get("success", False) and ff_res.get("success", False))
        status_text = "successfully" if overall_success else "with warnings or errors"
        append_update_log(f"[system] Engine update completed {status_text}.")
        append_update_log(f"[system] yt-dlp: {yt_res.get('new_version', 'unknown')} | FFmpeg: {ff_res.get('version', 'unknown')}")

        with _update_logs_lock:
            _update_status["in_progress"] = False
            _update_status["success"] = overall_success
            _update_status["current_step"] = "completed"
            _update_status["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            from . import database
            database.add_activity_log(
                "SYSTEM",
                f"Engine update {status_text}. yt-dlp ({yt_res.get('new_version')}): {'Success' if yt_res.get('success') else 'Failed'} | FFmpeg ({ff_res.get('version')}): {'Success' if ff_res.get('success') else 'Failed'}",
            )
        except Exception:
            pass

        return {
            "success": overall_success,
            "yt_dlp": yt_res,
            "ffmpeg": ff_res,
        }
    except Exception as e:
        err_msg = f"Fatal error during engine update: {str(e)}"
        append_update_log(f"[system] {err_msg}")
        with _update_logs_lock:
            _update_status["in_progress"] = False
            _update_status["success"] = False
            _update_status["current_step"] = "failed"
            _update_status["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "success": False,
            "error": err_msg,
        }


def parse_version(ver_str):
    try:
        parts = []
        for part in ver_str.strip().split("."):
            digits = "".join(c for c in part if c.isdigit())
            parts.append(int(digits) if digits else 0)
        return parts
    except Exception:
        return [0]


def check_yt_dlp_update():
    current_version = get_yt_dlp_version()
    latest_version = current_version
    update_available = False

    try:
        req = urllib.request.Request(
            "https://pypi.org/pypi/yt-dlp/json",
            headers={"User-Agent": "python-urllib/3"},
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            latest_version = data["info"]["version"]
            update_available = parse_version(latest_version) > parse_version(current_version)
    except Exception:
        pass

    return {
        "current": current_version,
        "latest": latest_version,
        "update_available": update_available,
    }


def check_ffmpeg_update():
    current_version = get_ffmpeg_version()
    friendly_current = get_ffmpeg_friendly_version()
    latest_version = friendly_current
    update_available = False

    asset_name = _get_ytdlp_ffmpeg_asset_name()
    if asset_name:
        bin_dir = get_ffmpeg_bin_dir()
        stamp_file = os.path.join(bin_dir, ".sha256")
        installed_sha = ""
        if os.path.isfile(stamp_file):
            try:
                with open(stamp_file, "r", encoding="utf-8") as sf:
                    installed_sha = sf.read().strip().lower()
            except OSError:
                pass

        try:
            expected_sha = _fetch_remote_ffmpeg_sha256(asset_name)
            if expected_sha:
                if (
                    not installed_sha
                    or not hmac.compare_digest(installed_sha, expected_sha)
                    or not os.path.isfile(os.path.join(bin_dir, "ffmpeg"))
                ):
                    update_available = True
                    latest_version = f"yt-dlp/FFmpeg ({expected_sha[:8]})"
        except Exception:
            pass

        return {
            "current": friendly_current,
            "raw_current": current_version,
            "latest": latest_version,
            "update_available": update_available,
        }

    return {
        "current": friendly_current,
        "raw_current": current_version,
        "latest": latest_version,
        "update_available": False,
    }
