import os
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
from typing import Optional

_cached_yt_dlp_version = None
_cached_ffmpeg_version = None
_update_lock = threading.Lock()

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


def update_yt_dlp():
    log_output = []
    success = False
    if os.environ.get("DISABLE_RUNTIME_UPDATES", "").lower() in ("1", "true", "yes"):
        return {
            "success": False,
            "new_version": get_yt_dlp_version(),
            "log": "Runtime updates are disabled by administrator configuration.",
        }

    if not _update_lock.acquire(blocking=False):
        return {
            "success": False,
            "new_version": get_yt_dlp_version(),
            "log": "Another component update is already in progress.",
        }

    try:
        pkg_dir = get_yt_dlp_pkg_dir()
        os.makedirs(pkg_dir, mode=0o700, exist_ok=True)

        try:
            log_output.append("Starting isolated yt-dlp package update...")
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
                log_output.append(line.strip())

            process.wait(timeout=60)
            if process.returncode == 0:
                new_version = get_yt_dlp_version(refresh=True)
                log_output.append(f"yt-dlp updated successfully! Current version: {new_version}")
                success = True
            else:
                log_output.append(f"pip install exited with code {process.returncode}")
        except Exception as e:
            log_output.append(f"Error during update process: {str(e)}")

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

    if os.environ.get("DISABLE_RUNTIME_UPDATES", "").lower() in ("1", "true", "yes"):
        return {
            "success": False,
            "version": get_ffmpeg_version(),
            "log": "Runtime updates are disabled by administrator configuration.",
        }

    if not _update_lock.acquire(blocking=False):
        return {
            "success": False,
            "version": get_ffmpeg_version(),
            "log": "Another component update is already in progress.",
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
                log_output.append(f"Checking official yt-dlp/FFmpeg-Builds checksum for {asset_name}...")
                expected_sha = _fetch_remote_ffmpeg_sha256(asset_name)
                if not expected_sha:
                    raise RuntimeError("Could not retrieve official SHA-256 checksum for FFmpeg build")

                if (
                    installed_sha
                    and hmac.compare_digest(installed_sha, expected_sha)
                    and os.path.isfile(os.path.join(bin_dir, "ffmpeg"))
                    and os.path.isfile(os.path.join(bin_dir, "ffprobe"))
                ):
                    ver = get_ffmpeg_version(refresh=True)
                    log_output.append(f"FFmpeg is already at the latest verified build ({ver}).")
                    return {
                        "success": True,
                        "version": ver,
                        "log": "\n".join(log_output),
                    }

                archive_url = f"{YTDLP_FFMPEG_BASE_URL}/{asset_name}"
                log_output.append(f"Downloading {archive_url}...")

                staging_dir = tempfile.mkdtemp(prefix=".staging_", dir=bin_dir)
                try:
                    archive_path = os.path.join(staging_dir, asset_name)
                    hasher = hashlib.sha256()

                    req = urllib.request.Request(
                        archive_url,
                        headers={"User-Agent": "Corgio-Updater/1.0"},
                    )
                    with urllib.request.urlopen(req, timeout=120) as resp, open(archive_path, "wb") as out_f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            hasher.update(chunk)
                            out_f.write(chunk)

                    computed_sha = hasher.hexdigest().lower()
                    if not hmac.compare_digest(computed_sha, expected_sha):
                        raise RuntimeError(
                            f"SHA-256 checksum mismatch! Expected {expected_sha}, got {computed_sha}"
                        )

                    log_output.append("SHA-256 checksum verified. Extracting ffmpeg and ffprobe binaries...")

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

                    new_ver = get_ffmpeg_version(refresh=True)
                    log_output.append(f"FFmpeg updated successfully to {new_ver}")
                    success = True
                finally:
                    shutil.rmtree(staging_dir, ignore_errors=True)
            except Exception as e:
                log_output.append(f"FFmpeg static overlay update failed: {str(e)}")
                success = False

            return {
                "success": success,
                "version": get_ffmpeg_version(refresh=True),
                "log": "\n".join(log_output),
            }

        # Non-Linux or unsupported arch fallback
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            log_output.append(
                "FFmpeg static overlay builds target Linux (x86_64 / arm64). Using host FFmpeg installation."
            )
            return {
                "success": True,
                "version": get_ffmpeg_version(refresh=True),
                "log": "\n".join(log_output),
            }

        apt_path = shutil.which("apt-get")
        apk_path = shutil.which("apk")

        try:
            log_output.append("Checking for ffmpeg updates via system package manager...")
            if apt_path:
                subprocess.run(["apt-get", "update"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                process = subprocess.Popen(
                    ["apt-get", "install", "--only-upgrade", "-y", "--no-install-recommends", "ffmpeg"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in process.stdout:
                    log_output.append(line.strip())
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
                    log_output.append(line.strip())
                process.wait(timeout=120)
                success = process.returncode == 0
            else:
                log_output.append("Using host FFmpeg installation.")
                success = True
        except Exception:
            log_output.append("Error during ffmpeg update.")
            success = False

        return {
            "success": success,
            "version": get_ffmpeg_version(refresh=True),
            "log": "\n".join(log_output),
        }
    finally:
        _update_lock.release()


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
    latest_version = current_version
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
            "current": current_version,
            "latest": latest_version,
            "update_available": update_available,
        }

    return {
        "current": current_version,
        "latest": latest_version,
        "update_available": False,
    }
