#!/bin/bash
set -e

# Default UID/GID to 99 (Unraid default 'nobody' user) and 100 ('users' group)
PUID=${PUID:-99}
PGID=${PGID:-100}
UMASK=${UMASK:-002}

if [ "$PUID" = "0" ] || [ "$PGID" = "0" ]; then
    if [ "${ALLOW_ROOT:-false}" != "true" ]; then
        echo "ERROR: Running the application as root (PUID=0 or PGID=0) is blocked by default for security."
        echo "Set PUID/PGID to a non-root user (e.g. 99/100 or 1000/1000), or set ALLOW_ROOT=true to override."
        exit 1
    fi
fi

echo "Configuring environment..."
echo "User ID (PUID): $PUID"
echo "Group ID (PGID): $PGID"
echo "File Umask: $UMASK"

# Create group if it doesn't exist (-o allows reusing existing GID such as 100 'users')
if ! getent group appgroup >/dev/null; then
    groupadd -o -g "$PGID" appgroup
fi

# Create user if it doesn't exist (-o allows reusing existing UID)
if ! getent passwd appuser >/dev/null; then
    useradd -o -u "$PUID" -g "$PGID" -M -d /config -s /bin/bash appuser
fi

# Ensure directories exist
mkdir -p /config /config/.yt-dlp-pkg /config/.ffmpeg-bin /downloads /downloads/.thumbnails /downloads/.work

# Set restrictive permissions on /config (holds SQLite database and isolated yt-dlp/ffmpeg updates)
chown -R "$PUID:$PGID" /config /downloads/.thumbnails /downloads/.work
chmod 700 /config /config/.yt-dlp-pkg /config/.ffmpeg-bin
chown "$PUID:$PGID" /downloads

# Ensure /opt/venv remains owned by root:root (read-only to appuser so runtime code cannot be overwritten)
if [ -d "/opt/venv" ]; then
    chown -R root:root /opt/venv
    chmod -R a+rX,go-w /opt/venv
fi

# Apply configured file creation mask (defaults to 002 for Unraid/NAS share compatibility)
umask "$UMASK"

# Export environments
export HOME=/config
export DB_PATH=/config/downloads.db
export DOWNLOAD_DIR=/downloads
export YT_DLP_PKG_DIR=/config/.yt-dlp-pkg
export FFMPEG_BIN_DIR=/config/.ffmpeg-bin

echo "Starting Corgio..."
exec gosu "$PUID:$PGID" uvicorn backend.main:app --host 0.0.0.0 --port 8080 --no-access-log
