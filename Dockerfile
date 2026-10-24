FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    gosu \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create isolated virtual environment so non-root appuser can update yt-dlp cleanly
RUN python -m venv /opt/venv

WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY backend /app/backend
COPY frontend /app/frontend
COPY entrypoint.sh /app/

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

VOLUME ["/config", "/downloads"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/auth/status', timeout=3)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
