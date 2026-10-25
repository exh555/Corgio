# Corgio Development & Agent Operating Instructions

> **Project**: Corgio (`exh555/Corgio`)  
> **Role**: Senior Full-Stack Media Systems Engineer & Security Architect  
> **Core Objective**: Maintain, enhance, and debug Corgio — a privacy-first, modern, containerized media downstreaming and archival system.

---

## 1. System Architecture & Tech Stack

### Backend
- **Framework**: FastAPI (Python 3.9+ / 3.14 compatible), Uvicorn.
- **Database**: SQLite3 in WAL mode (`journal_mode = WAL`, `synchronous = NORMAL`, `secure_delete = ON`).
  - Thread-safe via module-level re-entrant lock `db_lock`.
  - Single-admin PBKDF2-HMAC-SHA256 authentication (600,000 iterations).
  - Explicit column whitelist `ALLOWED_DOWNLOAD_COLUMNS` for updates.
  - Schema migrations run automatically in `init_db()` via `ALTER TABLE` checks.
- **Media Downloader & Pipeline**:
  - `yt-dlp` invoked via isolated subprocesses with sanitized environment (`updater.get_yt_dlp_env()`).
  - `ffmpeg` & `ffprobe` for stream remuxing, thumbnail generation, and post-download metadata probe.
  - Overlay support for persistent updates without rebuilding images: `/config/.ffmpeg-bin` (PATH) and `/config/.yt-dlp-pkg` (PYTHONPATH).
- **JavaScript Challenge & Engine Support**:
  - EJS (Embedded JS) at `/usr/local/bin/ejs`, Deno, and QuickJS support via `--js-runtimes ejs:/usr/local/bin/ejs`.
  - Used for YouTube SABR / JS challenge decoding and signature deciphering.
- **Authentication & Cookies**:
  - Dynamic `cookies.txt` detection in `/config/cookies.txt`.
  - Custom `--extractor-args` up to 1024 chars for PO tokens and client configuration.
  - **Important**: Do NOT hardcode `player_client=android` because Android client requires PO tokens and causes HTTP 403 blocks unauthenticated. Allow `yt-dlp` to negotiate default and `web_embedded` clients.

### Frontend
- **Design System**: Pembroke theme system with light/dark modes (`theme-init.js`, `style.css`).
- **Core UI**: Vanilla JavaScript (`app.js`), zero heavy framework dependencies.
- **Real-Time Telemetry**: Server-Sent Events (SSE) via `/api/stream-logs/{id}` and periodic polling.
- **Modals**:
  - Media Stream & Technical Metadata Modal (`#metadata-modal`): displays true codecs, framerate, overall bitrate, resolution, uploader info, and full persistent console log.
  - Secure Purge Confirmation Modal (`#delete-modal`).
  - Live Console Log Modal (`#log-modal`).
  - System Drawer (`#system-drawer`): Engine versions, storage telemetry, cookie management.

---

## 2. Non-Negotiable Operational Rules

### Rule 1: Zero-Trace Redaction & Privacy
> [!IMPORTANT]
> **NEVER leak or expose user media metadata in public channels.**
- **Strictly Prohibited**: Do NOT include raw video IDs, direct stream/video URLs, exact video titles, channel URLs, or uploader usernames in:
  - GitHub issue titles or bodies
  - GitHub issue comments
  - Git commit messages
  - Release notes or pull requests
- **Required Redaction Pattern**: Always redact sensitive media data with generic placeholders:
  - URL $\to$ `<url>`
  - Video ID $\to$ `<video_id>`
  - Video Title $\to$ `<media_title>`
  - Domain $\to$ `<domain>` (or generic platform name like `YouTube`, `CNN`)
  - Uploader $\to$ `<uploader>`

### Rule 2: Issue-Driven Development (IDD) Lifecycle
All bugs, features, and enhancements MUST strictly adhere to this end-to-end lifecycle:

1. **Check Existing Issues**:
   ```bash
   gh issue list --state all --limit 10
   ```
2. **Create GitHub Issue**:
   - Write a clear, professional issue title and body.
   - Apply Zero-Trace Redaction to the issue content.
   - Add appropriate label (`bug`, `enhancement`, etc.).
   ```bash
   gh issue create --title "[Feature/Bug]: <Descriptive Redacted Title>" --body "### Problem Statement..." --label "enhancement"
   ```
3. **Implement Code Changes**:
   - Make clean, modular modifications to backend and frontend files.
   - Maintain documentation integrity and preserve existing comments.
4. **Local Verification & Validation**:
   - Validate Python syntax:
     ```bash
     python3 -m py_compile backend/*.py tests/*.py
     ```
   - Run automated security & regression test suite:
     ```bash
     python3 tests/test_corgio_security.py
     ```
   - Validate JavaScript syntax and types:
     ```bash
     /opt/homebrew/bin/deno check frontend/app.js
     ```
5. **Post Technical Resolution Details**:
   - Post an in-depth resolution comment directly to the GitHub issue explaining the root cause and implementation details:
     ```bash
     gh issue comment <ISSUE_ID> --body "### Technical Resolution & Implementation Details..."
     ```
6. **Commit with Issue Reference**:
   - Include `(fixes #<ISSUE_ID>)` in the commit message:
     ```bash
     git commit -m "feat: concise summary of change (fixes #<ISSUE_ID>)"
     ```
7. **Bump Semantic Version**:
   - Synchronize version string across:
     - `backend/main.py`: `APP_VERSION = "1.x.x"`
     - `frontend/index.html`: query params `?v=1.x.x` and `#sys-app-version`
8. **Tag Release**:
   ```bash
   git tag -a v1.x.x -m "Release v1.x.x"
   ```
9. **Push to GitHub**:
   ```bash
   git push origin main --tags
   ```
10. **Verify Issue Closure**:
    - Confirm the issue was closed automatically by GitHub via `(fixes #N)`. If still open, close it manually:
      ```bash
      gh issue close <ISSUE_ID>
      ```

---

## 3. Key Technical Conventions & Guardrails

### Database Migrations
When adding a new column to the `downloads` table:
1. Add the column name to `ALLOWED_DOWNLOAD_COLUMNS` in `backend/database.py`.
2. Add the column definition to `CREATE TABLE IF NOT EXISTS downloads` in `init_db()`.
3. Add `ALTER TABLE downloads ADD COLUMN <col> <type>` to the migration loop in `init_db()`.

### Metadata Extraction & ffprobe
- Manifests from `yt-dlp --dump-json` often return `None` for codecs, fps, and bitrate on non-YouTube or HLS streams.
- **Rule**: Upon download completion, always run `get_video_metadata(final_filepath)` using `ffprobe` to enrich the database record with the true container and stream parameters.
- **Self-Healing**: When `GET /api/downloads/{id}` or File Info is requested, if an existing file on disk lacks codecs or bitrate, dynamically probe the file with `ffprobe` and persist the healed data into SQLite.

### Console Log Retention & Secure Purge
- **Routine Download Completion**: When `persist_download_logs` is enabled (default), persist execution logs in `download_log` in SQLite so users can inspect them in File Info. If disabled, do not persist console logs to SQLite.
- **Explicit Item Purge**: When the user explicitly purges or deletes an item (`DELETE /api/downloads/{id}`), all logs (in-memory `logs_queue`, `download_log` in SQLite, and `activity_logs`) MUST be permanently and securely wiped (`PRAGMA secure_delete = ON` overwrites freed database pages with binary zeros, followed by WAL checkpoint truncation).
- Ensure `/api/logs/{download_id}` falls back to the database record if the in-memory queue has been cleared.

### Password Security & Bootstrap Credentials
- **Password Length**: Passwords must be at least 8 characters long, enforced across backend models, database update methods, and frontend forms.
- **Bootstrap Credentials**: On fresh installations, a cryptographically secure random password is saved to `/config/bootstrap_credentials.txt` (mode `0600`). It is removed automatically once the admin sets a permanent custom password.
- **Password Reset Sentinel**: `RESET_PASSWORD=true` is a one-shot operation guarded by `/config/.password_reset_done`.

### Terminal & Sandbox Rules
- Commands run in standard sandbox mode by default.
- Only use `BypassSandbox: true` when a command genuinely requires network access (e.g. `gh issue`, `git push`).
