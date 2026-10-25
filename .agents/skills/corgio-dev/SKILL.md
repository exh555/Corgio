---
name: corgio-dev
description: >-
  Standard operating procedures, Issue-Driven Development (IDD) lifecycle, Zero-Trace privacy
  redaction rules, testing/validation steps, and release workflows for the Corgio media project.
---

# Corgio Development & Release Runbook

This skill guides the agent through the development, verification, issue management, and release process for Corgio (`exh555/Corgio`).

---

## 1. Zero-Trace Privacy Redaction Checklist

Before publishing ANY content to GitHub (issue titles, bodies, comments, PRs, or commit messages):
- [ ] Are all raw video URLs redacted to `<url>`?
- [ ] Are all video IDs (e.g. YouTube IDs, CNN media keys) redacted to `<video_id>`?
- [ ] Are exact video titles replaced with `<media_title>`?
- [ ] Are channel or uploader names replaced with `<uploader>`?
- [ ] Are any cookies, tokens, or auth keys stripped?

---

## 2. Issue-Driven Development (IDD) Workflow

Whenever an enhancement, bug fix, or feature is requested:

### Phase A: Issue Discovery & Creation
1. Check existing open/closed issues to find context:
   ```bash
   PATH=$PATH:/opt/homebrew/bin gh issue list --limit 10
   ```
2. Create an issue using `gh issue create`. Ensure the body and title are fully redacted:
   ```bash
   PATH=$PATH:/opt/homebrew/bin gh issue create \
     --title "[Feature/Bug]: <Redacted descriptive title>" \
     --body "### Problem Statement\n...\n\n### Proposed Solution\n..." \
     --label "enhancement"
   ```
   Note the newly created issue number `#N`.

### Phase B: Implementation & Local Verification
1. Edit the relevant backend and frontend files.
2. Maintain backward compatibility and documentation comments.
3. Validate backend Python syntax:
   ```bash
   python3 -m py_compile backend/*.py
   ```
4. Validate frontend JavaScript syntax and types:
   ```bash
   /opt/homebrew/bin/deno check frontend/app.js
   ```
5. Run custom Python verification scripts if altering database schemas or downloader pipelines.

### Phase C: Issue Resolution & Release
1. Post comprehensive technical resolution notes to the GitHub issue **before pushing**:
   ```bash
   PATH=$PATH:/opt/homebrew/bin gh issue comment <N> --body "### Technical Resolution & Implementation Details\n..."
   ```
2. Stage and commit changes with the `(fixes #N)` keyword:
   ```bash
   git add <modified_files>
   git commit -m "feat: concise summary of changes (fixes #N)"
   ```
3. Bump the semantic version in:
   - `backend/main.py`: `APP_VERSION = "1.x.x"`
   - `frontend/index.html`: `?v=1.x.x` and `#sys-app-version`
4. Create an annotated release tag:
   ```bash
   git tag -a v1.x.x -m "Release v1.x.x"
   ```
5. Push `main` and the new tag to GitHub:
   ```bash
   git push origin main --tags
   ```
6. Check issue closure status:
   ```bash
   PATH=$PATH:/opt/homebrew/bin gh issue view <N>
   ```
7. Verify GitHub Actions build status:
   ```bash
   PATH=$PATH:/opt/homebrew/bin gh run list --limit 3
   ```

---

## 3. Database Schema Migration Runbook

When altering the SQLite database:
1. Always edit `backend/database.py`:
   - Add new column to `ALLOWED_DOWNLOAD_COLUMNS`.
   - Add new column to `CREATE TABLE IF NOT EXISTS downloads (...)`.
   - Add `ALTER TABLE downloads ADD COLUMN ...` statement in the `init_db()` migration loop.
2. Protect all write operations with `with db_lock:`.
3. If new metadata fields are probed, update `get_video_metadata` in `downloader.py` and self-healing logic in `main.py`.
