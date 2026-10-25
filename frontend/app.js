/**
 * Corgio — Traditional Flat "Command Deck" Frontend Controller
 * Supports Pembroke & GitHub palettes in Light & Dark modes.
 */

const API_BASE = '/api';

// Application State
let appState = {
    settings: {
        theme: localStorage.getItem('corgio_theme') || 'light',
        palette: localStorage.getItem('corgio_palette') || 'pembroke',
        default_format: 'mp4',
        default_speed_limit: '',
        default_subtitles: false,
        custom_args: '',
        download_subfolder: '',
        enable_access_logs: false
    },
    activeDownloads: [],
    libraryItems: [],
    activityLogs: [],
    activeFilter: 'all',
    searchQuery: '',
    sortBy: 'date_added',
    sortOrder: 'desc',
    viewMode: localStorage.getItem('corgio_view_mode') || 'table',
    queueCollapsed: localStorage.getItem('corgio_queue_collapsed') === 'true',
    batchMode: false,
    selectedIds: new Set(),
    pendingPurgeIds: [],
    activeLogStream: null,
    activeUpdateStream: null,
    hadActiveDownloads: false,
    pollTimer: null,
    auth: {
        authenticated: false,
        username: 'admin',
        mustChangePassword: false,
        lastLoginPassword: ''
    }
};

// ============================================================================
// UTILITY HELPERS
// ============================================================================

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatBytes(bytes) {
    const num = Number(bytes);
    if (!num || num <= 0) return '0 B';
    const k = 1024;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(num) / Math.log(k));
    const val = num / Math.pow(k, i);
    return `${val.toFixed(i >= 2 ? 1 : 0)} ${units[i]}`;
}

function formatDuration(seconds) {
    const sec = Number(seconds);
    if (!sec || sec <= 0) return '00:00';
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const rem = Math.floor(sec % 60);
    const pad = (n) => (n < 10 ? '0' + n : String(n));
    if (hrs > 0) {
        return `${hrs}:${pad(mins)}:${pad(rem)}`;
    }
    return `${pad(mins)}:${pad(rem)}`;
}

function formatShortDate(isoStr) {
    if (!isoStr) return '--';
    const normalized = (isoStr.endsWith('Z') || isoStr.includes('+')) ? isoStr : isoStr + 'Z';
    const d = new Date(normalized);
    if (isNaN(d.getTime())) return isoStr.slice(0, 10);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
}

function formatFullTimestamp(isoStr) {
    if (!isoStr) return '--';
    const normalized = (isoStr.endsWith('Z') || isoStr.includes('+')) ? isoStr : isoStr + 'Z';
    const d = new Date(normalized);
    if (isNaN(d.getTime())) return isoStr;
    return d.toISOString().replace('T', ' ').slice(0, 19);
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button type="button" class="btn btn-xs" aria-label="Dismiss notification">✕</button>
    `;

    const closeBtn = toast.querySelector('button');
    closeBtn.addEventListener('click', () => toast.remove());

    container.appendChild(toast);
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 3800);
}

async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('X-Requested-With', 'Corgio');
    const res = await fetch(url, {
        ...options,
        headers,
        credentials: 'same-origin'
    });
    if (res.status === 401 && !url.endsWith('/auth/login') && !url.endsWith('/auth/status')) {
        showSignInGate();
    } else if (res.status === 403 && appState.auth.authenticated && !url.endsWith('/auth/account')) {
        appState.auth.mustChangePassword = true;
        openAccountModal(true);
    }
    return res;
}

// ============================================================================
// USER ACCOUNT & AUTHENTICATION CONTROLLER
// ============================================================================

function updateAccountHeaderUI() {
    const labelEl = document.getElementById('account-btn-label');
    if (labelEl) {
        labelEl.textContent = appState.auth.username || 'admin';
    }
}

function scrubWorkspaceStateAndDom() {
    appState.auth.authenticated = false;
    appState.auth.lastLoginPassword = '';
    if (appState.pollTimer) {
        clearTimeout(appState.pollTimer);
        appState.pollTimer = null;
    }

    closePlayerModal();
    closeLogModal();
    closePurgeModal();
    document.getElementById('metadata-modal')?.classList.add('hidden');
    document.getElementById('activity-detail-modal')?.classList.add('hidden');
    document.getElementById('theme-modal')?.classList.add('hidden');
    document.getElementById('account-modal')?.classList.add('hidden');
    document.getElementById('drawer-options')?.classList.remove('open');
    document.getElementById('drawer-system')?.classList.remove('open');

    appState.activeDownloads = [];
    appState.libraryItems = [];
    appState.activityLogs = [];
    appState.selectedIds.clear();
    appState.pendingPurgeIds = [];
    appState.batchMode = false;

    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = '';

    const tableBody = document.getElementById('library-table-body');
    if (tableBody) {
        tableBody.innerHTML = '<tr><td colspan="9" class="empty-cell">Sign in required.</td></tr>';
    }
    const gridWrap = document.getElementById('library-grid-wrap');
    if (gridWrap) gridWrap.innerHTML = '';

    const activeList = document.getElementById('active-downloads-list');
    if (activeList) {
        activeList.innerHTML = `
            <div class="queue-empty">
                <p class="queue-empty-title">No active downloads</p>
            </div>
        `;
    }
    const actBody = document.getElementById('activity-logs-tbody');
    if (actBody) {
        actBody.innerHTML = '<tr><td colspan="3" class="empty-cell">No activity logs recorded.</td></tr>';
    }
    const metaBody = document.getElementById('metadata-body');
    if (metaBody) metaBody.innerHTML = '';
    const actDetailBody = document.getElementById('activity-detail-body');
    if (actDetailBody) actDetailBody.innerHTML = '';

    document.querySelector('.app-shell')?.classList.add('hidden');
}

function showSignInGate() {
    scrubWorkspaceStateAndDom();

    const authModal = document.getElementById('auth-modal');
    const userIn = document.getElementById('auth-username-input');
    const passIn = document.getElementById('auth-password-input');

    if (userIn) {
        userIn.value = '';
    }
    if (passIn) {
        passIn.value = '';
    }
    if (authModal) {
        authModal.classList.remove('hidden');
    }
    setTimeout(() => {
        userIn?.focus();
    }, 30);
}

function openAccountModal(forcePasswordChange = false) {
    const modal = document.getElementById('account-modal');
    const forcedBanner = document.getElementById('account-forced-banner');
    const closeBtn = document.getElementById('close-account-modal');
    const cancelBtn = document.getElementById('cancel-account-modal');
    const titleEl = document.getElementById('account-modal-title');
    const userIn = document.getElementById('account-username-input');
    const currPassIn = document.getElementById('account-current-password');
    const newPassIn = document.getElementById('account-new-password');
    const confPassIn = document.getElementById('account-confirm-password');

    if (!modal) return;

    if (userIn) userIn.value = appState.auth.username || 'admin';
    if (newPassIn) newPassIn.value = '';
    if (confPassIn) confPassIn.value = '';

    if (forcePasswordChange) {
        if (titleEl) titleEl.textContent = 'First Launch — Set Permanent Password';
        forcedBanner?.classList.remove('hidden');
        closeBtn?.classList.add('hidden');
        cancelBtn?.classList.add('hidden');
        if (currPassIn) {
            currPassIn.value = appState.auth.lastLoginPassword || '';
        }
    } else {
        if (titleEl) titleEl.textContent = 'Account & Password';
        forcedBanner?.classList.add('hidden');
        closeBtn?.classList.remove('hidden');
        cancelBtn?.classList.remove('hidden');
        if (currPassIn) currPassIn.value = '';
    }

    modal.classList.remove('hidden');
    setTimeout(() => {
        if (currPassIn && !currPassIn.value) {
            currPassIn.focus();
        } else {
            newPassIn?.focus();
        }
    }, 30);
}

function closeAccountModal() {
    if (appState.auth.mustChangePassword) {
        showToast('Please set your permanent password to finish first-launch setup.', 'info');
        return;
    }
    document.getElementById('account-modal')?.classList.add('hidden');
}

function loadWorkspaceData() {
    document.querySelector('.app-shell')?.classList.remove('hidden');
    loadSettings();
    fetchStatus();
    fetchLibrary();
    fetchActiveDownloads();
}

async function checkAuthStatusAndInit() {
    try {
        const res = await apiFetch(`${API_BASE}/auth/status`);
        if (!res.ok) {
            showSignInGate();
            return;
        }
        const data = await res.json();
        appState.auth.username = data.username || 'admin';
        appState.auth.mustChangePassword = Boolean(data.must_change_password);
        updateAccountHeaderUI();

        if (data.auth_required && !data.authenticated) {
            showSignInGate();
            return;
        }

        appState.auth.authenticated = true;
        document.getElementById('auth-modal')?.classList.add('hidden');
        document.querySelector('.app-shell')?.classList.remove('hidden');

        if (appState.auth.mustChangePassword) {
            openAccountModal(true);
        } else {
            loadWorkspaceData();
        }
    } catch (e) {
        console.error('Error checking auth status:', e);
    }
}

// ============================================================================
// THEME & PALETTE CONTROLLER (Amber / GitHub × Dark / Light / System)
// ============================================================================

function getEffectiveMode(themeSetting) {
    if (themeSetting === 'system') {
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    return themeSetting === 'light' ? 'light' : 'dark';
}

function normalizePalette(palette) {
    if (palette === 'github' || palette === 'slate') return 'github';
    return 'pembroke';
}

function applyAppearance(palette, themeSetting) {
    const cleanPalette = normalizePalette(palette);
    const cleanTheme = ['dark', 'light', 'system'].includes(themeSetting) ? themeSetting : 'light';
    const effectiveMode = getEffectiveMode(cleanTheme);

    appState.settings.palette = cleanPalette;
    appState.settings.theme = cleanTheme;

    localStorage.setItem('corgio_palette', cleanPalette);
    localStorage.setItem('corgio_theme', cleanTheme);

    document.documentElement.setAttribute('data-palette', cleanPalette);
    document.documentElement.setAttribute('data-mode', effectiveMode);

    const pTitle = cleanPalette === 'github' ? 'GitHub' : 'Pembroke';
    const mTitle = effectiveMode === 'dark' ? 'Dark' : 'Light';

    const themeBtnLabel = document.getElementById('theme-btn-label');
    if (themeBtnLabel) {
        themeBtnLabel.textContent = `${pTitle} · ${mTitle}`;
    }

    // Highlight active card inside Theme Modal
    document.querySelectorAll('.theme-card[data-preset-palette]').forEach((card) => {
        const cPal = card.getAttribute('data-preset-palette');
        const cMode = card.getAttribute('data-preset-mode');
        card.classList.toggle('active', cPal === cleanPalette && cMode === effectiveMode);
    });
}

async function persistSettingsToBackend(showSuccessToast = false) {
    const payload = {
        theme: appState.settings.theme,
        palette: appState.settings.palette,
        default_format: document.getElementById('format-select')?.value || appState.settings.default_format || 'mp4',
        default_speed_limit: document.getElementById('speed-input')?.value.trim() ?? appState.settings.default_speed_limit,
        default_subtitles: Boolean(document.getElementById('subs-input')?.checked),
        custom_args: document.getElementById('custom-args-input')?.value.trim() ?? appState.settings.custom_args,
        download_subfolder: document.getElementById('subfolder-input')?.value.trim() ?? appState.settings.download_subfolder,
        enable_access_logs: Boolean(document.getElementById('setting-access-logs')?.checked)
    };

    try {
        const res = await apiFetch(`${API_BASE}/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || 'Failed to save settings');
        }
        appState.settings = { ...appState.settings, ...payload };
        if (showSuccessToast) {
            showToast('Default settings saved successfully.', 'success');
        }
        return true;
    } catch (err) {
        if (showSuccessToast) {
            showToast(err.message || 'Error saving settings', 'error');
        }
        return false;
    }
}

// ============================================================================
// API FETCHERS & SYNCHRONIZATION
// ============================================================================

async function loadSettings() {
    try {
        const res = await apiFetch(`${API_BASE}/settings`);
        if (!res.ok) return;
        const data = await res.json();

        const localPal = localStorage.getItem('corgio_palette');
        const localTheme = localStorage.getItem('corgio_theme');

        appState.settings = {
            ...appState.settings,
            ...data,
            palette: normalizePalette(localPal || data.palette || 'pembroke'),
            theme: localTheme || data.theme || 'light'
        };

        applyAppearance(appState.settings.palette, appState.settings.theme);
        populateOptionsDrawerFromSettings();
    } catch (e) {
        console.error('Error loading settings:', e);
    }
}

function populateOptionsDrawerFromSettings() {
    const s = appState.settings;
    const fmtEl = document.getElementById('format-select');
    if (fmtEl && s.default_format) fmtEl.value = s.default_format;

    const speedEl = document.getElementById('speed-input');
    if (speedEl) speedEl.value = s.default_speed_limit || '';

    const subEl = document.getElementById('subfolder-input');
    if (subEl) subEl.value = s.download_subfolder || '';

    const argsEl = document.getElementById('custom-args-input');
    if (argsEl) argsEl.value = s.custom_args || '';

    const subsCheck = document.getElementById('subs-input');
    if (subsCheck) subsCheck.checked = Boolean(s.default_subtitles);

    const logsCheck = document.getElementById('setting-access-logs');
    if (logsCheck) logsCheck.checked = Boolean(s.enable_access_logs);

    const palSelect = document.getElementById('setting-palette');
    if (palSelect) palSelect.value = normalizePalette(s.palette);

    const themeSelect = document.getElementById('setting-theme');
    if (themeSelect) themeSelect.value = s.theme || 'dark';
}

function formatFfmpegVersion(raw) {
    if (!raw || raw === 'unknown') return 'Unknown';
    let str = raw
        .replace(/^ffmpeg\s+version\s+/i, '')
        .split(/\s+Copyright/i)[0]
        .trim();
    if (!str) return raw;

    // Git snapshot builds, e.g. N-127989-gc6f044e604-20261023 or N-127989-20261023
    const masterMatch = str.match(/^N-\d+(?:-g([0-9a-f]+))?-(\d{4})(\d{2})(\d{2})$/i);
    if (masterMatch) {
        const hash = masterMatch[1] ? masterMatch[1].slice(0, 7) : '';
        const dateStr = `${masterMatch[2]}-${masterMatch[3]}-${masterMatch[4]}`;
        return hash ? `Master · ${dateStr} (${hash})` : `Master · ${dateStr}`;
    }

    // Autobuild or git date patterns, e.g. autobuild-2026-10-23
    const autoMatch = str.match(/^(?:autobuild|git)-(\d{4})-(\d{2})-(\d{2})(?:-([0-9a-f]+))?/i);
    if (autoMatch) {
        const dateStr = `${autoMatch[1]}-${autoMatch[2]}-${autoMatch[3]}`;
        const hash = autoMatch[4] ? autoMatch[4].slice(0, 7) : '';
        return hash ? `Master · ${dateStr} (${hash})` : `Master · ${dateStr}`;
    }

    // Standard / distro release versions, e.g. 7.1, 7.1-ytdlp, n7.1
    if (/^\d+\.\d+/.test(str)) {
        return `v${str}`;
    }
    if (/^n\d+\.\d+/i.test(str)) {
        return `v${str.replace(/^n/i, '')}`;
    }

    return str;
}

async function fetchStatus() {
    try {
        const res = await apiFetch(`${API_BASE}/status`);
        if (!res.ok) return;
        const data = await res.json();

        const appVer = data.app_version ? `v${String(data.app_version).replace(/^v/i, '')}` : 'v1.0.0';
        const sysAppVer = document.getElementById('sys-app-version');
        if (sysAppVer) sysAppVer.textContent = appVer;

        const ytVer = data.yt_dlp_version || 'unknown';
        const ffRaw = data.ffmpeg_version || 'unknown';
        const ffDisplay = data.ffmpeg_friendly_version || formatFfmpegVersion(ffRaw);

        const sysYt = document.getElementById('sys-ytdlp-version');
        if (sysYt) sysYt.textContent = ytVer;

        const sysFf = document.getElementById('sys-ffmpeg-version');
        if (sysFf) {
            sysFf.textContent = ffDisplay;
            sysFf.title = ffRaw;
        }

        const sysJs = document.getElementById('sys-js-runtime');
        if (sysJs && data.js_runtime) {
            sysJs.textContent = data.js_runtime;
            sysJs.title = data.js_runtime;
        }

        const sysDir = document.getElementById('sys-downloads-dir');
        if (sysDir && data.downloads_dir) {
            sysDir.textContent = data.downloads_dir;
            sysDir.title = data.downloads_dir;
        }

        if (data.disk_space) {
            const { total, used, free, percent_used } = data.disk_space;
            const freeStr = formatBytes(free);
            const usedStr = formatBytes(used);
            const totalStr = formatBytes(total);

            const diskText = document.getElementById('disk-text');
            if (diskText) diskText.textContent = `${freeStr} free`;

            const diskWidget = document.getElementById('disk-widget');
            if (diskWidget) {
                diskWidget.title = `Used: ${usedStr} / ${totalStr} (${percent_used}%) • Path: ${data.downloads_dir || '/downloads'}`;
            }

            const diskFill = document.getElementById('disk-fill');
            if (diskFill) {
                diskFill.style.width = `${Math.min(100, Math.max(0, percent_used))}%`;
                diskFill.classList.remove('disk-warn', 'disk-danger');
                if (percent_used >= 90) {
                    diskFill.classList.add('disk-danger');
                } else if (percent_used >= 75) {
                    diskFill.classList.add('disk-warn');
                }
            }

            const sysDiskDetail = document.getElementById('sys-disk-detail');
            if (sysDiskDetail) {
                sysDiskDetail.textContent = `${usedStr} / ${totalStr} (${percent_used}%)`;
            }
        }

        await checkAndUpdateEngineStatus();
    } catch (e) {
        console.error('Error fetching status:', e);
    }
}

async function checkAndUpdateEngineStatus() {
    try {
        const res = await apiFetch(`${API_BASE}/update/status`);
        if (!res.ok) return;
        const st = await res.json();
        const updateBtn = document.getElementById('update-btn');
        const viewLogsBtn = document.getElementById('view-update-logs-btn');

        if (st.in_progress) {
            if (updateBtn) {
                updateBtn.disabled = true;
                updateBtn.textContent = 'Updating...';
            }
            if (viewLogsBtn) viewLogsBtn.classList.remove('hidden');
        } else {
            if (updateBtn) {
                updateBtn.disabled = false;
                updateBtn.textContent = 'Update Engines';
            }
            if (viewLogsBtn) {
                if (st.log_count > 0) {
                    viewLogsBtn.classList.remove('hidden');
                }
            }
        }
    } catch (_) {}
}

async function checkComponentUpdates(showFeedback = false) {
    const btn = document.getElementById('check-updates-btn');
    if (btn && showFeedback) {
        btn.disabled = true;
        btn.textContent = 'Checking...';
    }
    try {
        const res = await apiFetch(`${API_BASE}/check-updates`);
        if (!res.ok) return;
        const data = await res.json();

        const badge = document.getElementById('yt-dlp-update-badge');
        const dot = document.getElementById('header-update-dot');

        const ytAvail = Boolean(data.yt_dlp && data.yt_dlp.update_available);
        const ffAvail = Boolean(data.ffmpeg && data.ffmpeg.update_available);

        if (ytAvail || ffAvail) {
            if (badge) {
                if (ytAvail && ffAvail) {
                    badge.textContent = 'yt-dlp & FFmpeg Updates';
                } else if (ytAvail) {
                    badge.textContent = `yt-dlp: ${data.yt_dlp.latest}`;
                } else {
                    badge.textContent = 'FFmpeg Update Available';
                }
                badge.className = 'status-tag status-warn';
            }
            if (dot) dot.classList.remove('hidden');
            if (showFeedback) {
                const updatesList = [];
                if (ytAvail) updatesList.push(`yt-dlp (${data.yt_dlp.latest})`);
                if (ffAvail) updatesList.push(`FFmpeg (${formatFfmpegVersion(data.ffmpeg.latest)})`);
                showToast(`Update available: ${updatesList.join(' & ')}.`, 'info');
            }
        } else {
            if (badge) {
                badge.textContent = 'Up to date';
                badge.className = 'status-tag status-ok';
            }
            if (dot) dot.classList.add('hidden');
            if (showFeedback) {
                showToast('yt-dlp and FFmpeg engines are up to date.', 'success');
            }
        }
    } catch (e) {
        if (showFeedback) {
            showToast('Could not check for updates.', 'error');
        }
    } finally {
        if (btn && showFeedback) {
            btn.disabled = false;
            btn.textContent = 'Check Updates';
        }
    }
}

// ============================================================================
// ACTIVE QUEUE DOCK RENDERING & POLLING
// ============================================================================

function getStageStates(stage, progress) {
    const s = stage || 'downloading';
    if (s === 'metadata') {
        return ['active', '', '', ''];
    }
    if (s === 'downloading') {
        if (progress >= 99.9) {
            return ['done', 'done', 'active', ''];
        }
        return ['done', 'active', '', ''];
    }
    if (s === 'encoding') {
        return ['done', 'done', 'active', ''];
    }
    if (s === 'cleaning') {
        return ['done', 'done', 'done', 'active'];
    }
    return ['done', 'active', '', ''];
}

function getStageLabel(stage) {
    switch (stage) {
        case 'metadata': return 'METADATA';
        case 'encoding': return 'FFMPEG MUX';
        case 'cleaning': return 'FINALIZING';
        default: return 'STREAMING';
    }
}

async function fetchActiveDownloads() {
    try {
        const res = await apiFetch(`${API_BASE}/active`);
        if (!res.ok) return;
        const active = await res.json();
        appState.activeDownloads = active;

        renderActiveQueue(active);

        if (appState.hadActiveDownloads && active.length === 0) {
            fetchLibrary();
            fetchStatus();
            const sysDrawer = document.getElementById('drawer-system');
            if (sysDrawer && sysDrawer.classList.contains('open')) {
                fetchActivityLogs();
            }
        }
        appState.hadActiveDownloads = active.length > 0;
        scheduleNextPoll();
    } catch (e) {
        console.error('Error fetching active downloads:', e);
        scheduleNextPoll();
    }
}

function scheduleNextPoll() {
    if (appState.pollTimer) clearTimeout(appState.pollTimer);
    const delay = appState.activeDownloads.length > 0 ? 1200 : 3000;
    appState.pollTimer = setTimeout(fetchActiveDownloads, delay);
}

function renderActiveQueue(activeList) {
    const countBadge = document.getElementById('active-count-badge');
    const expandCount = document.getElementById('expand-queue-count');
    if (countBadge) countBadge.textContent = String(activeList.length);
    if (expandCount) expandCount.textContent = String(activeList.length);

    const container = document.getElementById('active-downloads-list');
    if (!container) return;

    if (activeList.length === 0) {
        container.innerHTML = `
            <div class="queue-empty">
                <p class="queue-empty-title">No active downloads</p>
                <p class="queue-empty-sub">Paste a link above to start downloading. Active jobs show live stream telemetry and 4-stage pipeline progress here.</p>
            </div>
        `;
        return;
    }

    // Check if same IDs are already rendered for smooth in-place updates
    const existingCards = Array.from(container.querySelectorAll('.q-card'));
    const existingIds = existingCards.map((c) => c.getAttribute('data-id'));
    const incomingIds = activeList.map((a) => String(a.id));

    const sameStructure =
        existingIds.length === incomingIds.length &&
        existingIds.every((id, idx) => id === incomingIds[idx]);

    if (sameStructure) {
        activeList.forEach((item) => {
            const card = container.querySelector(`.q-card[data-id="${CSS.escape(String(item.id))}"]`);
            if (!card) return;
            const prog = Number(item.progress || 0);
            const progRounded = prog.toFixed(1);

            const titleEl = card.querySelector('.q-title');
            if (titleEl) titleEl.textContent = item.title || item.url;

            const stageTag = card.querySelector('.q-stage-tag');
            if (stageTag) stageTag.textContent = getStageLabel(item.stage);

            const pctEl = card.querySelector('.q-pct');
            if (pctEl) pctEl.textContent = `${progRounded}%`;

            const speedEl = card.querySelector('.q-speed');
            if (speedEl) speedEl.textContent = `${item.speed || '0 KB/s'} • ETA ${item.eta || '00:00'}`;

            const fillEl = card.querySelector('.q-progress-fill');
            if (fillEl) fillEl.style.width = `${Math.min(100, Math.max(0, prog))}%`;

            const steps = getStageStates(item.stage, prog);
            const stepEls = card.querySelectorAll('.pipe-step');
            stepEls.forEach((el, idx) => {
                el.className = `pipe-step ${steps[idx] || ''}`.trim();
            });
        });
        return;
    }

    container.innerHTML = activeList.map((item) => {
        const prog = Number(item.progress || 0);
        const progRounded = prog.toFixed(1);
        const steps = getStageStates(item.stage, prog);
        const domain = item.domain || 'remote';
        const fmt = (item.format || 'mp4').toUpperCase();

        return `
            <div class="q-card" data-id="${escapeHtml(item.id)}">
                <div class="q-top">
                    <div class="q-tags">
                        <span class="status-tag">${escapeHtml(domain)}</span>
                        <span class="status-tag">${escapeHtml(fmt)}</span>
                    </div>
                    <span class="status-tag status-info q-stage-tag">${escapeHtml(getStageLabel(item.stage))}</span>
                </div>
                <div class="q-title" title="${escapeHtml(item.title || item.url)}">${escapeHtml(item.title || item.url)}</div>
                <div class="q-metrics">
                    <span class="q-pct">${progRounded}%</span>
                    <span class="q-speed">${escapeHtml(item.speed || '0 KB/s')} • ETA ${escapeHtml(item.eta || '00:00')}</span>
                </div>
                <div class="q-progress-track">
                    <div class="q-progress-fill" style="width: ${Math.min(100, Math.max(0, prog))}%;"></div>
                </div>
                <div class="pipeline-steps">
                    <div class="pipe-step ${steps[0]}">1.Meta</div>
                    <div class="pipe-step ${steps[1]}">2.Stream</div>
                    <div class="pipe-step ${steps[2]}">3.FFmpeg</div>
                    <div class="pipe-step ${steps[3]}">4.Clean</div>
                </div>
                <div class="q-actions">
                    <button type="button" class="btn btn-xs" data-action="logs" data-id="${escapeHtml(item.id)}">Console Log</button>
                    <button type="button" class="btn btn-xs" data-action="stop" data-id="${escapeHtml(item.id)}">Stop</button>
                    <button type="button" class="btn btn-xs btn-danger" data-action="purge" data-id="${escapeHtml(item.id)}">Purge</button>
                </div>
            </div>
        `;
    }).join('');
}

function applyQueueDockState() {
    const workspace = document.getElementById('workspace');
    const expandBtn = document.getElementById('btn-expand-queue');
    const headerToggleBtn = document.getElementById('btn-toggle-queue-header');
    if (!workspace) return;

    if (appState.queueCollapsed) {
        workspace.classList.add('queue-collapsed');
        if (expandBtn) expandBtn.classList.remove('hidden');
        if (headerToggleBtn) {
            headerToggleBtn.classList.remove('active');
            headerToggleBtn.setAttribute('title', 'Expand Active Queue panel (press Q)');
            headerToggleBtn.setAttribute('aria-expanded', 'false');
        }
    } else {
        workspace.classList.remove('queue-collapsed');
        if (expandBtn) expandBtn.classList.add('hidden');
        if (headerToggleBtn) {
            headerToggleBtn.classList.add('active');
            headerToggleBtn.setAttribute('title', 'Collapse Active Queue panel (press Q)');
            headerToggleBtn.setAttribute('aria-expanded', 'true');
        }
    }
}

function toggleQueueDock() {
    appState.queueCollapsed = !appState.queueCollapsed;
    localStorage.setItem('corgio_queue_collapsed', String(appState.queueCollapsed));
    applyQueueDockState();
    if (appState.queueCollapsed) {
        showToast('Active Queue collapsed. Click "Show Queue" in toolbar or press Q to restore.', 'info');
    }
}

// ============================================================================
// MEDIA LIBRARY FILTERING, SORTING & RENDERING (TABLE + GRID)
// ============================================================================

async function fetchLibrary() {
    try {
        const res = await apiFetch(`${API_BASE}/downloads`);
        if (!res.ok) return;
        const items = await res.json();
        // Exclude actively running items only if they are still pending/downloading
        appState.libraryItems = items.filter((d) => d.status !== 'downloading' && d.status !== 'pending');

        // Prune selectedIds that no longer exist
        const validIds = new Set(appState.libraryItems.map((i) => String(i.id)));
        for (const id of Array.from(appState.selectedIds)) {
            if (!validIds.has(id)) {
                appState.selectedIds.delete(id);
            }
        }

        renderFilterChips();
        renderLibrary();
        updateBatchBarUI();
    } catch (e) {
        console.error('Error fetching library:', e);
    }
}

function isAudioFormat(fmt) {
    return ['mp3', 'm4a', 'wav', 'flac', 'opus', 'aac'].includes(String(fmt || '').toLowerCase());
}

function renderFilterChips() {
    const container = document.getElementById('filter-chips-container');
    if (!container) return;

    const items = appState.libraryItems;
    const totalCount = items.length;
    const audioCount = items.filter((i) => isAudioFormat(i.format)).length;
    const failedCount = items.filter((i) => ['failed', 'stopped', 'missing'].includes(i.status)).length;

    // Count top domains
    const domainCounts = {};
    items.forEach((item) => {
        const dom = item.domain || 'unknown';
        domainCounts[dom] = (domainCounts[dom] || 0) + 1;
    });

    const topDomains = Object.entries(domainCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4);

    // Ensure activeFilter is still valid
    const validFilters = new Set(['all', 'audio', 'issues', ...topDomains.map(([d]) => `domain:${d}`)]);
    if (!validFilters.has(appState.activeFilter)) {
        appState.activeFilter = 'all';
    }

    let html = `
        <button type="button" class="chip ${appState.activeFilter === 'all' ? 'active' : ''}" data-filter="all">
            All (${totalCount})
        </button>
    `;

    topDomains.forEach(([dom, count]) => {
        const key = `domain:${dom}`;
        html += `
            <button type="button" class="chip ${appState.activeFilter === key ? 'active' : ''}" data-filter="${escapeHtml(key)}">
                ${escapeHtml(dom)} (${count})
            </button>
        `;
    });

    if (audioCount > 0 || appState.activeFilter === 'audio') {
        html += `
            <button type="button" class="chip ${appState.activeFilter === 'audio' ? 'active' : ''}" data-filter="audio">
                Audio (${audioCount})
            </button>
        `;
    }

    if (failedCount > 0 || appState.activeFilter === 'issues') {
        html += `
            <button type="button" class="chip ${appState.activeFilter === 'issues' ? 'active' : ''}" data-filter="issues">
                Failed / Stopped (${failedCount})
            </button>
        `;
    }

    container.innerHTML = html;
}

function getFilteredAndSortedLibrary() {
    let list = [...appState.libraryItems];

    // 1. Apply chip filter
    if (appState.activeFilter === 'audio') {
        list = list.filter((i) => isAudioFormat(i.format));
    } else if (appState.activeFilter === 'issues') {
        list = list.filter((i) => ['failed', 'stopped', 'missing'].includes(i.status));
    } else if (appState.activeFilter.startsWith('domain:')) {
        const targetDom = appState.activeFilter.slice('domain:'.length);
        list = list.filter((i) => (i.domain || 'unknown') === targetDom);
    }

    // 2. Apply search query
    if (appState.searchQuery) {
        const q = appState.searchQuery.toLowerCase();
        list = list.filter((i) => {
            const title = (i.title || '').toLowerCase();
            const domain = (i.domain || '').toLowerCase();
            const filename = (i.filename || '').toLowerCase();
            const url = (i.url || '').toLowerCase();
            const fmt = (i.format || '').toLowerCase();
            return (
                title.includes(q) ||
                domain.includes(q) ||
                filename.includes(q) ||
                url.includes(q) ||
                fmt.includes(q)
            );
        });
    }

    // 3. Apply sorting
    const { sortBy, sortOrder } = appState;
    list.sort((a, b) => {
        let valA = a[sortBy];
        let valB = b[sortBy];

        if (sortBy === 'date_added') {
            valA = valA ? new Date(valA).getTime() : 0;
            valB = valB ? new Date(valB).getTime() : 0;
        } else if (['duration', 'file_size', 'play_count'].includes(sortBy)) {
            valA = Number(valA) || 0;
            valB = Number(valB) || 0;
        } else {
            valA = String(valA || '').toLowerCase();
            valB = String(valB || '').toLowerCase();
        }

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
        return 0;
    });

    return list;
}

function getStatusBadgeHtml(item) {
    if (item.status === 'completed') {
        const fmt = (item.format || 'mp4').toUpperCase();
        return `<span class="status-tag status-ok">${escapeHtml(fmt)}</span>`;
    }
    if (item.status === 'failed') {
        return `<span class="status-tag status-err">FAILED</span>`;
    }
    if (item.status === 'stopped') {
        return `<span class="status-tag status-warn">STOPPED</span>`;
    }
    if (item.status === 'missing') {
        return `<span class="status-tag status-warn">MISSING</span>`;
    }
    return `<span class="status-tag">${escapeHtml(item.status || 'UNKNOWN')}</span>`;
}

function renderLibrary() {
    const tableWrap = document.getElementById('library-table-wrap');
    const gridWrap = document.getElementById('library-grid-wrap');
    const tableBtn = document.getElementById('btn-view-table');
    const gridBtn = document.getElementById('btn-view-grid');

    if (appState.viewMode === 'grid') {
        tableWrap?.classList.add('hidden');
        gridWrap?.classList.remove('hidden');
        tableBtn?.classList.remove('active');
        gridBtn?.classList.add('active');
    } else {
        tableWrap?.classList.remove('hidden');
        gridWrap?.classList.add('hidden');
        tableBtn?.classList.add('active');
        gridBtn?.classList.remove('active');
    }

    const filtered = getFilteredAndSortedLibrary();
    renderTableView(filtered);
    renderGridView(filtered);
}

function renderTableView(items) {
    const tbody = document.getElementById('library-table-body');
    if (!tbody) return;

    if (items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="empty-cell">
                    No media items match the current view. Paste a URL above to download or adjust your search filter.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = items.map((item) => {
        const id = String(item.id);
        const isSelected = appState.selectedIds.has(id);
        const isCompleted = item.status === 'completed';
        const isRetryable = item.status === 'failed' || item.status === 'stopped';
        const thumbUrl = isCompleted && item.thumbnail_url ? item.thumbnail_url : '/static/fallback-icon.svg';
        const durStr = formatDuration(item.duration);
        const sizeStr = isCompleted ? formatBytes(item.file_size) : '--';
        const plays = isCompleted ? (item.play_count || 0) : '--';
        const addedStr = formatShortDate(item.date_added);
        const domainStr = item.domain || 'unknown';

        let subLine = '';
        if (isCompleted && item.filename) {
            subLine = `<div class="row-sub-text">${escapeHtml(item.filename)}</div>`;
        } else if (item.error_log) {
            subLine = `<div class="row-err-text">${escapeHtml(item.error_log)}</div>`;
        } else if (item.url) {
            subLine = `<div class="row-sub-text">${escapeHtml(item.url)}</div>`;
        }

        let actionsHtml = '';
        if (isCompleted) {
            actionsHtml += `
                <button type="button" class="btn btn-xs btn-primary" data-action="play" data-id="${escapeHtml(id)}">Play</button>
                <a href="${API_BASE}/video/${encodeURIComponent(id)}?download=true" download class="btn btn-xs" data-action="save-log" data-id="${escapeHtml(id)}" title="Save media file to device">Save</a>
                <button type="button" class="btn btn-xs" data-action="info" data-id="${escapeHtml(id)}" title="Stream &amp; file metadata">Info</button>
            `;
        } else if (isRetryable) {
            actionsHtml += `
                <button type="button" class="btn btn-xs btn-primary" data-action="retry" data-id="${escapeHtml(id)}">Retry</button>
                <button type="button" class="btn btn-xs" data-action="logs" data-id="${escapeHtml(id)}">Log</button>
            `;
        } else {
            actionsHtml += `
                <button type="button" class="btn btn-xs" data-action="info" data-id="${escapeHtml(id)}">Info</button>
            `;
        }

        actionsHtml += `
            <button type="button" class="btn btn-xs btn-danger" data-action="purge" data-id="${escapeHtml(id)}" title="Zero-trace purge item and logs">Purge</button>
        `;

        return `
            <tr class="${isSelected ? 'row-selected' : ''}" data-id="${escapeHtml(id)}">
                <td class="col-check">
                    <input type="checkbox" class="item-checkbox" data-id="${escapeHtml(id)}" ${isSelected ? 'checked' : ''} aria-label="Select ${escapeHtml(item.title || id)}">
                </td>
                <td class="col-preview">
                    <div class="thumb-mini" data-action="${isCompleted ? 'play' : 'info'}" data-id="${escapeHtml(id)}" title="${isCompleted ? 'Click to play' : 'Click for details'}">
                        <img src="${escapeHtml(thumbUrl)}" alt="" loading="lazy" class="media-thumb-img">
                        ${isCompleted && item.duration ? `<span class="thumb-mini-dur">${escapeHtml(durStr)}</span>` : ''}
                    </div>
                </td>
                <td class="col-title">
                    <div class="row-title-text" title="${escapeHtml(item.title || item.url)}">${escapeHtml(item.title || item.url)}</div>
                    ${subLine}
                    <div class="row-inline-meta">
                        <span class="status-tag">${escapeHtml(domainStr)}</span>
                        ${getStatusBadgeHtml(item)}
                        <span>${escapeHtml(sizeStr)}</span>
                        <span>${escapeHtml(addedStr)}</span>
                    </div>
                </td>
                <td class="col-domain">
                    <span class="status-tag">${escapeHtml(domainStr)}</span>
                </td>
                <td class="col-format">
                    ${getStatusBadgeHtml(item)}
                </td>
                <td class="col-size mono-cell">${escapeHtml(sizeStr)}</td>
                <td class="col-plays mono-cell">${escapeHtml(String(plays))}</td>
                <td class="col-date mono-cell">${escapeHtml(addedStr)}</td>
                <td class="col-actions">
                    <div class="row-actions">
                        ${actionsHtml}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function renderGridView(items) {
    const grid = document.getElementById('library-grid-wrap');
    if (!grid) return;

    if (items.length === 0) {
        grid.innerHTML = `
            <div class="queue-empty" style="grid-column: 1 / -1;">
                <p class="queue-empty-title">No media items match the current filter</p>
                <p class="queue-empty-sub">Paste a video or audio URL in the top command bar to start downloading.</p>
            </div>
        `;
        return;
    }

    grid.innerHTML = items.map((item) => {
        const id = String(item.id);
        const isSelected = appState.selectedIds.has(id);
        const isCompleted = item.status === 'completed';
        const isRetryable = item.status === 'failed' || item.status === 'stopped';
        const thumbUrl = isCompleted && item.thumbnail_url ? item.thumbnail_url : '/static/fallback-icon.svg';
        const durStr = formatDuration(item.duration);
        const sizeStr = isCompleted ? formatBytes(item.file_size) : (item.status || '').toUpperCase();
        const domainStr = item.domain || 'unknown';
        const addedStr = formatShortDate(item.date_added);

        let leftActions = '';
        if (isCompleted) {
            leftActions = `
                <button type="button" class="btn btn-xs btn-primary" data-action="play" data-id="${escapeHtml(id)}">Play</button>
                <a href="${API_BASE}/video/${encodeURIComponent(id)}?download=true" download class="btn btn-xs" data-action="save-log" data-id="${escapeHtml(id)}">Save</a>
                <button type="button" class="btn btn-xs" data-action="info" data-id="${escapeHtml(id)}">Info</button>
            `;
        } else if (isRetryable) {
            leftActions = `
                <button type="button" class="btn btn-xs btn-primary" data-action="retry" data-id="${escapeHtml(id)}">Retry</button>
                <button type="button" class="btn btn-xs" data-action="logs" data-id="${escapeHtml(id)}">Log</button>
            `;
        } else {
            leftActions = `
                <button type="button" class="btn btn-xs" data-action="info" data-id="${escapeHtml(id)}">Info</button>
            `;
        }

        return `
            <article class="m-card ${isSelected ? 'card-selected' : ''}" data-id="${escapeHtml(id)}">
                <div class="m-thumb" data-action="${isCompleted ? 'play' : 'info'}" data-id="${escapeHtml(id)}">
                    <div class="m-check-wrap" data-stop-prop="true">
                        <input type="checkbox" class="item-checkbox" data-id="${escapeHtml(id)}" ${isSelected ? 'checked' : ''} aria-label="Select ${escapeHtml(item.title || id)}">
                    </div>
                    <img src="${escapeHtml(thumbUrl)}" alt="" loading="lazy" class="media-thumb-img">
                    <div class="m-badges-top">
                        ${getStatusBadgeHtml(item)}
                    </div>
                    ${isCompleted && item.duration ? `<span class="m-duration">${escapeHtml(durStr)}</span>` : ''}
                </div>
                <div class="m-body">
                    <div class="m-title" title="${escapeHtml(item.title || item.url)}">${escapeHtml(item.title || item.url)}</div>
                    ${item.error_log ? `<div class="row-err-text">${escapeHtml(item.error_log)}</div>` : ''}
                    <div class="m-meta">
                        <span>${escapeHtml(domainStr)} • ${escapeHtml(sizeStr)}</span>
                        <span>${escapeHtml(addedStr)}</span>
                    </div>
                    <div class="m-footer">
                        <div class="m-footer-left">
                            ${leftActions}
                        </div>
                        <div class="m-footer-right">
                            <button type="button" class="btn btn-xs btn-danger" data-action="purge" data-id="${escapeHtml(id)}">Purge</button>
                        </div>
                    </div>
                </div>
            </article>
        `;
    }).join('');
}

// ============================================================================
// BATCH MULTI-SELECT MODE
// ============================================================================

function updateBatchBarUI() {
    const batchBar = document.getElementById('batch-bar');
    const batchBtn = document.getElementById('btn-batch-mode');
    const countEl = document.getElementById('batch-count');
    const selectAllA = document.getElementById('batch-select-all');
    const selectAllB = document.getElementById('table-select-all');

    const count = appState.selectedIds.size;
    if (countEl) countEl.textContent = String(count);

    const visibleItems = getFilteredAndSortedLibrary();
    const allVisibleSelected =
        visibleItems.length > 0 &&
        visibleItems.every((i) => appState.selectedIds.has(String(i.id)));

    if (selectAllA) selectAllA.checked = allVisibleSelected;
    if (selectAllB) selectAllB.checked = allVisibleSelected;

    if (appState.batchMode || count > 0) {
        batchBar?.classList.remove('hidden');
        batchBtn?.classList.add('active');
    } else {
        batchBar?.classList.add('hidden');
        batchBtn?.classList.remove('active');
    }
}

function toggleSelectAllVisible(checked) {
    const visibleItems = getFilteredAndSortedLibrary();
    visibleItems.forEach((item) => {
        const id = String(item.id);
        if (checked) {
            appState.selectedIds.add(id);
        } else {
            appState.selectedIds.delete(id);
        }
    });
    renderLibrary();
    updateBatchBarUI();
}

// ============================================================================
// DOWNLOAD & QUEUE ACTIONS
// ============================================================================

async function triggerDownloadFromOmnibox() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput?.value.trim();
    if (!url) return;

    const format = document.getElementById('format-select')?.value || 'mp4';
    const speedLimit = document.getElementById('speed-input')?.value.trim() || null;
    const subtitles = Boolean(document.getElementById('subs-input')?.checked);
    const customArgs = document.getElementById('custom-args-input')?.value.trim() || null;
    const subfolderInput = document.getElementById('subfolder-input')?.value.trim() || '';

    const downloadBtn = document.getElementById('download-btn');
    if (downloadBtn) downloadBtn.disabled = true;

    try {
        // If custom subfolder differs from saved setting, persist it first so backend uses it
        if (subfolderInput !== (appState.settings.download_subfolder || '')) {
            await persistSettingsToBackend(false);
        }

        const res = await apiFetch(`${API_BASE}/download`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url,
                format,
                speed_limit: speedLimit,
                subtitles,
                custom_args: customArgs
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || 'Failed to start download');
        }

        if (urlInput) urlInput.value = '';
        showToast('Download queued in isolated work directory.', 'success');

        // Expand queue dock if collapsed so user sees progress
        if (appState.queueCollapsed) {
            appState.queueCollapsed = false;
            localStorage.setItem('corgio_queue_collapsed', 'false');
            applyQueueDockState();
        }

        appState.hadActiveDownloads = true;
        fetchActiveDownloads();
    } catch (err) {
        showToast(err.message || 'Error starting download', 'error');
    } finally {
        if (downloadBtn) downloadBtn.disabled = false;
    }
}

async function stopDownloadById(id) {
    try {
        const res = await apiFetch(`${API_BASE}/downloads/${encodeURIComponent(id)}/stop`, {
            method: 'POST'
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || 'Could not stop download');
        }
        showToast('Download stopped and partial work files cleaned.', 'info');
        fetchActiveDownloads();
        fetchLibrary();
    } catch (err) {
        showToast(err.message || 'Error stopping download', 'error');
    }
}

async function retryDownloadById(id) {
    try {
        const res = await apiFetch(`${API_BASE}/downloads/${encodeURIComponent(id)}/retry`, {
            method: 'POST'
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || 'Could not retry download');
        }
        showToast('Retrying download...', 'info');
        appState.hadActiveDownloads = true;
        fetchActiveDownloads();
        fetchLibrary();
    } catch (err) {
        showToast(err.message || 'Error retrying download', 'error');
    }
}

// ============================================================================
// MODALS (Player, Console Logs, Metadata, Zero-Trace Purge, Activity Detail)
// ============================================================================

function openPlayerModal(id) {
    const item = appState.libraryItems.find((i) => String(i.id) === String(id));
    const modal = document.getElementById('player-modal');
    const video = document.getElementById('video-player');
    const titleEl = document.getElementById('player-title');
    const saveLink = document.getElementById('player-download-link');
    if (!modal || !video) return;

    const label = item ? (item.title || item.filename || 'Media Player') : 'Media Player';
    if (titleEl) titleEl.textContent = label;
    if (saveLink) saveLink.href = `${API_BASE}/video/${encodeURIComponent(id)}?download=true`;

    video.src = `${API_BASE}/video/${encodeURIComponent(id)}`;
    modal.classList.remove('hidden');
    video.play().catch(() => {});

    // Record server-verified PLAY activity and increment play_count in SQLite (L2)
    apiFetch(`${API_BASE}/downloads/${encodeURIComponent(id)}/play`, {
        method: 'POST'
    }).catch(() => {});

    if (item) {
        item.play_count = (item.play_count || 0) + 1;
        renderLibrary();
    }
}

function closePlayerModal() {
    const modal = document.getElementById('player-modal');
    const video = document.getElementById('video-player');
    if (video) {
        video.pause();
        video.removeAttribute('src');
        video.load();
    }
    modal?.classList.add('hidden');
}

function openLogModal(id) {
    const modal = document.getElementById('log-modal');
    const logPre = document.getElementById('log-content');
    if (!modal || !logPre) return;

    if (appState.activeLogStream) {
        appState.activeLogStream.close();
        appState.activeLogStream = null;
    }

    logPre.textContent = 'Connecting to downloader & encoder log stream...\n';
    modal.classList.remove('hidden');

    let receivedLines = false;
    const evtSource = new EventSource(`${API_BASE}/stream-logs/${encodeURIComponent(id)}`);
    appState.activeLogStream = evtSource;

    evtSource.onmessage = (event) => {
        if (!receivedLines) {
            logPre.textContent = '';
            receivedLines = true;
        }
        const line = event.data || '';
        logPre.textContent += line + '\n';
        logPre.scrollTop = logPre.scrollHeight;

        if (line.includes('[system] Log stream ended.')) {
            evtSource.close();
            appState.activeLogStream = null;
        }
    };

    evtSource.onerror = () => {
        evtSource.close();
        appState.activeLogStream = null;
        if (!receivedLines) {
            fetchStaticLogsFallback(id, logPre);
        }
    };
}

async function fetchStaticLogsFallback(id, logPre) {
    try {
        const res = await apiFetch(`${API_BASE}/logs/${encodeURIComponent(id)}`);
        if (!res.ok) {
            logPre.textContent = '[system] Could not retrieve logs.';
            return;
        }
        const lines = await res.json();
        logPre.textContent = Array.isArray(lines) && lines.length > 0
            ? lines.join('\n')
            : '[system] No logs available for this item.';
    } catch (e) {
        logPre.textContent = '[system] Error retrieving logs.';
    }
}

function closeLogModal() {
    if (appState.activeLogStream) {
        appState.activeLogStream.close();
        appState.activeLogStream = null;
    }
    document.getElementById('log-modal')?.classList.add('hidden');
}

function openMetadataModal(id) {
    const item = appState.libraryItems.find((i) => String(i.id) === String(id));
    if (!item) return;

    let meta = {};
    if (item.metadata_json) {
        try {
            meta = JSON.parse(item.metadata_json) || {};
        } catch (e) {
            meta = {};
        }
    }

    const resStr = meta.width && meta.height ? `${meta.width}×${meta.height}` : 'N/A';
    const fpsStr = meta.fps ? `${meta.fps} fps` : 'N/A';
    const vcodec = (meta.vcodec && meta.vcodec !== 'none') ? meta.vcodec : 'N/A';
    const acodec = (meta.acodec && meta.acodec !== 'none') ? meta.acodec : 'N/A';

    const body = document.getElementById('metadata-body');
    const modal = document.getElementById('metadata-modal');
    if (!body || !modal) return;

    body.innerHTML = `
        <div class="meta-grid">
            <div class="meta-item meta-item-full">
                <div class="meta-label">Title</div>
                <div class="meta-value">${escapeHtml(item.title || 'Unknown')}</div>
            </div>
            <div class="meta-item meta-item-full">
                <div class="meta-label">Source URL</div>
                <div class="meta-value" style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                    <span>${escapeHtml(item.url || 'N/A')}</span>
                    <button type="button" class="btn btn-xs" id="btn-copy-meta-url" data-url="${escapeHtml(item.url || '')}">Copy URL</button>
                </div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Domain</div>
                <div class="meta-value">${escapeHtml(item.domain || 'unknown')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Container &amp; Status</div>
                <div class="meta-value">${escapeHtml((item.format || 'N/A').toUpperCase())} (${escapeHtml(item.status)})</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">File Size</div>
                <div class="meta-value">${escapeHtml(formatBytes(item.file_size))}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Duration</div>
                <div class="meta-value">${escapeHtml(formatDuration(item.duration))}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Resolution &amp; Frame Rate</div>
                <div class="meta-value">${escapeHtml(resStr)} • ${escapeHtml(fpsStr)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Video / Audio Codecs</div>
                <div class="meta-value">${escapeHtml(vcodec)} / ${escapeHtml(acodec)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Uploader</div>
                <div class="meta-value">${escapeHtml(meta.uploader || 'Unknown')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Upload Date / Play Count</div>
                <div class="meta-value">${escapeHtml(meta.upload_date || 'N/A')} • ${escapeHtml(String(item.play_count || 0))} plays</div>
            </div>
            <div class="meta-item meta-item-full">
                <div class="meta-label">Local File Path</div>
                <div class="meta-value">${escapeHtml(item.filepath || 'N/A')}</div>
            </div>
            ${meta.description ? `
                <div class="meta-item meta-item-full">
                    <div class="meta-label">Description</div>
                    <div class="meta-desc-pre">${escapeHtml(meta.description)}</div>
                </div>
            ` : ''}
        </div>
    `;

    const copyBtn = document.getElementById('btn-copy-meta-url');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const u = copyBtn.getAttribute('data-url') || '';
            navigator.clipboard.writeText(u).then(() => {
                showToast('Source URL copied to clipboard.', 'info');
            }).catch(() => {});
        });
    }

    modal.classList.remove('hidden');
}

function openPurgeModal(ids) {
    const idList = Array.isArray(ids) ? ids.map(String) : [String(ids)];
    if (idList.length === 0) return;

    appState.pendingPurgeIds = idList;

    const descEl = document.getElementById('delete-modal-desc');
    const confirmBtn = document.getElementById('confirm-delete');
    const modal = document.getElementById('delete-modal');
    if (!modal) return;

    if (idList.length === 1) {
        const singleId = idList[0];
        const item =
            appState.libraryItems.find((i) => String(i.id) === singleId) ||
            appState.activeDownloads.find((i) => String(i.id) === singleId);
        const label = item ? (item.title || item.url || singleId) : singleId;
        if (descEl) {
            descEl.innerHTML = `Purge <strong>${escapeHtml(label)}</strong> and wipe all associated downloader, encoder, and database artifacts?`;
        }
        if (confirmBtn) confirmBtn.textContent = 'Purge Item & Logs';
    } else {
        if (descEl) {
            descEl.innerHTML = `Purge <strong>${idList.length} selected items</strong> and wipe all associated downloader, encoder, and database artifacts?`;
        }
        if (confirmBtn) confirmBtn.textContent = `Purge ${idList.length} Items & Logs`;
    }

    modal.classList.remove('hidden');
}

function closePurgeModal() {
    appState.pendingPurgeIds = [];
    document.getElementById('delete-modal')?.classList.add('hidden');
}

async function executeConfirmedPurge() {
    const ids = [...appState.pendingPurgeIds];
    if (ids.length === 0) return;

    const deleteFile = Boolean(document.getElementById('delete-file-checkbox')?.checked);
    const confirmBtn = document.getElementById('confirm-delete');
    if (confirmBtn) confirmBtn.disabled = true;

    let successCount = 0;
    try {
        for (const id of ids) {
            const res = await apiFetch(
                `${API_BASE}/downloads/${encodeURIComponent(id)}?delete_file=${deleteFile}`,
                { method: 'DELETE' }
            );
            if (res.ok) {
                successCount += 1;
                appState.selectedIds.delete(String(id));
            }
        }

        closePurgeModal();
        showToast(
            `Purged ${successCount} item(s) and wiped all associated logs.`,
            'success'
        );

        fetchActiveDownloads();
        fetchLibrary();
        fetchStatus();
        const sysDrawer = document.getElementById('drawer-system');
        if (sysDrawer && sysDrawer.classList.contains('open')) {
            fetchActivityLogs();
        }
    } catch (e) {
        showToast('Error purging one or more items.', 'error');
    } finally {
        if (confirmBtn) confirmBtn.disabled = false;
    }
}

// ============================================================================
// SYSTEM MAINTENANCE & ACTIVITY AUDIT LOGS
// ============================================================================

async function fetchActivityLogs() {
    const tbody = document.getElementById('activity-logs-tbody');
    const countEl = document.getElementById('activity-count');
    if (!tbody) return;

    try {
        const res = await apiFetch(`${API_BASE}/activity-logs`);
        if (!res.ok) return;
        const logs = await res.json();
        appState.activityLogs = logs;

        if (countEl) countEl.textContent = String(logs.length);

        if (logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="3" class="empty-cell">No activity logs recorded.</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = logs.map((log, idx) => {
            const ts = formatFullTimestamp(log.timestamp);
            const ev = log.event_type || 'EVENT';
            let tagClass = '';
            if (ev.includes('COMPLETE') || ev.includes('RESTORE')) tagClass = 'status-ok';
            else if (ev.includes('FAIL') || ev.includes('ERROR')) tagClass = 'status-err';
            else if (ev.includes('START') || ev.includes('TRIGGER') || ev === 'PLAY') tagClass = 'status-info';
            else if (ev.includes('MISSING') || ev.includes('WARN')) tagClass = 'status-warn';

            const firstLine = String(log.message || '').split('\n')[0];
            return `
                <tr data-log-index="${idx}">
                    <td class="mono-cell">${escapeHtml(ts)}</td>
                    <td><span class="status-tag ${tagClass}">${escapeHtml(ev)}</span></td>
                    <td>${escapeHtml(firstLine)}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('Error fetching activity logs:', e);
    }
}

function openActivityDetailModal(index) {
    const log = appState.activityLogs[index];
    if (!log) return;

    const body = document.getElementById('activity-detail-body');
    const modal = document.getElementById('activity-detail-modal');
    if (!body || !modal) return;

    body.innerHTML = `
        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Timestamp (UTC)</div>
                <div class="meta-value">${escapeHtml(formatFullTimestamp(log.timestamp))}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Event Type</div>
                <div class="meta-value">${escapeHtml(log.event_type || 'N/A')}</div>
            </div>
            <div class="meta-item meta-item-full">
                <div class="meta-label">Associated Download ID</div>
                <div class="meta-value">${escapeHtml(log.download_id || 'System-wide event')}</div>
            </div>
            <div class="meta-item meta-item-full">
                <div class="meta-label">Event Details</div>
                <pre class="console-pre" style="margin-top:4px;">${escapeHtml(log.message || '')}</pre>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
}

async function clearAllActivityLogs() {
    try {
        const res = await apiFetch(`${API_BASE}/activity-logs/clear`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to clear activity logs');
        showToast('Activity audit log cleared and WAL truncated.', 'success');
        fetchActivityLogs();
    } catch (e) {
        showToast('Could not clear activity logs.', 'error');
    }
}

async function runFolderScan() {
    const btn = document.getElementById('scan-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Scanning...';
    }
    try {
        const res = await apiFetch(`${API_BASE}/scan`, { method: 'POST' });
        if (!res.ok) throw new Error('Folder scan failed');
        const data = await res.json();
        const added = data.added_count ?? data.added ?? 0;
        const missing = data.missing_count ?? data.missing ?? 0;
        const restored = data.restored_count ?? data.restored ?? 0;
        showToast(
            `Scan complete: +${added} imported, ${missing} missing, ${restored} restored.`,
            'success'
        );
        fetchLibrary();
        fetchStatus();
        fetchActivityLogs();
    } catch (e) {
        showToast('Error scanning downloads folder.', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Scan Folder';
        }
    }
}

function openUpdateModal(autoFollow = false) {
    const modal = document.getElementById('update-modal');
    const logPre = document.getElementById('update-log-content');
    const badge = document.getElementById('update-modal-badge');
    const statusText = document.getElementById('update-modal-status-text');
    if (!modal || !logPre) return;

    if (appState.activeUpdateStream) {
        appState.activeUpdateStream.close();
        appState.activeUpdateStream = null;
    }

    modal.classList.remove('hidden');
    logPre.textContent = 'Connecting to engine update log stream...\n';
    if (badge) {
        badge.className = 'status-tag status-neutral';
        badge.textContent = 'Connecting...';
    }
    if (statusText) statusText.textContent = '';

    let receivedLines = false;
    const evtSource = new EventSource(`${API_BASE}/update/stream`);
    appState.activeUpdateStream = evtSource;

    evtSource.onmessage = (event) => {
        if (!receivedLines) {
            logPre.textContent = '';
            receivedLines = true;
        }
        const line = event.data || '';
        logPre.textContent += line + '\n';
        logPre.scrollTop = logPre.scrollHeight;

        if (badge) {
            if (line.includes('[system] Starting') || line.includes('[yt-dlp]') || line.includes('[ffmpeg]')) {
                badge.className = 'status-tag status-warn';
                badge.textContent = 'Updating...';
            }
            if (line.includes('Engine update completed successfully')) {
                badge.className = 'status-tag status-ok';
                badge.textContent = 'Completed';
            } else if (line.includes('Fatal error') || line.includes('completed with warnings or errors')) {
                badge.className = 'status-tag status-danger';
                badge.textContent = 'Failed';
            }
        }

        if (line.includes('[system] Update log stream ended.')) {
            evtSource.close();
            appState.activeUpdateStream = null;
            fetchStatus();
            fetchActivityLogs();
            const updateBtn = document.getElementById('update-btn');
            if (updateBtn) {
                updateBtn.disabled = false;
                updateBtn.textContent = 'Update Engines';
            }
            const viewLogsBtn = document.getElementById('view-update-logs-btn');
            if (viewLogsBtn) viewLogsBtn.classList.remove('hidden');
        }
    };

    evtSource.onerror = () => {
        evtSource.close();
        appState.activeUpdateStream = null;
        if (!receivedLines) {
            fetchStaticUpdateLogsFallback(logPre, badge);
        }
    };
}

async function fetchStaticUpdateLogsFallback(logPre, badge) {
    try {
        const res = await apiFetch(`${API_BASE}/update/logs`);
        if (!res.ok) {
            logPre.textContent = '[system] Could not retrieve update logs.';
            return;
        }
        const data = await res.json();
        const logs = data.logs || [];
        logPre.textContent = logs.length > 0
            ? logs.join('\n')
            : '[system] No engine update logs recorded yet.';
        logPre.scrollTop = logPre.scrollHeight;

        if (badge && data.status) {
            if (data.status.in_progress) {
                badge.className = 'status-tag status-warn';
                badge.textContent = 'Updating...';
            } else if (data.status.success === true) {
                badge.className = 'status-tag status-ok';
                badge.textContent = 'Completed';
            } else if (data.status.success === false) {
                badge.className = 'status-tag status-danger';
                badge.textContent = 'Failed';
            } else {
                badge.className = 'status-tag status-neutral';
                badge.textContent = 'Idle';
            }
        }
    } catch (_) {
        logPre.textContent = '[system] Error retrieving update logs.';
    }
}

function closeUpdateModal() {
    if (appState.activeUpdateStream) {
        appState.activeUpdateStream.close();
        appState.activeUpdateStream = null;
    }
    document.getElementById('update-modal')?.classList.add('hidden');
}

async function runEngineUpdate() {
    const btn = document.getElementById('update-btn');
    const viewLogsBtn = document.getElementById('view-update-logs-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Updating...';
    }
    if (viewLogsBtn) viewLogsBtn.classList.remove('hidden');

    openUpdateModal(true);
    showToast('Starting engine update. Streaming logs live...', 'info');

    try {
        const res = await apiFetch(`${API_BASE}/update`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'already_running') {
            showToast('Engine update is already in progress.', 'info');
        } else if (data.status === 'update_started') {
            showToast('Engine update started in background.', 'success');
        } else {
            showToast(data.message || 'Engine update triggered.', 'info');
        }
    } catch (e) {
        showToast('Error starting engine update.', 'error');
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Update Engines';
        }
    }
}

// ============================================================================
// EVENT LISTENERS & INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // 1. Apply initial appearance & queue dock state
    applyAppearance(appState.settings.palette, appState.settings.theme);
    applyQueueDockState();

    // Listen for OS theme changes when set to 'system'
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
        if (appState.settings.theme === 'system') {
            applyAppearance(appState.settings.palette, 'system');
        }
    });

    // 2. Top Command Bar — Theme Modal Trigger & Preset Grid
    const themeModal = document.getElementById('theme-modal');
    document.getElementById('btn-open-theme-modal')?.addEventListener('click', () => {
        themeModal?.classList.remove('hidden');
    });
    document.getElementById('close-theme-modal')?.addEventListener('click', () => {
        themeModal?.classList.add('hidden');
    });
    document.getElementById('done-theme-modal')?.addEventListener('click', () => {
        themeModal?.classList.add('hidden');
    });
    document.getElementById('theme-preset-grid')?.addEventListener('click', (e) => {
        const card = e.target.closest('.theme-card[data-preset-palette]');
        if (!card) return;
        const chosenPalette = card.getAttribute('data-preset-palette') || 'pembroke';
        const chosenMode = card.getAttribute('data-preset-mode') || 'light';
        applyAppearance(chosenPalette, chosenMode);
        persistSettingsToBackend(false);
    });

    // 3. Slide-Down Drawers (Options & System)
    const optionsDrawer = document.getElementById('drawer-options');
    const systemDrawer = document.getElementById('drawer-system');
    const toggleOptionsBtn = document.getElementById('btn-toggle-options');
    const toggleSystemBtn = document.getElementById('btn-toggle-system');

    function setDrawerState(drawerToToggle) {
        if (drawerToToggle === 'options') {
            const isOpen = optionsDrawer?.classList.toggle('open');
            toggleOptionsBtn?.classList.toggle('active', Boolean(isOpen));
            systemDrawer?.classList.remove('open');
            toggleSystemBtn?.classList.remove('active');
        } else if (drawerToToggle === 'system') {
            const isOpen = systemDrawer?.classList.toggle('open');
            toggleSystemBtn?.classList.toggle('active', Boolean(isOpen));
            optionsDrawer?.classList.remove('open');
            toggleOptionsBtn?.classList.remove('active');
            if (isOpen) {
                fetchStatus();
                fetchActivityLogs();
            }
        } else {
            optionsDrawer?.classList.remove('open');
            systemDrawer?.classList.remove('open');
            toggleOptionsBtn?.classList.remove('active');
            toggleSystemBtn?.classList.remove('active');
        }
    }

    toggleOptionsBtn?.addEventListener('click', () => setDrawerState('options'));
    toggleSystemBtn?.addEventListener('click', () => setDrawerState('system'));
    document.getElementById('btn-close-options')?.addEventListener('click', () => setDrawerState(null));
    document.getElementById('btn-close-system')?.addEventListener('click', () => setDrawerState(null));

    // Options Drawer Selectors & Buttons
    document.getElementById('setting-palette')?.addEventListener('change', (e) => {
        applyAppearance(e.target.value, appState.settings.theme);
    });
    document.getElementById('setting-theme')?.addEventListener('change', (e) => {
        applyAppearance(appState.settings.palette, e.target.value);
    });
    document.getElementById('btn-reset-options')?.addEventListener('click', () => {
        populateOptionsDrawerFromSettings();
        applyAppearance(appState.settings.palette, appState.settings.theme);
        showToast('Reverted fields to saved defaults.', 'info');
    });
    document.getElementById('btn-save-defaults')?.addEventListener('click', () => {
        persistSettingsToBackend(true);
    });

    // 4. Omnibox Form & Paste-and-Go
    document.getElementById('download-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        triggerDownloadFromOmnibox();
    });

    document.getElementById('btn-paste-go')?.addEventListener('click', async () => {
        try {
            const text = (await navigator.clipboard.readText()).trim();
            if (!text || (!text.startsWith('http://') && !text.startsWith('https://'))) {
                showToast('Clipboard does not contain a valid http:// or https:// URL.', 'error');
                return;
            }
            const urlInput = document.getElementById('url-input');
            if (urlInput) {
                urlInput.value = text;
                triggerDownloadFromOmnibox();
            }
        } catch (e) {
            showToast('Clipboard access requires browser permission or manual Cmd+V / Ctrl+V.', 'info');
            document.getElementById('url-input')?.focus();
        }
    });

    // Global Paste Anywhere handler
    document.addEventListener('paste', (e) => {
        if (!appState.auth.authenticated) return;
        const activeTag = document.activeElement?.tagName?.toLowerCase();
        if (['input', 'textarea', 'select'].includes(activeTag)) return;

        const pasted = (e.clipboardData || window.clipboardData)?.getData('text')?.trim();
        if (pasted && (pasted.startsWith('http://') || pasted.startsWith('https://'))) {
            const urlInput = document.getElementById('url-input');
            if (urlInput) {
                e.preventDefault();
                urlInput.value = pasted;
                urlInput.focus();
                showToast('URL pasted into command bar.', 'info');
            }
        }
    });

    // Global Drag & Drop Link Handler (Full Page + Top Omnibox)
    const dropOverlay = document.getElementById('drop-zone-overlay');
    const omniboxEl = document.getElementById('download-form');
    let dragDepth = 0;

    function extractDroppedUrl(dt) {
        if (!dt) return '';
        // 1. Check HTML anchor href first if user dragged a linked thumbnail/card
        const htmlData = dt.getData('text/html') || '';
        if (htmlData) {
            const hrefMatch = htmlData.match(/<a[^>]+href=["'](https?:\/\/[^"'\s<>]+)["']/i);
            if (hrefMatch && hrefMatch[1]) return hrefMatch[1].trim();
        }
        // 2. Check standard text/uri-list
        const uriList = dt.getData('text/uri-list') || '';
        if (uriList) {
            const lines = uriList.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
            const firstHttp = lines.find((l) => l.startsWith('http://') || l.startsWith('https://'));
            if (firstHttp) return firstHttp;
        }
        // 3. Fallback to plain text
        const plain = (dt.getData('text/plain') || '').trim();
        if (plain) {
            const urlMatch = plain.match(/https?:\/\/[^\s"'<>]+/i);
            if (urlMatch && urlMatch[0]) return urlMatch[0].trim();
        }
        return '';
    }

    function clearDragVisuals() {
        dragDepth = 0;
        dropOverlay?.classList.add('hidden');
        omniboxEl?.classList.remove('drag-active');
    }

    window.addEventListener('dragenter', (e) => {
        if (!appState.auth.authenticated) return;
        dragDepth += 1;
        dropOverlay?.classList.remove('hidden');
        omniboxEl?.classList.add('drag-active');
        e.preventDefault();
    });

    window.addEventListener('dragover', (e) => {
        if (!appState.auth.authenticated) return;
        e.preventDefault();
        if (e.dataTransfer) {
            e.dataTransfer.dropEffect = 'copy';
        }
    });

    window.addEventListener('dragleave', (e) => {
        if (!appState.auth.authenticated) return;
        dragDepth = Math.max(0, dragDepth - 1);
        if (dragDepth === 0 || e.clientX <= 0 || e.clientY <= 0 || e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
            clearDragVisuals();
        }
    });

    window.addEventListener('dragend', clearDragVisuals);
    window.addEventListener('blur', clearDragVisuals);

    window.addEventListener('drop', (e) => {
        if (!appState.auth.authenticated) return;
        const droppedOnOmnibox = Boolean(e.target?.closest && e.target.closest('#download-form'));
        clearDragVisuals();
        e.preventDefault();

        const droppedUrl = extractDroppedUrl(e.dataTransfer);
        if (!droppedUrl) {
            showToast('Dropped item does not contain a valid http:// or https:// link.', 'error');
            return;
        }

        const urlInput = document.getElementById('url-input');
        if (!urlInput) return;

        urlInput.value = droppedUrl;
        const optionsOpen = optionsDrawer?.classList.contains('open');

        if (droppedOnOmnibox || e.shiftKey || optionsOpen) {
            urlInput.focus();
            showToast('Link dropped into URL bar — review options and click Download.', 'info');
        } else {
            triggerDownloadFromOmnibox();
        }
    });

    // 5. Queue Dock Collapse / Expand
    document.getElementById('btn-collapse-queue')?.addEventListener('click', () => {
        appState.queueCollapsed = true;
        localStorage.setItem('corgio_queue_collapsed', 'true');
        applyQueueDockState();
        showToast('Active Queue collapsed. Click "Show Queue" in toolbar or press Q to restore.', 'info');
    });
    document.getElementById('btn-expand-queue')?.addEventListener('click', () => {
        appState.queueCollapsed = false;
        localStorage.setItem('corgio_queue_collapsed', 'false');
        applyQueueDockState();
    });
    document.getElementById('btn-toggle-queue-header')?.addEventListener('click', () => {
        toggleQueueDock();
    });

    // Delegate clicks inside Active Queue list
    document.getElementById('active-downloads-list')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.getAttribute('data-action');
        const id = btn.getAttribute('data-id');
        if (!id) return;

        if (action === 'logs') openLogModal(id);
        else if (action === 'stop') stopDownloadById(id);
        else if (action === 'purge') openPurgeModal([id]);
    });

    // 6. Media Library Toolbar Controls
    document.getElementById('filter-chips-container')?.addEventListener('click', (e) => {
        const chip = e.target.closest('.chip');
        if (!chip) return;
        appState.activeFilter = chip.getAttribute('data-filter') || 'all';
        renderFilterChips();
        renderLibrary();
        updateBatchBarUI();
    });

    document.getElementById('search-input')?.addEventListener('input', (e) => {
        appState.searchQuery = e.target.value.trim();
        renderLibrary();
        updateBatchBarUI();
    });

    document.getElementById('sort-select')?.addEventListener('change', (e) => {
        appState.sortBy = e.target.value;
        renderLibrary();
    });

    document.getElementById('sort-order-btn')?.addEventListener('click', (e) => {
        appState.sortOrder = appState.sortOrder === 'desc' ? 'asc' : 'desc';
        e.currentTarget.textContent = appState.sortOrder === 'desc' ? '↓' : '↑';
        renderLibrary();
    });

    document.getElementById('btn-view-table')?.addEventListener('click', () => {
        appState.viewMode = 'table';
        localStorage.setItem('corgio_view_mode', 'table');
        renderLibrary();
    });

    document.getElementById('btn-view-grid')?.addEventListener('click', () => {
        appState.viewMode = 'grid';
        localStorage.setItem('corgio_view_mode', 'grid');
        renderLibrary();
    });

    // 7. Batch Mode & Selection Delegation
    document.getElementById('btn-batch-mode')?.addEventListener('click', () => {
        appState.batchMode = !appState.batchMode;
        if (!appState.batchMode) {
            appState.selectedIds.clear();
            renderLibrary();
        }
        updateBatchBarUI();
    });

    document.getElementById('btn-batch-cancel')?.addEventListener('click', () => {
        appState.batchMode = false;
        appState.selectedIds.clear();
        renderLibrary();
        updateBatchBarUI();
    });

    document.getElementById('batch-select-all')?.addEventListener('change', (e) => {
        toggleSelectAllVisible(e.target.checked);
    });

    document.getElementById('table-select-all')?.addEventListener('change', (e) => {
        toggleSelectAllVisible(e.target.checked);
    });

    document.getElementById('btn-batch-retry')?.addEventListener('click', async () => {
        const ids = Array.from(appState.selectedIds);
        if (ids.length === 0) return;
        let retried = 0;
        for (const id of ids) {
            const item = appState.libraryItems.find((i) => String(i.id) === id);
            if (item && (item.status === 'failed' || item.status === 'stopped')) {
                await retryDownloadById(id);
                retried += 1;
            }
        }
        if (retried === 0) {
            showToast('No failed or stopped items among selection.', 'info');
        }
    });

    document.getElementById('btn-batch-delete')?.addEventListener('click', () => {
        const ids = Array.from(appState.selectedIds);
        if (ids.length === 0) {
            showToast('Select at least one item to purge.', 'info');
            return;
        }
        openPurgeModal(ids);
    });

    // Delegate actions & checkboxes inside Library Scroll Area
    const libraryScroll = document.querySelector('.library-scroll');
    libraryScroll?.addEventListener('change', (e) => {
        if (e.target.classList.contains('item-checkbox')) {
            const id = e.target.getAttribute('data-id');
            if (!id) return;
            if (e.target.checked) {
                appState.selectedIds.add(id);
            } else {
                appState.selectedIds.delete(id);
            }
            renderLibrary();
            updateBatchBarUI();
        }
    });

    libraryScroll?.addEventListener('click', (e) => {
        if (e.target.closest('[data-stop-prop="true"]') || e.target.classList.contains('item-checkbox')) {
            return;
        }
        const actionEl = e.target.closest('[data-action]');
        if (!actionEl) return;
        const action = actionEl.getAttribute('data-action');
        const id = actionEl.getAttribute('data-id');
        if (!id) return;

        if (action === 'play') openPlayerModal(id);
        else if (action === 'info') openMetadataModal(id);
        else if (action === 'retry') retryDownloadById(id);
        else if (action === 'logs') openLogModal(id);
        else if (action === 'purge') openPurgeModal([id]);
    });

    // 8. System Drawer Actions
    document.getElementById('check-updates-btn')?.addEventListener('click', () => checkComponentUpdates(true));
    document.getElementById('update-btn')?.addEventListener('click', runEngineUpdate);
    document.getElementById('view-update-logs-btn')?.addEventListener('click', () => openUpdateModal(false));
    document.getElementById('scan-btn')?.addEventListener('click', runFolderScan);
    document.getElementById('refresh-logs-btn')?.addEventListener('click', fetchActivityLogs);
    document.getElementById('clear-logs-btn')?.addEventListener('click', clearAllActivityLogs);

    document.getElementById('activity-logs-tbody')?.addEventListener('click', (e) => {
        const row = e.target.closest('tr[data-log-index]');
        if (!row) return;
        const idx = Number(row.getAttribute('data-log-index'));
        openActivityDetailModal(idx);
    });

    // 9. Modal Close Handlers
    document.getElementById('close-player')?.addEventListener('click', closePlayerModal);
    document.getElementById('close-log')?.addEventListener('click', closeLogModal);
    document.getElementById('copy-log-btn')?.addEventListener('click', () => {
        const text = document.getElementById('log-content')?.textContent || '';
        navigator.clipboard.writeText(text).then(() => {
            showToast('Console output copied to clipboard.', 'info');
        }).catch(() => {});
    });
    document.getElementById('close-update-modal')?.addEventListener('click', closeUpdateModal);
    document.getElementById('copy-update-log-btn')?.addEventListener('click', () => {
        const text = document.getElementById('update-log-content')?.textContent || '';
        navigator.clipboard.writeText(text).then(() => {
            showToast('Update console output copied to clipboard.', 'info');
        }).catch(() => {});
    });
    document.getElementById('close-metadata')?.addEventListener('click', () => {
        document.getElementById('metadata-modal')?.classList.add('hidden');
    });
    document.getElementById('cancel-delete')?.addEventListener('click', closePurgeModal);
    document.getElementById('cancel-delete-top')?.addEventListener('click', closePurgeModal);
    document.getElementById('confirm-delete')?.addEventListener('click', executeConfirmedPurge);
    document.getElementById('close-activity-detail')?.addEventListener('click', () => {
        document.getElementById('activity-detail-modal')?.classList.add('hidden');
    });

    // Close modals on backdrop click or Escape key
    document.querySelectorAll('.modal').forEach((modalEl) => {
        modalEl.addEventListener('click', (e) => {
            if (e.target === modalEl) {
                if (modalEl.id === 'auth-modal') return;
                if (modalEl.id === 'account-modal') {
                    closeAccountModal();
                    return;
                }
                if (modalEl.id === 'player-modal') closePlayerModal();
                else if (modalEl.id === 'log-modal') closeLogModal();
                else if (modalEl.id === 'update-modal') closeUpdateModal();
                else if (modalEl.id === 'delete-modal') closePurgeModal();
                else modalEl.classList.add('hidden');
            }
        });
    });

    document.addEventListener('keydown', (e) => {
        // Toggle Queue dock with 'q' when not typing in an input
        if ((e.key === 'q' || e.key === 'Q') && !e.ctrlKey && !e.metaKey && !e.altKey) {
            const tag = document.activeElement?.tagName;
            if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT' && !document.activeElement?.isContentEditable) {
                const anyModalOpen = document.querySelector('.modal-backdrop:not(.hidden)');
                if (!anyModalOpen) {
                    e.preventDefault();
                    toggleQueueDock();
                }
            }
        }

        if (e.key === 'Escape') {
            closePlayerModal();
            closeLogModal();
            closeUpdateModal();
            closePurgeModal();
            closeAccountModal();
            document.getElementById('metadata-modal')?.classList.add('hidden');
            document.getElementById('activity-detail-modal')?.classList.add('hidden');
            document.getElementById('theme-modal')?.classList.add('hidden');
        }
    });

    // Delegated image fallback handler (M4: avoids inline onerror handlers for strict CSP)
    document.addEventListener(
        'error',
        (e) => {
            const target = e.target;
            if (
                target &&
                target.tagName === 'IMG' &&
                target.classList.contains('media-thumb-img') &&
                !target.src.endsWith('/static/fallback-icon.svg')
            ) {
                target.src = '/static/fallback-icon.svg';
            }
        },
        true
    );

    // 10. User Account Sign-In, Password Change & Sign-Out Handlers (H1)
    document.getElementById('auth-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const userInput = document.getElementById('auth-username-input');
        const passInput = document.getElementById('auth-password-input');
        const remInput = document.getElementById('auth-remember-input');
        const submitBtn = document.getElementById('auth-submit-btn');

        const username = userInput?.value.trim() || '';
        const password = passInput?.value || '';
        const remember = remInput ? Boolean(remInput.checked) : true;
        if (!username || !password) return;

        if (submitBtn) submitBtn.disabled = true;
        try {
            const res = await apiFetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, remember })
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || 'Invalid username or password');
            }
            const data = await res.json();
            appState.auth.authenticated = true;
            appState.auth.username = data.username || username;
            appState.auth.mustChangePassword = Boolean(data.must_change_password);
            appState.auth.lastLoginPassword = appState.auth.mustChangePassword ? password : '';

            if (passInput) passInput.value = '';
            updateAccountHeaderUI();
            document.getElementById('auth-modal')?.classList.add('hidden');
            document.querySelector('.app-shell')?.classList.remove('hidden');
            showToast(`Signed in as ${appState.auth.username}.`, 'success');

            if (appState.auth.mustChangePassword) {
                openAccountModal(true);
            } else {
                loadWorkspaceData();
            }
        } catch (err) {
            showToast(err.message || 'Sign-in failed', 'error');
        } finally {
            if (submitBtn) submitBtn.disabled = false;
        }
    });

    document.getElementById('btn-open-account-modal')?.addEventListener('click', () => {
        openAccountModal(appState.auth.mustChangePassword);
    });
    document.getElementById('close-account-modal')?.addEventListener('click', closeAccountModal);
    document.getElementById('cancel-account-modal')?.addEventListener('click', closeAccountModal);

    document.getElementById('account-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const wasForced = appState.auth.mustChangePassword;
        const newUsername = document.getElementById('account-username-input')?.value.trim() || '';
        const currentPassword = document.getElementById('account-current-password')?.value || '';
        const newPassword = document.getElementById('account-new-password')?.value || '';
        const confirmPassword = document.getElementById('account-confirm-password')?.value || '';
        const saveBtn = document.getElementById('save-account-btn');

        if (!currentPassword || !newPassword) {
            showToast('Please enter both your current password and a new password.', 'error');
            return;
        }
        if (newPassword.length < 6) {
            showToast('New password must be at least 6 characters long.', 'error');
            return;
        }
        if (newPassword !== confirmPassword) {
            showToast('New password and confirmation do not match.', 'error');
            return;
        }

        if (saveBtn) saveBtn.disabled = true;
        try {
            const res = await apiFetch(`${API_BASE}/auth/account`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_username: newUsername,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                })
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || 'Could not update credentials');
            }
            const data = await res.json();
            appState.auth.username = data.username || newUsername;
            appState.auth.mustChangePassword = false;
            appState.auth.lastLoginPassword = '';
            updateAccountHeaderUI();
            document.getElementById('account-modal')?.classList.add('hidden');
            showToast('Account credentials updated and sessions rotated.', 'success');
            if (wasForced) {
                loadWorkspaceData();
            }
        } catch (err) {
            showToast(err.message || 'Error updating credentials', 'error');
        } finally {
            if (saveBtn) saveBtn.disabled = false;
        }
    });

    document.getElementById('btn-logout')?.addEventListener('click', async () => {
        try {
            await apiFetch(`${API_BASE}/auth/logout`, { method: 'POST' });
        } catch (e) {
            // Ignore network errors during logout
        }
        appState.auth.lastLoginPassword = '';
        document.getElementById('account-modal')?.classList.add('hidden');
        setDrawerState(null);
        showSignInGate();
        showToast('Signed out.', 'info');
    });

    // 11. Check Authentication Status & Initialize Workspace (M8: no external PyPI calls on page load)
    checkAuthStatusAndInit();
});
