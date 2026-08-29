// DomainLens - Frontend Logic

let scanData = null;
let currentScanId = null;
let monitorsDrawerOpen = false;

function t(key, vars) {
    if (window.DomainLensI18n && typeof window.DomainLensI18n.t === 'function') {
        return window.DomainLensI18n.t(key, vars);
    }
    return key;
}

function updateLoadingText(domain) {
    const el = $('loadingText');
    if (el) el.textContent = t('loading.scanning', { domain: domain || '' });
}

function updateResultsTitle(domain) {
    const el = $('resultsTitle');
    if (el) el.textContent = t('results.title', { domain: domain || '' });
}

// ===== Helpers =====
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function $(id) { return document.getElementById(id); }

function showError(msg) {
    const toast = $('errorToast');
    toast.textContent = msg;
    toast.classList.remove('toast-success');
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 5000);
}

function formatFrequency(minutes) {
    const n = Number(minutes) || 0;
    if (n === 15) return 'every 15 minutes';
    if (n === 30) return 'every 30 minutes';
    if (n === 60) return 'hourly';
    if (n === 360) return 'every 6 hours';
    if (n === 720) return 'every 12 hours';
    if (n === 1440) return 'daily';
    if (n === 10080) return 'weekly';
    if (n % 1440 === 0) return `every ${n / 1440} day(s)`;
    if (n % 60 === 0) return `every ${n / 60} hour(s)`;
    return `every ${n} min`;
}

function showToast(msg) {
    const toast = $('errorToast');
    toast.textContent = msg;
    toast.classList.add('toast-success');
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
        toast.classList.remove('toast-success');
    }, 4000);
}

function handleAuthFailure(resp, data) {
    if (resp && resp.status === 401) {
        const loginUrl = (data && data.login_url) || '/login';
        window.location.href = loginUrl + '?next=' + encodeURIComponent(window.location.pathname);
        return true;
    }
    return false;
}

// ===== Event Listeners (no inline handlers) =====
// Bind only when the element is on this page. app.js is shared by the scan
// page, monitoring and reports, so a missing node is normal — and one
// unguarded lookup used to throw and silently kill every binding after it.
function on(id, event, handler) {
    const el = $(id);
    if (el) el.addEventListener(event, handler);
    return el;
}

document.addEventListener('DOMContentLoaded', async () => {
    if (window.DomainLensI18n) {
        // Never let a translation failure abort the rest of this handler —
        // everything below (tabs, scan button, monitoring) depends on it.
        try {
            await DomainLensI18n.init(DomainLensI18n.pageLocale());
        } catch (e) {
            console.error('i18n init failed; continuing without translations', e);
        }
    }
    // Pick up a scan that was still running when this page was last left.
    resumeScanIfRunning();
    openFromQuery();
    // Tab navigation
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            $('tab-' + tab.dataset.tab).classList.add('active');
        });
    });

    // Enter key triggers scan
    on('domainInput', 'keydown', e => {
        if (e.key === 'Enter') startScan();
    });

    // Scan button
    on('scanBtn', 'click', startScan);

    // Custom DKIM selectors: remembered per browser via localStorage, so a
    // selector you've discovered for one domain (e.g. "zmail" for Zoho) is
    // still there next time without needing an admin-settings change.
    initCustomDkimSelectors();

    // Export menu
    const exportBtn = $('exportBtn');
    const exportDropdown = $('exportDropdown');
    if (exportBtn && exportDropdown) {
        exportBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const open = exportDropdown.classList.toggle('hidden') === false;
            exportBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
        exportDropdown.querySelectorAll('[data-export]').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportDropdown.classList.add('hidden');
                exportBtn.setAttribute('aria-expanded', 'false');
                exportResults(btn.getAttribute('data-export') || 'json');
            });
        });
        document.addEventListener('click', () => {
            exportDropdown.classList.add('hidden');
            exportBtn.setAttribute('aria-expanded', 'false');
        });
    }

    // Report button
    on('reportBtn', 'click', openReport);

    // History drawer
    on('historyBtn', 'click', openHistory);
    on('historyCloseBtn', 'click', closeHistory);
    on('monitorsBtn', 'click', openMonitors);
    on('monitorsCloseBtn', 'click', closeMonitors);
    on('drawerOverlay', 'click', () => {
        closeHistory();
        closeMonitors();
    });
    on('historyClearBtn', 'click', clearHistory);
    on('createMonitorBtn', 'click', createMonitor);
    on('importMonitorsBtn', 'click', importMonitors);
    on('runDueBtn', 'click', runDueMonitors);
    on('importModeInput', 'change', syncImportMode);

    // Schedule preset dropdown: sets the underlying minutes value directly,
    // or reveals a free-entry field when "Custom..." is picked. Both
    // "Create monitor" and "Import DNS records" read the same hidden
    // #monitorScheduleInput value.
    const schedulePreset = $('monitorSchedulePreset');
    const scheduleCustom = $('monitorScheduleInput');
    if (schedulePreset && scheduleCustom) {
        schedulePreset.addEventListener('change', () => {
            if (schedulePreset.value === 'custom') {
                scheduleCustom.classList.remove('hidden');
                scheduleCustom.focus();
            } else {
                scheduleCustom.classList.add('hidden');
                scheduleCustom.value = schedulePreset.value;
            }
        });
        // Initialize the hidden field to match the default preset (Daily).
        scheduleCustom.value = schedulePreset.value;
    }
    const rapid7UploadBtn = $('rapid7UploadBtn');
    if (rapid7UploadBtn) rapid7UploadBtn.addEventListener('click', uploadRapid7Export);
    const rapid7SyncBtn = $('rapid7SyncBtn');
    if (rapid7SyncBtn) rapid7SyncBtn.addEventListener('click', syncRapid7Api);

    // On their own pages the panels are simply present, so nothing clicks
    // them open — they load their data on arrival instead.
    if (document.querySelector('#monitorsDrawer.page-panel')) loadMonitors();
    if (document.querySelector('#historyDrawer.page-panel')) loadHistory();

    // Everything below belongs to the scan form, which only exists on the
    // scan page. Bail out here rather than guarding each line.
    const checkToggle = $('checkToggle');
    const checkGroups = $('checkGroups');
    const allCheckbox = document.querySelector('input[value="all"]');
    if (!checkToggle || !checkGroups || !allCheckbox) return;

    // Expand / collapse the specific-check groups
    checkToggle.addEventListener('click', () => {
        const isHidden = checkGroups.classList.toggle('hidden');
        checkToggle.setAttribute('aria-expanded', String(!isHidden));
    });

    // Reflect the "Full scan" state visually and keep the groups dimmed while active
    function syncAllState() {
        checkGroups.classList.toggle('all-active', allCheckbox.checked);
    }

    // "Full scan" master toggle
    allCheckbox.addEventListener('change', () => {
        if (allCheckbox.checked) {
            document.querySelectorAll('.check-item, .group-all').forEach(i => { i.checked = false; });
        }
        syncAllState();
    });

    // Group-level toggle: check/uncheck every item in the group
    document.querySelectorAll('.group-all').forEach(groupCb => {
        groupCb.addEventListener('change', () => {
            const group = groupCb.dataset.group;
            const items = document.querySelectorAll(`.check-group[data-group="${group}"] .check-item`);
            items.forEach(i => { i.checked = groupCb.checked; });
            if (groupCb.checked) allCheckbox.checked = false;
            syncAllState();
        });
    });

    // Individual checkbox: unchecks "Full scan", syncs its group toggle
    document.querySelectorAll('.check-item').forEach(cb => {
        cb.addEventListener('change', () => {
            if (cb.checked) allCheckbox.checked = false;
            const groupEl = cb.closest('.check-group');
            if (groupEl) {
                const group = groupEl.dataset.group;
                const items = groupEl.querySelectorAll('.check-item');
                const groupCb = groupEl.querySelector('.group-all');
                if (groupCb) groupCb.checked = Array.from(items).every(i => i.checked);
            }
            syncAllState();
        });
    });

    syncAllState();
});

// The overlay belongs to the drawers, and the drawers only exist on their
// own pages. Reaching for it elsewhere threw, and the throw surfaced as
// whatever the calling function's catch happened to say.
function showOverlay() {
    const overlay = $('drawerOverlay');
    if (overlay) overlay.classList.remove('hidden');
}

function syncOverlay() {
    const overlay = $('drawerOverlay');
    if (!overlay) return;
    const open = drawer => drawer && !drawer.classList.contains('hidden');
    overlay.classList.toggle(
        'hidden', !(open($('historyDrawer')) || open($('monitorsDrawer'))));
}

// ===== Export Results =====
function exportResults(format) {
    format = format || 'json';
    if (format === 'report') {
        openReport();
        return;
    }
    if (currentScanId && (format === 'markdown' || format === 'csv' || format === 'json')) {
        const url = `/api/reports/${currentScanId}/export?format=${encodeURIComponent(format === 'json' ? 'json-download' : format)}`;
        window.open(url, '_blank', 'noopener');
        return;
    }
    // Fallback: client-side JSON of in-memory scan
    if (!scanData) return;
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `domainlens-${scanData.domain}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Deep links into the scan page. /remediate/domain/<d> has always linked here
// with ?domain=&tab=advies, and nothing read either parameter — so the button
// labelled "Scan & open Advies" opened an empty search box. ServiceNow's deep
// links landed the same way.
//
// The tab names in those links are the ones a person would write, not the
// internal data-tab values, so they are mapped rather than assumed to match.
const QUERY_TAB_ALIASES = {
    advies: 'recommendations',
    advice: 'recommendations',
    recommendations: 'recommendations',
    findings: 'recommendations',
    security: 'security',
    whois: 'whois',
    dns: 'dns',
    email: 'email',
    ssl: 'ssl',
    tls: 'ssl',
    web: 'web',
    network: 'network',
    osint: 'osint',
    rapid7: 'rapid7',
    hubspot: 'hubspot',
};

let pendingTab = null;

function selectTab(name) {
    const tab = document.querySelector(`.tab[data-tab="${name}"]`);
    if (!tab || tab.closest('.tab-group.hidden')) return false;
    tab.click();
    return true;
}

function openFromQuery() {
    const params = new URLSearchParams(window.location.search);
    const wanted = (params.get('tab') || '').trim().toLowerCase();
    if (wanted) pendingTab = QUERY_TAB_ALIASES[wanted] || wanted;

    // A stored scan opens as it was, without scanning again.
    const stored = (params.get('scan') || '').trim();
    if (stored && $('domainInput')) {
        loadScan(stored);
        return;
    }

    const domain = (params.get('domain') || '').trim();
    const input = $('domainInput');
    if (!domain || !input) return;
    input.value = domain;
    // Never start a second scan on top of one already running in this
    // browser; resumeScanIfRunning() is re-attaching to it.
    if (readJob()) return;
    startScan();
}

// ===== Start Scan =====
// An address is not a domain, and the scan pipeline rejects it outright with
// "Invalid domain name". Typing one in the search box is a reasonable thing
// to do, so it goes to the tool that can answer instead of to an error.
function looksLikeIp(value) {
    const v = (value || '').trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
        return v.split('.').every(part => Number(part) <= 255);
    }
    return v.includes(':') && /^[0-9a-f:.]+$/i.test(v) && !v.includes('/');
}

async function startScan() {
    const domain = $('domainInput').value.trim();
    if (!domain) {
        showError(t('errors.no_domain'));
        return;
    }
    if (looksLikeIp(domain)) {
        window.location.href = '/tools/ip?ip=' + encodeURIComponent(domain);
        return;
    }

    const allChecked = document.querySelector('input[value="all"]').checked;
    let checks = ['all'];
    if (!allChecked) {
        checks = Array.from(document.querySelectorAll('.check-item:checked')).map(c => c.value);
        if (checks.length === 0) checks = ['all'];
    }

    // Custom DKIM selectors: checked in addition to the built-in list.
    // Saved to localStorage on this device so they're remembered next time.
    const dkimSelectors = getCustomDkimSelectors();

    showScanning(domain);

    try {
        const resp = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain, checks, dkim_selectors: dkimSelectors,
                force_refresh: !!($('forceRefreshInput') || {}).checked,
            }),
        });
        const data = await resp.json();

        if (handleAuthFailure(resp, data)) return;
        // 409 means a scan for this domain is already running — adopt it
        // rather than refusing, which is what the user wanted anyway.
        if (!resp.ok && resp.status !== 409) {
            showError(data.error || `Scan failed (${resp.status})`);
            hideScanning();
            return;
        }
        if (!data.job_id) {
            showError(data.error || 'Scan could not be started');
            hideScanning();
            return;
        }
        rememberJob(data.job_id, domain);
        await followJob(data.job_id);
    } catch (err) {
        showError(t('errors.network'));
        hideScanning();
    }
}


// ===== Scan job tracking =====
// A scan runs server-side, so the page can be left and returned to. The job
// id lives in sessionStorage; on load we re-attach to it, and if that job is
// gone we ask the server whether one is still running for the domain.
const SCAN_JOB_KEY = 'domainlens_active_scan_job';
let scanPollTimer = null;

function rememberJob(jobId, domain) {
    try {
        sessionStorage.setItem(SCAN_JOB_KEY, JSON.stringify({ jobId, domain }));
    } catch (e) { /* private mode: tracking is best-effort */ }
}

function forgetJob() {
    try { sessionStorage.removeItem(SCAN_JOB_KEY); } catch (e) { /* ignore */ }
}

function readJob() {
    try { return JSON.parse(sessionStorage.getItem(SCAN_JOB_KEY) || 'null'); }
    catch (e) { return null; }
}

// The progress bar belongs to the scan page, but "Run now" on /monitoring
// drives the same job through these helpers. Every node is therefore
// optional: an unguarded lookup threw a TypeError that runMonitorScan's
// catch relabelled as "Network error" for a scan that had in fact started.
function showScanning(domain) {
    const box = $('loading');
    if (box) box.classList.remove('hidden');
    const label = $('loadingDomain');
    if (label) label.textContent = domain;
    updateLoadingText(domain);
    const results = $('results');
    if (results) results.classList.add('hidden');
    const btn = $('scanBtn');
    if (btn) btn.disabled = true;
    setProgress(0, null);
}

function hideScanning() {
    const box = $('loading');
    if (box) box.classList.add('hidden');
    const btn = $('scanBtn');
    if (btn) btn.disabled = false;
    // Not guarded by the nodes above: the poll timer runs on every page that
    // can start a job, and leaving it armed keeps polling a finished scan.
    if (scanPollTimer) { clearTimeout(scanPollTimer); scanPollTimer = null; }
}

function setProgress(percent, step) {
    const fill = $('scanProgressFill');
    const pct = $('scanPercent');
    const stepEl = $('scanStep');
    if (fill) fill.style.width = `${Math.max(0, Math.min(100, percent || 0))}%`;
    if (pct) pct.textContent = `${Math.round(percent || 0)}%`;
    if (stepEl) stepEl.textContent = step ? `· ${step.replace(/_/g, ' ')}` : '';
}

// A monitor job returns {monitor, scan_id, results, event}; a plain scan
// returns the results directly. Unwrapping in one place keeps both kinds of
// scan on the same tracking, resuming and progress code.
function jobResults(job) {
    const payload = (job && job.result) || null;
    if (!payload) return null;
    return payload.results || payload;
}

function jobScanId(job) {
    const payload = (job && job.result) || {};
    return payload.scan_id || (payload.results && payload.results.scan_id) || null;
}

async function followJob(jobId, options) {
    const opts = options || {};
    return new Promise(resolve => {
        const poll = async () => {
            let job;
            try {
                const resp = await fetch('/api/scan/status/' + encodeURIComponent(jobId));
                if (resp.status === 404) {
                    forgetJob();
                    hideScanning();
                    if (opts.onProgress) opts.onProgress(null);
                    return resolve();
                }
                job = await resp.json();
            } catch (e) {
                // A transient network blip must not abandon a running scan.
                scanPollTimer = setTimeout(poll, 2000);
                return;
            }

            setProgress(job.percent, job.current);
            if (opts.onProgress) opts.onProgress(job);

            if (job.status === 'running') {
                scanPollTimer = setTimeout(poll, 1000);
                return;
            }
            forgetJob();
            hideScanning();
            if (job.status === 'error') {
                showError(job.error || 'Scan failed');
            } else {
                const results = jobResults(job);
                if (results) {
                    scanData = results;
                    currentScanId = jobScanId(job);
                    // Only the scan page has a pane to render into. On
                    // /monitoring rendering threw mid-poll, so this promise
                    // never resolved and the button stayed on "Scanning…".
                    if ($('results')) renderResults(results);
                }
            }
            if (opts.onDone) opts.onDone(job);
            resolve();
        };
        poll();
    });
}

// Re-attach to a scan that was still running when the page was left.
async function resumeScanIfRunning() {
    const stored = readJob();
    if (!stored || !stored.jobId) return;
    try {
        const resp = await fetch('/api/scan/status/' + encodeURIComponent(stored.jobId));
        if (resp.status === 404) { forgetJob(); return; }
        const job = await resp.json();
        if (job.status === 'running') {
            $('domainInput').value = stored.domain || job.domain || '';
            showScanning(job.domain || stored.domain);
            setProgress(job.percent, job.current);
            followJob(stored.jobId);
        } else if (job.status === 'done' && jobResults(job)) {
            // Finished while we were away — show it instead of losing it.
            forgetJob();
            $('domainInput').value = job.domain || '';
            scanData = jobResults(job);
            currentScanId = jobScanId(job);
            renderResults(scanData);
        } else {
            forgetJob();
        }
    } catch (e) {
        /* offline: leave the stored job for the next attempt */
    }
}

// ===== Custom DKIM selectors (saved locally per browser) =====
const DKIM_SELECTORS_STORAGE_KEY = 'domainlens_custom_dkim_selectors';

function getCustomDkimSelectors() {
    const el = $('customDkimSelectors');
    if (!el || !el.value.trim()) return [];
    return el.value.split(',').map(s => s.trim()).filter(Boolean);
}

function initCustomDkimSelectors() {
    const el = $('customDkimSelectors');
    if (!el) return;
    try {
        const saved = localStorage.getItem(DKIM_SELECTORS_STORAGE_KEY);
        if (saved) el.value = saved;
    } catch (e) {
        // localStorage unavailable (private browsing etc.) — field just won't persist.
    }
    el.addEventListener('change', () => {
        try {
            localStorage.setItem(DKIM_SELECTORS_STORAGE_KEY, el.value.trim());
        } catch (e) {
            // Ignore storage errors — the field still works for the current session.
        }
    });
}

// ===== Render Results =====
// The Platform group covers checks that only mean something on a specific
// stack — HubSpot behind Cloudflare, and the CDN-specific hardening advice.
// On a site running none of them the tab is permanently empty, which reads
// as "we looked and found nothing wrong" rather than "this does not apply".
function platformDetected(data) {
    const hubspot = data.hubspot_cf || {};
    if (hubspot.hubspot?.detected || hubspot.cloudflare?.detected) return true;
    if (hubspot.detected) return true;
    const cdn = data.cdn || {};
    return Boolean(cdn.id && cdn.id !== 'generic');
}

function syncPlatformGroup(data) {
    const group = $('tabGroupPlatform');
    if (!group) return;
    const show = platformDetected(data);
    group.classList.toggle('hidden', !show);
    if (!show && group.querySelector('.tab.active')) {
        // Never leave the reader staring at a tab that just disappeared.
        document.querySelector('.tab[data-tab="recommendations"]')?.click();
    }
}

function renderResults(data) {
    syncPlatformGroup(data);
    if (pendingTab) {
        // After the render: there is nothing for the tab to show before it.
        const wanted = pendingTab;
        pendingTab = null;
        setTimeout(() => selectTab(wanted), 0);
    }
    const isSubdomain = data.apex_domain && data.apex_domain !== data.domain;
    $('resultDomain').textContent = data.domain;
    updateResultsTitle(data.domain);
    const apexNote = $('apexNote');
    if (apexNote) {
        if (isSubdomain) {
            apexNote.textContent = `Email & WHOIS checked on apex domain: ${data.apex_domain}`;
            apexNote.classList.remove('hidden');
        } else {
            apexNote.classList.add('hidden');
        }
    }
    $('resultTimestamp').textContent = new Date(data.timestamp).toLocaleString();

    renderScoreOverview(data);
    renderRecommendations(data);
    renderRemediationPlan(data);
    renderHttpDeep(data.http_deep);
    renderWhois(data.whois);
    renderDns(data.dns);
    renderDnssec(data.dnssec);
    renderSpf(data.spf);
    renderDmarc(data.dmarc);
    renderDkim(data.dkim);
    renderMtaSts(data.mta_sts);
    renderTlsrpt(data.tlsrpt);
    renderSsl(data.ssl);
    renderTlsDeep(data.tls_deep);
    renderNcscTls(data.ncsc_tls);
    renderHttpsRedirect(data.https_redirect);
    renderHeaders(data.http_headers);
    renderIpv6(data.ipv6);
    renderBlacklist(data.blacklist);
    renderPorts(data.ports);
    renderSecurity(data.security);
    renderOsint(data.osint);
    renderHubspot(data.hubspot_cf);
    renderWeakAuth(data.weak_auth);
    renderJsScan(data.js_scan);
    renderActiveScan(data.active_scan);
    renderRapid7(data.rapid7);

    document.querySelectorAll('.tab')[0].click();
    $('results').classList.remove('hidden');
}

// ===== Score Overview =====
function renderScoreOverview(data) {
    const grid = $('scoreGrid');
    grid.innerHTML = '';

    const checks = [
        { label: 'DNSSEC', pass: data.dnssec?.signed },
        { label: 'SPF', pass: data.spf?.pass },
        { label: 'DMARC', pass: data.dmarc?.pass },
        { label: 'DKIM', pass: data.dkim?.pass },
        { label: 'MTA-STS', pass: data.mta_sts?.pass },
        { label: 'TLS-RPT', pass: data.tlsrpt?.pass },
        { label: 'HTTPS', pass: data.https_redirect?.pass === true, warn: data.https_redirect?.pass === null || data.https_redirect?.blocked },
        { label: 'SSL Valid', pass: data.ssl?.success && !data.ssl?.expired },
        { label: 'TLS Grade', pass: data.tls_deep?.grade && ['A+', 'A'].includes(data.tls_deep.grade), warn: data.tls_deep?.grade === 'B' },
        { label: 'NCSC TLS', pass: data.ncsc_tls?.pass === true, warn: data.ncsc_tls?.success && data.ncsc_tls?.overall_level === 'phased_out' },
        {
            label: 'Cipher order',
            pass: !data.tls_deep?.cipher_order ? undefined :
                (data.tls_deep.cipher_order.applicable === false || data.tls_deep.cipher_order.pass === true),
            warn: !!(data.tls_deep?.cipher_order?.applicable && data.tls_deep.cipher_order.pass == null),
        },
        { label: 'HSTS', pass: data.tls_deep?.hsts?.enabled === true, warn: data.tls_deep?.hsts?.enabled == null || data.tls_deep?.hsts?.blocked },
        { label: 'Fwd Secrecy', pass: data.tls_deep?.cipher_summary?.forward_secrecy > 0 },
        { label: 'Headers', pass: data.http_headers?.score >= 50, warn: data.http_headers?.blocked || (data.http_headers?.score >= 25 && data.http_headers?.score < 50) },
        { label: 'IPv6 Web', pass: data.ipv6?.web_pass },
        { label: 'IPv6 Mail', pass: data.ipv6?.mail_pass },
        { label: 'Blacklist', pass: data.blacklist && !data.blacklist?.is_listed },
        { label: 'OSINT Clean', pass: data.osint?.summary && !data.osint.summary.listed_in_threat_feeds },
        { label: 'HubSpot/CF', pass: data.hubspot_cf?.success && data.hubspot_cf?.pass !== false, warn: data.hubspot_cf?.success && data.hubspot_cf?.pass === false },
        {
            label: 'Weak auth',
            pass: data.weak_auth?.skipped ? undefined : (data.weak_auth?.weak_credentials_found === false),
            warn: data.weak_auth?.skipped,
        },
    ];

    checks.forEach(c => {
        if (c.pass === undefined && !c.warn) return;
        const div = document.createElement('div');
        div.className = 'score-item';

        let badgeClass, badgeText;
        if (c.pass) { badgeClass = 'badge-pass'; badgeText = 'Pass'; }
        else if (c.warn) { badgeClass = 'badge-warn'; badgeText = 'Partial'; }
        else { badgeClass = 'badge-fail'; badgeText = 'Fail'; }

        const labelDiv = document.createElement('div');
        labelDiv.className = 'label';
        labelDiv.textContent = c.label;

        const span = document.createElement('span');
        span.className = 'badge ' + badgeClass;
        span.textContent = badgeText;

        div.appendChild(labelDiv);
        div.appendChild(span);
        grid.appendChild(div);
    });

    $('scoreOverview').classList.toggle('hidden', grid.children.length === 0);
}

// ===== WHOIS =====
function renderWhois(data) {
    const el = $('whoisContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'WHOIS lookup failed')}</p>`;
        return;
    }
    const d = data.data;
    let rows = '';
    const labels = {
        domain_name: 'Domain', registrar: 'Registrar', whois_server: 'WHOIS Server',
        creation_date: 'Created', expiration_date: 'Expires', updated_date: 'Updated',
        name_servers: 'Name Servers', status: 'Status', emails: 'Contact',
        dnssec: 'DNSSEC', org: 'Organization', country: 'Country',
    };
    for (const [key, label] of Object.entries(labels)) {
        if (d[key] !== undefined && d[key] !== null) {
            let val = d[key];
            if (Array.isArray(val)) {
                val = val.map(v => escapeHtml(v)).join('<br>');
            } else {
                val = escapeHtml(val);
            }
            rows += `<tr><th>${escapeHtml(label)}</th><td>${val}</td></tr>`;
        }
    }
    el.innerHTML = `<table class="data-table">${rows}</table>`;
}

// ===== DNS =====
function renderDns(data) {
    const el = $('dnsContent');
    if (!data || Object.keys(data).length === 0) {
        el.innerHTML = '<p class="status status-fail">No DNS records found</p>';
        return;
    }
    let html = '';
    const order = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA', 'PTR'];
    for (const rtype of order) {
        if (!data[rtype]) continue;
        data[rtype].forEach(val => {
            html += `<div class="dns-record"><span class="record-type">${escapeHtml(rtype)}</span><span class="dns-value">${escapeHtml(val)}</span></div>`;
        });
    }
    el.innerHTML = html;
}

// ===== DNSSEC =====
function renderDnssec(data) {
    const el = $('dnssecContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    const cls = data.signed ? 'status-pass' : 'status-fail';
    let html = `<p class="status ${cls}">${escapeHtml(data.status)}</p>`;
    html += `<table class="data-table">
        <tr><th>DNSKEY</th><td>${data.has_dnskey ? 'Found' : 'Not found'}</td></tr>
        <tr><th>DS Record</th><td>${data.has_ds ? 'Found' : 'Not found'}</td></tr>
    </table>`;
    el.innerHTML = html;
}

// ===== SPF =====
function renderSpf(data) {
    const el = $('spfContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No SPF record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    let msg = data.strict ? 'Strict policy (-all)' : data.pass ? 'SPF configured' : 'Weak SPF policy';
    if (data.multiple_records) msg = 'Multiple SPF records published — PermError, SPF is ignored entirely';
    let html = `<p class="status ${cls}">${escapeHtml(msg)}</p>`;
    (data.records && data.records.length > 1 ? data.records : [data.record]).forEach(r => {
        html += `<div class="record-box">${escapeHtml(r)}</div>`;
    });
    el.innerHTML = html;
}

// ===== DMARC =====
function renderDmarc(data) {
    const el = $('dmarcContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No DMARC record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    let msg = `Policy: ${escapeHtml(data.policy)}`;
    if (data.multiple_records) msg = 'Multiple DMARC records published — receivers ignore DMARC entirely';
    let html = `<p class="status ${cls}">${msg}</p>`;
    (data.records && data.records.length > 1 ? data.records : [data.record]).forEach(r => {
        html += `<div class="record-box">${escapeHtml(r)}</div>`;
    });
    el.innerHTML = html;
}

// ===== DKIM =====
function renderDkim(data) {
    const el = $('dkimContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No DKIM records found (checked common selectors)</p>';
        return;
    }
    const active = data.selectors.filter(s => !s.revoked);
    const cls = data.pass ? 'status-pass' : 'status-warn';
    let html = `<p class="status ${cls}">${active.length} active selector(s) found${active.length !== data.selectors.length ? `, ${data.selectors.length - active.length} revoked` : ''}</p>`;
    data.selectors.forEach(s => {
        html += `<p style="margin-top:0.5rem"><strong>${escapeHtml(s.selector)}</strong>._domainkey${s.revoked ? ' <span class="status status-warn">revoked (empty p=)</span>' : ''}</p>`;
        html += `<div class="record-box">${escapeHtml(s.record)}</div>`;
    });
    el.innerHTML = html;
}

// ===== MTA-STS =====
function renderMtaSts(data) {
    const el = $('mtaStsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No MTA-STS record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    let msg;
    if (data.pass) {
        msg = `MTA-STS configured and policy reachable (mode: ${escapeHtml(data.policy_mode || '?')})`;
    } else if (!data.policy_reachable) {
        msg = `DNS record found, but the /.well-known/mta-sts.txt policy file is NOT reachable over HTTPS (${data.policy_status_code ? `HTTP ${data.policy_status_code}` : 'request failed'})`;
    } else {
        msg = 'DNS record found and policy file reachable, but the policy content is not valid (missing version/mode/mx/max_age)';
    }
    let html = `<p class="status ${cls}">${escapeHtml(msg)}</p>`;
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    if (!data.pass) {
        html += `<p style="margin-top:0.5rem;font-size:0.85em;opacity:0.75">Note: reachability is only checked from DomainLens's own server location, not from arbitrary mail-server vantage points worldwide.</p>`;
    }
    el.innerHTML = html;
}

// ===== TLS-RPT =====
function renderTlsrpt(data) {
    const el = $('tlsrptContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No TLS-RPT record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    const msg = data.pass ? 'TLS-RPT configured' : 'TLS-RPT record found, but no rua= report destination is set — no reports will ever be delivered';
    let html = `<p class="status ${cls}">${escapeHtml(msg)}</p>`;
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    el.innerHTML = html;
}

// ===== SSL Certificate =====
function renderSsl(data) {
    const el = $('sslContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'SSL check failed')}</p>`;
        return;
    }
    const expCls = data.expired ? 'status-fail' : (data.days_until_expiry < 30 ? 'status-warn' : 'status-pass');
    const expText = data.expired ? 'EXPIRED' : `${data.days_until_expiry} days remaining`;

    let html = `<p class="status ${expCls}">${escapeHtml(expText)}</p>`;
    html += `<table class="data-table">
        <tr><th>Subject</th><td>${escapeHtml(data.subject?.commonName || data.subject?.organizationName || '-')}</td></tr>
        <tr><th>Issuer</th><td>${escapeHtml(data.issuer?.organizationName || data.issuer?.commonName || '-')}</td></tr>
        <tr><th>Valid From</th><td>${escapeHtml(data.not_before)}</td></tr>
        <tr><th>Valid Until</th><td>${escapeHtml(data.not_after)}</td></tr>
        <tr><th>Protocol</th><td>${escapeHtml(data.protocol || '-')}</td></tr>
        <tr><th>Cipher</th><td>${escapeHtml(data.cipher || '-')}</td></tr>
        <tr><th>Serial</th><td style="font-family:monospace;font-size:0.8rem">${escapeHtml(data.serial_number || '-')}</td></tr>
        <tr><th>SAN</th><td>${(data.san || []).map(escapeHtml).join('<br>') || '-'}</td></tr>
    </table>`;
    el.innerHTML = html;
}

// ===== TLS Deep Scan =====
function renderTlsDeep(data) {
    const gradeCard = $('tlsGradeCard');
    const protoEl = $('tlsProtocolsContent');
    const cipherSumEl = $('tlsCipherSummary');
    const cipherEl = $('tlsCiphersContent');
    const featEl = $('tlsFeaturesContent');

    if (!data || !data.success) {
        gradeCard.style.display = 'none';
        protoEl.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'TLS scan not available')}</p>`;
        cipherSumEl.innerHTML = '';
        cipherEl.innerHTML = '';
        featEl.innerHTML = '';
        return;
    }

    gradeCard.style.display = '';
    const gradeCircle = $('tlsGradeCircle');
    const grade = data.grade || '?';
    gradeCircle.textContent = grade;
    gradeCircle.className = 'tls-grade-circle grade-' + grade.replace('+', 'plus').toLowerCase();

    const warningsEl = $('tlsWarnings');
    if (data.warnings && data.warnings.length > 0) {
        warningsEl.innerHTML = data.warnings.map(w => `<div class="tls-warning"><span class="status status-warn"></span> ${escapeHtml(w)}</div>`).join('');
    } else {
        warningsEl.innerHTML = '<div class="tls-warning"><span class="status status-pass"></span> No issues found</div>';
    }

    let protoHtml = '<div class="proto-grid">';
    const protoOrder = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
    const deprecated = ['TLS 1.0', 'TLS 1.1'];
    for (const pname of protoOrder) {
        const p = (data.protocols || []).find(x => x.name === pname);
        if (!p) continue;
        const supported = p.supported;
        const isOld = deprecated.includes(pname);
        let cls, statusText;
        if (supported && isOld) { cls = 'proto-warn'; statusText = 'Enabled (deprecated)'; }
        else if (supported) { cls = 'proto-pass'; statusText = 'Enabled'; }
        else if (!supported && isOld) { cls = 'proto-good-disabled'; statusText = 'Disabled'; }
        else { cls = 'proto-fail'; statusText = 'Not supported'; }

        protoHtml += `<div class="proto-item ${cls}">
            <div class="proto-name">${escapeHtml(pname)}</div>
            <div class="proto-status">${escapeHtml(statusText)}</div>
            ${supported && p.cipher ? `<div class="proto-cipher">${escapeHtml(p.cipher)} (${escapeHtml(String(p.bits))} bit)</div>` : ''}
        </div>`;
    }
    protoHtml += '</div>';
    protoEl.innerHTML = protoHtml;

    const cs = data.cipher_summary || {};
    cipherSumEl.innerHTML = `<div class="cipher-summary">
        <span class="cipher-stat"><strong>${cs.total || 0}</strong> total</span>
        <span class="cipher-stat cipher-strong"><strong>${cs.strong || 0}</strong> strong</span>
        <span class="cipher-stat cipher-acceptable"><strong>${cs.acceptable || 0}</strong> acceptable</span>
        <span class="cipher-stat cipher-weak"><strong>${cs.weak || 0}</strong> weak</span>
        <span class="cipher-stat cipher-insecure"><strong>${cs.insecure || 0}</strong> insecure</span>
        <span class="cipher-stat cipher-fs"><strong>${cs.forward_secrecy || 0}</strong> PFS</span>
    </div>`;

    if (data.ciphers && data.ciphers.length > 0) {
        let cHtml = '<table class="data-table cipher-table"><thead><tr><th>Cipher Suite</th><th>Protocol</th><th>Bits</th><th>Strength</th><th>PFS</th></tr></thead><tbody>';
        for (const c of data.ciphers) {
            const strengthCls = c.strength === 'strong' ? 'badge-pass' : c.strength === 'acceptable' ? 'badge-info' : c.strength === 'weak' ? 'badge-warn' : 'badge-fail';
            cHtml += `<tr>
                <td style="font-family:monospace;font-size:0.8rem">${escapeHtml(c.name)}</td>
                <td>${escapeHtml(c.protocol)}</td>
                <td>${escapeHtml(String(c.bits))}</td>
                <td><span class="badge ${strengthCls}">${escapeHtml(c.strength)}</span></td>
                <td>${c.forward_secrecy ? '<span class="status status-pass"></span>' : '<span class="status status-fail"></span>'}</td>
            </tr>`;
        }
        cHtml += '</tbody></table>';
        cipherEl.innerHTML = cHtml;
    } else {
        cipherEl.innerHTML = '<p class="status status-fail">No cipher suites detected</p>';
    }

    let fHtml = '<table class="data-table">';
    fHtml += `<tr><th>OCSP Stapling</th><td><span class="status ${data.ocsp_stapling ? 'status-pass' : 'status-fail'}">${data.ocsp_stapling ? 'Enabled' : 'Not enabled'}</span></td></tr>`;
    fHtml += `<tr><th>TLS Compression</th><td><span class="status ${!data.tls_compression ? 'status-pass' : 'status-fail'}">${data.tls_compression ? 'Enabled (CRIME vulnerable!)' : 'Disabled (safe)'}</span></td></tr>`;
    if (data.hsts) {
        let hstsStatus = 'status-fail';
        let hstsText = 'Not set';
        if (data.hsts.enabled === true) {
            hstsStatus = 'status-pass';
            hstsText = 'Enabled';
        } else if (data.hsts.enabled == null || data.hsts.blocked) {
            hstsStatus = 'status-warn';
            const country = data.hsts.request_country ? ` from ${data.hsts.request_country}` : '';
            hstsText = data.hsts.block_detail
                || `Could not verify (CDN/WAF geo-blocked probe${country})`;
        }
        fHtml += `<tr><th>HSTS</th><td><span class="status ${hstsStatus}">${escapeHtml(hstsText)}</span></td></tr>`;
        if (data.hsts.enabled === true) {
            fHtml += `<tr><th>HSTS Value</th><td class="record-box" style="margin:0">${escapeHtml(data.hsts.value)}</td></tr>`;
            fHtml += `<tr><th>HSTS Preload</th><td><span class="status ${data.hsts.preload ? 'status-pass' : 'status-warn'}">${data.hsts.preload ? 'Yes' : 'No'}</span></td></tr>`;
        } else if (data.hsts.blocked) {
            fHtml += `<tr><th>Probe status</th><td class="record-box" style="margin:0">${escapeHtml(String(data.hsts.status_code || ''))} ${escapeHtml(data.hsts.block_reason || '')}${data.hsts.request_country ? ' country=' + escapeHtml(data.hsts.request_country) : ''}</td></tr>`;
        }
    }
    if (data.certificate?.success) {
        const cert = data.certificate;
        fHtml += `<tr><th>Certificate</th><td><span class="status ${cert.expired ? 'status-fail' : 'status-pass'}">${cert.expired ? 'EXPIRED' : escapeHtml(String(cert.days_until_expiry)) + ' days remaining'}</span></td></tr>`;
        fHtml += `<tr><th>Wildcard</th><td>${cert.wildcard ? 'Yes' : 'No'}</td></tr>`;
        fHtml += `<tr><th>Self-signed</th><td><span class="status ${cert.self_signed ? 'status-fail' : 'status-pass'}">${cert.self_signed ? 'Yes' : 'No'}</span></td></tr>`;
        fHtml += `<tr><th>SAN Count</th><td>${escapeHtml(String(cert.san_count))}</td></tr>`;
    }
    fHtml += '</table>';
    featEl.innerHTML = fHtml;
}

// ===== Security Audit =====
function sevBadge(sev) {
    return `<span class="rec-badge sev-${escapeHtml(sev)}">${escapeHtml(String(sev).toUpperCase())}</span>`;
}

function renderSecurity(data) {
    const badge = $('secBadge');
    const findingsEl = $('secFindingsContent');
    const subEl = $('secSubdomainsContent');
    const webEl = $('secWebContent');
    const dnsEl = $('secDnsContent');
    const infoEl = $('secInfoContent');

    if (!data) {
        if (badge) { badge.textContent = ''; badge.className = 'tab-badge'; }
        findingsEl.innerHTML = '<p class="status status-warn">Security audit not run. Enable "Security Audit" in the scan options.</p>';
        subEl.innerHTML = webEl.innerHTML = dnsEl.innerHTML = infoEl.innerHTML = '';
        return;
    }
    if (!data.success) {
        findingsEl.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'Security audit failed')}</p>`;
        subEl.innerHTML = webEl.innerHTML = dnsEl.innerHTML = infoEl.innerHTML = '';
        return;
    }

    // Badge = total findings count
    const findings = data.findings || [];
    if (badge) {
        if (findings.length > 0) { badge.textContent = String(findings.length); badge.className = 'tab-badge'; }
        else { badge.textContent = '0'; badge.className = 'tab-badge ok'; }
    }

    // --- Findings list ---
    const counts = data.counts || {};
    if (findings.length === 0) {
        findingsEl.innerHTML = '<div class="rec-empty">No security findings. Nice — but keep scanning regularly.</div>';
    } else {
        let html = '<div class="rec-summary">';
        SEVERITIES.forEach(s => {
            if (counts[s] > 0) html += `<span class="chip sev-${s}"><span class="chip-count">${counts[s]}</span> ${escapeHtml(s)}</span>`;
        });
        html += '</div>';
        findings.forEach(f => {
            html += `<article class="rec sev-${escapeHtml(f.severity)}">
                <div class="rec-head">${sevBadge(f.severity)}<span class="rec-category">${escapeHtml(f.category)}</span><h4>${escapeHtml(f.title)}</h4></div>
                <div class="rec-body">
                    <p>${escapeHtml(f.detail || '')}</p>
                    ${f.evidence ? `<p><strong>${escapeHtml(t('advies.evidence'))}:</strong> <code>${escapeHtml(f.evidence)}</code></p>` : ''}
                    ${f.fix ? `<p><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(f.fix)}</p>` : ''}
                </div>
            </article>`;
        });
        findingsEl.innerHTML = html;
    }

    // --- Subdomains ---
    const subs = data.subdomains || {};
    if (subs.success) {
        let html = '';
        const takeovers = subs.takeovers || [];
        const dangling = subs.dangling || [];
        if (takeovers.length > 0) {
            html += '<div class="diag-list">';
            takeovers.forEach(t => {
                const why = t.fingerprint_match
                    ? 'the unclaimed-resource page of this service was served'
                    : 'the CNAME target returns NXDOMAIN';
                html += `<div class="diag-item" style="border-left-color:var(--red)">
                    <div class="diag-title">⚠️ ${escapeHtml(t.subdomain)} → ${escapeHtml(t.service)} (${escapeHtml(t.confidence)} confidence)</div>
                    <div class="diag-detail">Flagged because ${escapeHtml(why)}.</div>
                    <div class="diag-detail">CNAME: <code>${escapeHtml(t.cname)}</code> · target resolves: ${t.target_resolves ? 'yes' : 'no'} · fingerprint: ${t.fingerprint_match ? 'matched' : 'not matched'}${t.http_status ? ' · HTTP ' + escapeHtml(String(t.http_status)) : ''}</div>
                    <div class="diag-detail">Fix: remove this DNS record, or re-claim the resource on ${escapeHtml(t.service)}.</div>
                </div>`;
            });
            html += '</div>';
        }
        if (dangling.length > 0) {
            html += '<div class="diag-list">';
            dangling.forEach(d => {
                html += `<div class="diag-item" style="border-left-color:var(--orange)">
                    <div class="diag-title">${escapeHtml(d.subdomain)} → dangling CNAME</div>
                    <div class="diag-detail">CNAME: <code>${escapeHtml(d.cname)}</code> returns NXDOMAIN. The provider is not in DomainLens's signature list, so this is not confirmed claimable — but it is a stale record.</div>
                    <div class="diag-detail">Fix: remove the record if the target is no longer in use.</div>
                </div>`;
            });
            html += '</div>';
        }
        if (subs.source_error) {
            // Never render a green all-clear off the back of an enumeration
            // that never happened.
            html += `<p class="status status-warn">Certificate Transparency lookup failed, so only the apex domain was checked — this is an absent answer, not a clean one.</p>`;
            html += `<p class="http-meta"><span>${escapeHtml(String(subs.source_error))}</span></p>`;
        } else if (takeovers.length === 0 && dangling.length === 0) {
            html += '<p class="status status-pass">No dangling / takeover-able subdomains detected</p>';
        }
        html += `<p class="http-meta"><span><strong>${escapeHtml(String(subs.count || 0))}</strong> subdomains checked via Certificate Transparency</span></p>`;
        if (subs.truncated) {
            html += `<p class="status status-warn">Only the first ${escapeHtml(String(subs.limit || 0))} of ${escapeHtml(String(subs.discovered_count || 0))} discovered hostnames were checked — this result does not cover the whole attack surface.</p>`;
        }
        if (subs.source_stale) {
            // crt.sh is down; this is the last answer known to be real, dated
            // so it is never mistaken for a current one.
            const when = subs.source_cached_at
                ? new Date(subs.source_cached_at).toLocaleString()
                : `${formatCacheAge(subs.source_cache_age_seconds)} ago`;
            html += `<p class="status status-warn">crt.sh is unavailable right now, so this list is the last successful lookup, from ${escapeHtml(when)}. Certificates issued since then are missing.</p>`;
            if (subs.source_outage) {
                html += `<p class="http-meta"><span>${escapeHtml(String(subs.source_outage))}</span></p>`;
            }
        } else if (subs.source_cached) {
            html += `<p class="http-meta"><span>Certificate list reused from a lookup ${escapeHtml(formatCacheAge(subs.source_cache_age_seconds))} ago rather than queried again.</span></p>`;
        }
        const list = subs.subdomains || [];
        if (list.length > 0) {
            html += '<details class="hdr-details"><summary>All discovered subdomains (' + list.length + ')</summary>';
            html += '<div class="sub-list" style="margin-top:0.5rem">';
            list.forEach(s => { html += `<span class="sub-chip">${escapeHtml(s)}</span>`; });
            html += '</div></details>';
        }
        subEl.innerHTML = html;
    } else {
        subEl.innerHTML = `<p class="status status-warn">${escapeHtml(subs.error || 'Subdomain enumeration unavailable')}</p>`;
    }

    // --- Web exposures ---
    const web = data.web_exposure || {};
    if (web.success) {
        let html = '';
        const files = web.sensitive_files || [];
        if (files.length > 0) {
            html += '<p class="status status-fail" style="margin-bottom:0.5rem">Exposed sensitive files:</p><table class="data-table">';
            files.forEach(f => { html += `<tr><th>${escapeHtml(f.path)}</th><td>HTTP ${escapeHtml(String(f.status))} · ${escapeHtml(String(f.size || '?'))} bytes</td></tr>`; });
            html += '</table>';
        } else {
            html += '<p class="status status-pass">No exposed sensitive files found</p>';
        }
        const admin = web.admin_endpoints || [];
        if (admin.length > 0) {
            html += '<p style="margin:0.75rem 0 0.4rem;font-weight:600">Reachable admin/debug endpoints:</p><table class="data-table">';
            admin.forEach(a => {
                const cls = a.status === 200 ? 'status-warn' : 'status-pass';
                html += `<tr><th>${escapeHtml(a.path)}</th><td><span class="status ${cls}">HTTP ${escapeHtml(String(a.status))}</span></td></tr>`;
            });
            html += '</table>';
        }
        // CORS
        const cors = web.cors || {};
        html += '<table class="data-table" style="margin-top:0.75rem">';
        html += `<tr><th>CORS Allow-Origin</th><td>${escapeHtml(cors.allow_origin || '(none)')}${cors.reflects_origin ? ' <span class="status status-fail">reflects Origin</span>' : ''}${cors.wildcard ? ' <span class="status status-warn">wildcard</span>' : ''}</td></tr>`;
        html += `<tr><th>CORS Credentials</th><td>${cors.allow_credentials ? 'true' : 'false'}</td></tr>`;
        // Methods
        const m = web.methods || {};
        if (m.allow_header) {
            html += `<tr><th>Allowed methods</th><td>${escapeHtml(m.allow_header)}${m.trace_enabled ? ' <span class="status status-warn">TRACE</span>' : ''}</td></tr>`;
        }
        html += `<tr><th>security.txt</th><td><span class="status ${web.security_txt ? 'status-pass' : 'status-warn'}">${web.security_txt ? 'present' : 'missing'}</span></td></tr>`;
        html += '</table>';
        // Cookies
        const cookies = web.cookies || [];
        if (cookies.length > 0) {
            html += '<p style="margin:0.75rem 0 0.4rem;font-weight:600">Cookies:</p><table class="data-table"><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead><tbody>';
            cookies.forEach(c => {
                html += `<tr><td>${escapeHtml(c.name)}</td>
                    <td>${c.secure ? '✓' : '<span class="status status-fail">✗</span>'}</td>
                    <td>${c.httponly ? '✓' : '<span class="status status-fail">✗</span>'}</td>
                    <td>${c.samesite ? escapeHtml(c.samesite) : '<span class="status status-warn">none</span>'}</td></tr>`;
            });
            html += '</tbody></table>';
        }
        webEl.innerHTML = html;
    } else {
        webEl.innerHTML = `<p class="status status-warn">${escapeHtml(web.error || 'Web exposure scan unavailable')}</p>`;
    }

    // --- DNS & mail gaps ---
    const dm = data.dns_mail || {};
    if (dm.success) {
        let html = '<table class="data-table">';
        const axfr = dm.axfr || {};
        if ((axfr.vulnerable || []).length > 0) {
            html += `<tr><th>Zone transfer (AXFR)</th><td><span class="status status-fail">VULNERABLE — ${escapeHtml(String(axfr.records_leaked))} records leaked</span></td></tr>`;
        } else {
            html += `<tr><th>Zone transfer (AXFR)</th><td><span class="status status-pass">Refused (${escapeHtml(String((axfr.tested || []).length))} NS tested)</span></td></tr>`;
        }
        const caa = dm.caa || {};
        const caaOk = caa.has_issue_tag && !((caa.non_lowercase_tags || []).length);
        let caaLabel = 'not set';
        if (caa.present) {
            caaLabel = escapeHtml((caa.records || []).join(', '));
            if (!caa.has_issue_tag) caaLabel += ' — missing issue tag';
            else if ((caa.non_lowercase_tags || []).length) caaLabel += ` — non-lowercase tag: ${escapeHtml(caa.non_lowercase_tags.join(', '))}`;
        }
        html += `<tr><th>CAA record</th><td><span class="status ${caaOk ? 'status-pass' : 'status-warn'}">${caaLabel}</span></td></tr>`;
        const tlsa = dm.tlsa || {};
        html += `<tr><th>DANE / TLSA</th><td><span class="status ${tlsa.present ? 'status-pass' : 'status-warn'}">${tlsa.present ? 'present' : 'not set'}</span></td></tr>`;
        const spf = dm.spf_lookups || {};
        html += `<tr><th>SPF DNS lookups</th><td><span class="status ${spf.over_limit ? 'status-fail' : 'status-pass'}">${escapeHtml(String(spf.count))} / 10${spf.over_limit ? ' — over limit!' : ''}</span></td></tr>`;
        const ds = dm.dmarc_subdomain || {};
        html += `<tr><th>DMARC subdomain policy</th><td>${ds.subdomain_policy ? 'sp=' + escapeHtml(ds.subdomain_policy) : 'inherits p=' + escapeHtml(ds.policy || '?')}${ds.weak_subdomain ? ' <span class="status status-warn">weaker than domain</span>' : ''}</td></tr>`;
        html += `<tr><th>Wildcard DNS</th><td><span class="status ${dm.wildcard_dns ? 'status-warn' : 'status-pass'}">${dm.wildcard_dns ? 'present' : 'none'}</span></td></tr>`;
        const hygiene = dm.txt_hygiene || {};
        const defects = hygiene.defects || [];
        html += `<tr><th>Policy TXT records</th><td>${defects.length === 0
            ? '<span class="status status-pass">no stray control characters</span>'
            : defects.map(d => `<span class="status status-fail">${escapeHtml(d.record)}: ${escapeHtml((d.problems || []).join('; '))}</span>`).join('<br>')}</td></tr>`;
        html += '</table>';
        if (defects.length) {
            html += `<p class="http-meta"><span>A control character (usually a line break pasted along with the value) makes the record invalid to strict parsers, so the policy silently stops applying — nothing in a DNS panel shows it.</span></p>`;
        }
        dnsEl.innerHTML = html;
    } else {
        dnsEl.innerHTML = `<p class="status status-warn">${escapeHtml(dm.error || 'DNS/mail gap scan unavailable')}</p>`;
    }

    // --- Info disclosure ---
    const info = data.info_disclosure || {};
    if (info.success) {
        let html = '';
        const techs = info.technologies || [];
        if (techs.length > 0) {
            html += '<div class="infra-badges">';
            techs.forEach(t => { html += `<span class="infra-badge" style="border-color:var(--border);color:var(--text)">${escapeHtml(t)}</span>`; });
            html += '</div>';
        }
        const leaks = info.version_leaks || [];
        if (leaks.length > 0) {
            html += '<p class="status status-warn" style="margin:0.5rem 0">Version numbers disclosed:</p><table class="data-table">';
            leaks.forEach(l => { html += `<tr><th>${escapeHtml(l.header)}</th><td>${escapeHtml(l.value)}</td></tr>`; });
            html += '</table>';
        } else {
            html += '<p class="status status-pass">No precise version numbers leaked</p>';
        }
        const disc = info.disclosed_headers || {};
        const dk = Object.keys(disc);
        if (dk.length > 0) {
            html += '<details class="hdr-details"><summary>Disclosed identifiers (' + dk.length + ')</summary><table class="data-table" style="margin-top:0.5rem">';
            dk.forEach(k => { html += `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(disc[k])}</td></tr>`; });
            html += '</table></details>';
        }
        infoEl.innerHTML = html;
    } else {
        infoEl.innerHTML = `<p class="status status-warn">${escapeHtml(info.error || 'Info disclosure scan unavailable')}</p>`;
    }
}

// ===== NCSC TLS Guidelines 2025-05 =====
function ncscLevelBadge(level) {
    const map = {
        good: 'badge-pass',
        sufficient: 'badge-info',
        phased_out: 'badge-warn',
        insufficient: 'badge-fail',
        unknown: 'badge-warn',
    };
    return map[level] || 'badge-warn';
}

function renderNcscTls(data) {
    const el = $('ncscTlsContent');
    if (!el) return;
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'NCSC TLS assessment not available')}</p>`;
        return;
    }

    const summary = data.cipher_summary || {};
    let html = `
        <div class="ncsc-summary">
            <div class="ncsc-overall">
                <span class="badge ${ncscLevelBadge(data.overall_level)}">${escapeHtml(data.overall_label || data.overall_level)}</span>
                <span class="ncsc-meta">${data.pass ? 'Compliant (no Insufficient settings)' : 'Non-compliant'}</span>
            </div>
            <p class="ncsc-guideline">
                <a href="${escapeHtml(data.guideline_url || '#')}" target="_blank" rel="noopener">
                    ${escapeHtml(data.guideline || 'NCSC TLS Security Guidelines 2025-05')}
                </a>
            </p>
            <div class="cipher-summary">
                <span class="cipher-stat cipher-strong"><strong>${summary.good || 0}</strong> good</span>
                <span class="cipher-stat cipher-acceptable"><strong>${summary.sufficient || 0}</strong> sufficient</span>
                <span class="cipher-stat cipher-weak"><strong>${summary.phased_out || 0}</strong> phase-out</span>
                <span class="cipher-stat cipher-insecure"><strong>${summary.insufficient || 0}</strong> insufficient</span>
            </div>
        </div>`;

    if (data.compression) {
        html += `<p><strong>TLS compression:</strong>
            <span class="badge ${ncscLevelBadge(data.compression.level)}">${escapeHtml(data.compression.label || '')}</span>
            ${data.compression.enabled ? ' (enabled)' : ' (disabled)'}
        </p>`;
    }

    const order = data.cipher_order || {};
    if (Object.keys(order).length) {
        let orderBadge = 'badge-info';
        let orderText = 'Not applicable';
        if (order.applicable && order.pass === true) {
            orderBadge = 'badge-pass';
            orderText = 'Server prefers Good/Sufficient';
        } else if (order.applicable && order.pass === false) {
            orderBadge = 'badge-fail';
            orderText = 'Server prefers weaker suites';
        } else if (order.pass == null) {
            orderBadge = 'badge-warn';
            orderText = 'Could not verify';
        }
        html += `<div class="ncsc-order">
            <p><strong>Cipher suite order:</strong> <span class="badge ${orderBadge}">${escapeHtml(orderText)}</span></p>`;
        if (order.applicable && order.pass === false) {
            const preferred = order.server_preferred_iana || order.server_preferred || '-';
            const expected = order.expected_preferred_iana || order.expected_preferred || '-';
            html += `<table class="data-table"><thead><tr><th>Server preferred</th><th>Expected preferred</th></tr></thead><tbody>
                <tr>
                    <td><code>${escapeHtml(preferred)}</code><div class="muted">${escapeHtml(order.server_preferred_level || '')}</div></td>
                    <td><code>${escapeHtml(expected)}</code><div class="muted">${escapeHtml(order.expected_preferred_level || '')}</div></td>
                </tr>
            </tbody></table>`;
        } else if (order.detail) {
            html += `<p class="login-hint">${escapeHtml(order.detail)}</p>`;
        }
        html += '</div>';
    }

    if (data.certificate && data.certificate.evaluated) {
        html += `<p><strong>Certificate key:</strong>
            <span class="badge ${ncscLevelBadge(data.certificate.level)}">${escapeHtml(data.certificate.label || '')}</span>
            ${escapeHtml(data.certificate.detail || '')}
        </p>`;
    }

    if (data.protocols && data.protocols.length) {
        html += '<table class="data-table"><thead><tr><th>Protocol</th><th>Status</th><th>NCSC level</th></tr></thead><tbody>';
        for (const p of data.protocols) {
            html += `<tr>
                <td>${escapeHtml(p.name)}</td>
                <td>${p.supported ? 'Enabled' : 'Disabled'}</td>
                <td>${p.supported ? `<span class="badge ${ncscLevelBadge(p.level)}">${escapeHtml(p.label || p.level || '')}</span>` : '—'}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    if (data.ciphers && data.ciphers.length) {
        html += '<table class="data-table cipher-table" style="margin-top:1rem"><thead><tr><th>Cipher suite</th><th>NCSC level</th><th>KX</th><th>Auth</th><th>Bulk</th><th>Hash</th></tr></thead><tbody>';
        for (const c of data.ciphers) {
            const comp = c.components || {};
            html += `<tr>
                <td style="font-family:monospace;font-size:0.8rem">${escapeHtml(c.name)}</td>
                <td><span class="badge ${ncscLevelBadge(c.level)}">${escapeHtml(c.label || c.level)}</span></td>
                <td>${escapeHtml(comp.key_exchange?.name || '-')}</td>
                <td>${escapeHtml(comp.authentication?.name || '-')}</td>
                <td>${escapeHtml(comp.bulk_encryption?.name || '-')}</td>
                <td>${escapeHtml(comp.hash?.name || '-')}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    if (data.findings && data.findings.length) {
        html += `<div class="ncsc-findings"><h4>${escapeHtml(t('results.ncsc_advice_heading'))}</h4>`;
        for (const f of data.findings) {
            const sev = f.severity === 'critical' || f.severity === 'high' ? 'fail' : (f.severity === 'medium' ? 'warn' : 'pass');
            html += `<article class="rec sev-${escapeHtml(f.severity || 'info')}" style="margin-top:0.75rem">
                <div class="rec-head">
                    <span class="status status-${sev}"></span>
                    <h4>${escapeHtml(f.title)}</h4>
                </div>
                <div class="rec-body">
                    <p><strong>${escapeHtml(t('advies.problem'))}:</strong> ${escapeHtml(f.problem || '')}</p>
                    ${f.fix ? `<div class="rec-advies"><p><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(f.fix)}</p>
                    <p><strong>${escapeHtml(t('advies.retest'))}:</strong> ${escapeHtml(f.retest || defaultRetest('NCSC TLS', f.title))}</p></div>` : ''}
                </div>
            </article>`;
        }
        html += '</div>';
    }

    el.innerHTML = html;
}

// ===== HTTP Deep Analysis =====
const INFRA_COLORS = {
    'Azure Front Door': '#0078d4',
    'Azure App Service': '#0078d4',
    'Azure (IP range)': '#0078d4',
    'Cloudflare': '#f38020',
    'AWS CloudFront': '#ff9900',
    'AWS ALB': '#ff9900',
    'Fastly': '#ff282d',
    'Akamai': '#009bde',
    'Microsoft IIS': '#5c2d91',
    'nginx': '#009900',
    'Apache': '#d22128',
};

function infraColor(name) {
    for (const [key, color] of Object.entries(INFRA_COLORS)) {
        if (name.startsWith(key)) return color;
    }
    return '#7c8299';
}

const DIAG_ICONS = {
    app_deny: '🚫', azure_waf: '🛡️', azure_fd_403: '☁️', azure_app_svc: '☁️',
    azure_appgw_waf: '🛡️', cf_waf: '🛡️', cf_403: '☁️',
    auth_required: '🔑', method_not_allowed: '⛔', rate_limited: '⏱️', generic_403: '❓',
};

function renderHttpDeep(data) {
    const el = $('httpDeepContent');
    const card = $('httpDeepCard');
    if (!data) {
        card.style.display = 'none';
        return;
    }
    card.style.display = '';

    if (!data.success) {
        el.innerHTML = `<p class="status status-warn">HTTP analysis not available</p>`;
        return;
    }

    let html = '';

    // Infrastructure badges
    const infra = data.infrastructure || [];
    if (infra.length > 0) {
        html += '<div class="infra-badges">';
        infra.forEach(d => {
            const color = infraColor(d.name);
            const conf = d.confidence === 'high' ? '' : ' (probable)';
            html += `<span class="infra-badge" style="background:${escapeHtml(color)}22;border-color:${escapeHtml(color)};color:${escapeHtml(color)}">${escapeHtml(d.name)}${escapeHtml(conf)}</span>`;
        });
        html += '</div>';
    }

    // Resolved IP & CNAME chain
    html += '<div class="http-meta">';
    if (data.resolved_ip) html += `<span>IP: <code>${escapeHtml(data.resolved_ip)}</code></span>`;
    if (data.cname_chain && data.cname_chain.length > 0) {
        html += `<span>CNAME chain: <code>${data.cname_chain.map(escapeHtml).join(' → ')}</code></span>`;
    }
    html += '</div>';

    // Redirect chain
    const chain = data.redirect_chain || [];
    if (chain.length > 0) {
        html += '<div class="redirect-chain">';
        chain.forEach((step, i) => {
            const cls = step.status >= 400 ? 'status-fail' : step.status >= 300 ? 'status-warn' : 'status-pass';
            const arrow = i < chain.length - 1 ? '<span class="chain-arrow">→</span>' : '';
            html += `<span class="chain-step"><span class="status ${cls}"></span><span class="chain-status">${escapeHtml(String(step.status))}</span> <span class="chain-url">${escapeHtml(step.url)}</span></span>${arrow}`;
        });
        html += '</div>';
    }

    // 4xx diagnostic hints
    const diags = data.diagnostics || [];
    if (diags.length > 0) {
        html += '<div class="diag-list">';
        diags.forEach(d => {
            const icon = DIAG_ICONS[d.type] || 'ℹ️';
            html += `<div class="diag-item">
                <div class="diag-title">${icon} ${escapeHtml(d.title)}</div>
                <div class="diag-detail">${escapeHtml(d.detail)}</div>
                <div class="diag-action"><strong>${escapeHtml(t('advies.action'))}:</strong> ${escapeHtml(d.action)}</div>
            </div>`;
        });
        html += '</div>';
    }

    // Notable (curated) response headers — the ones our detection logic uses
    const notable = data.notable_headers || {};
    const notableKeys = Object.keys(notable);
    if (notableKeys.length > 0) {
        html += '<div class="hdr-key-indicators">';
        html += '<div class="hdr-section-label">Key indicators</div>';
        html += '<table class="data-table">';
        notableKeys.forEach(k => {
            html += `<tr><th>${escapeHtml(k)}</th><td style="font-size:0.8rem;word-break:break-all">${escapeHtml(notable[k])}</td></tr>`;
        });
        html += '</table></div>';
    }

    // Full raw header dump — always available even when detection finds nothing
    const all = data.all_headers || {};
    const allKeys = Object.keys(all);
    if (allKeys.length > 0) {
        html += '<details class="hdr-details"><summary>All response headers (' + allKeys.length + ')</summary>';
        html += '<table class="data-table" style="margin-top:0.5rem">';
        allKeys.forEach(k => {
            html += `<tr><th>${escapeHtml(k)}</th><td style="font-size:0.8rem;word-break:break-all">${escapeHtml(all[k])}</td></tr>`;
        });
        html += '</table></details>';
    }

    if (notableKeys.length === 0 && allKeys.length === 0) {
        html += '<p class="status status-warn">No response headers captured</p>';
    }

    el.innerHTML = html;
}

// ===== HTTPS Redirect =====
function renderHttpsRedirect(data) {
    const el = $('httpsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-fail';
    let html = `<p class="status ${cls}">${data.redirects ? 'HTTP redirects to HTTPS' : 'No HTTPS redirect'}</p>`;
    if (data.redirects) {
        html += `<table class="data-table">
            <tr><th>Status</th><td>${escapeHtml(String(data.status_code))} (${data.permanent ? 'Permanent' : 'Temporary'})</td></tr>
            <tr><th>Location</th><td>${escapeHtml(data.location)}</td></tr>
        </table>`;
    }
    el.innerHTML = html;
}

// ===== HTTP Headers =====
function renderHeaders(data) {
    const el = $('headersContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'Headers check failed')}</p>`;
        return;
    }

    const score = data.score;
    const barColor = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--orange)' : 'var(--red)';

    let html = `<div class="header-bar">
        <span style="font-weight:600">${escapeHtml(String(score))}%</span>
        <div class="progress-bar"><div class="progress-fill" style="width:${score}%;background:${barColor}"></div></div>
    </div>`;

    if (data.server) {
        html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">Server: ${escapeHtml(data.server)}</p>`;
    }

    html += '<table class="data-table">';
    for (const [hdr, val] of Object.entries(data.headers_found || {})) {
        html += `<tr><th><span class="status status-pass"></span> ${escapeHtml(hdr)}</th><td style="font-size:0.8rem">${escapeHtml(val)}</td></tr>`;
    }
    for (const hdr of (data.headers_missing || [])) {
        html += `<tr><th><span class="status status-fail"></span> ${escapeHtml(hdr)}</th><td style="color:var(--text-muted)">Not set</td></tr>`;
    }
    html += '</table>';

    // A Report-Only policy is a staged change, so show what it would alter
    // rather than leaving the work-in-progress invisible.
    const delta = data.csp_delta || {};
    if (delta.has_report_only) {
        const fmt = entries => (entries || [])
            .map(e => `<code>${escapeHtml(e.directive)}</code> ${escapeHtml((e.sources || []).join(' '))}`)
            .join(', ');
        html += '<p style="margin:0.9rem 0 0.35rem;font-weight:600">CSP Report-Only (staged)</p>';
        if (delta.identical) {
            html += '<p class="status status-warn">Identical to the enforced policy — it can only report violations you already block.</p>';
        } else {
            html += '<table class="data-table">';
            if ((delta.stricter || []).length) {
                html += `<tr><th>Would stop allowing</th><td style="font-size:0.8rem">${fmt(delta.stricter)}</td></tr>`;
            }
            if ((delta.looser || []).length) {
                html += `<tr><th>Would start allowing</th><td style="font-size:0.8rem">${fmt(delta.looser)}</td></tr>`;
            }
            if ((delta.added_directives || []).length) {
                html += `<tr><th>Adds directive</th><td style="font-size:0.8rem">${fmt(delta.added_directives)}</td></tr>`;
            }
            if ((delta.removed_directives || []).length) {
                html += `<tr><th>Drops directive</th><td style="font-size:0.8rem">${fmt(delta.removed_directives)}</td></tr>`;
            }
            html += '</table>';
            html += '<p class="http-meta"><span>Nothing is blocked by this — it only reports. Check the reporting endpoint in the policy (e.g. uriports) for report-only violations before promoting it to the enforced header.</span></p>';
        }
    }
    el.innerHTML = html;
}

// ===== IPv6 =====
function renderIpv6(data) {
    const el = $('ipv6Content');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }

    let html = '<table class="data-table">';
    const aaaaText = (data.aaaa_records || []).map(escapeHtml).join(', ') || 'None';
    html += `<tr><th>Web (AAAA)</th><td><span class="status ${data.web_pass ? 'status-pass' : 'status-fail'}">${aaaaText}</span></td></tr>`;

    if (data.mx_ipv6 && Object.keys(data.mx_ipv6).length > 0) {
        const mxText = Object.entries(data.mx_ipv6)
            .map(([h, ips]) => `${escapeHtml(h)}: ${ips.map(escapeHtml).join(', ')}`)
            .join('<br>');
        html += `<tr><th>Mail IPv6</th><td><span class="status status-pass">${mxText}</span></td></tr>`;
    } else {
        html += `<tr><th>Mail IPv6</th><td><span class="status status-fail">No mail server IPv6</span></td></tr>`;
    }

    if (data.ns_ipv6 && Object.keys(data.ns_ipv6).length > 0) {
        const nsText = Object.entries(data.ns_ipv6)
            .map(([h, ips]) => `${escapeHtml(h)}: ${ips.map(escapeHtml).join(', ')}`)
            .join('<br>');
        html += `<tr><th>NS IPv6</th><td><span class="status status-pass">${nsText}</span></td></tr>`;
    } else {
        html += `<tr><th>NS IPv6</th><td><span class="status status-fail">No nameserver IPv6</span></td></tr>`;
    }
    html += '</table>';
    el.innerHTML = html;
}

// ===== Blacklist =====
function renderBlacklist(data) {
    const el = $('blacklistContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }

    let html = '';
    if (data.ip) html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">IP: ${escapeHtml(data.ip)}</p>`;

    if (data.spamhaus_dqs === false) {
        const spamhausMsg = t('results.spamhaus_not_checked').replace('SPAMHAUS_DQS_KEY', '<code>SPAMHAUS_DQS_KEY</code>');
        html += `<p class="status status-warn" style="margin-bottom:0.75rem">${spamhausMsg} — see <a href="/admin/settings">Settings → Optional API keys</a>.</p>`;
    }

    const cls = data.is_listed ? 'status-fail' : 'status-pass';
    const msg = data.is_listed ? `Listed on ${data.listed.length} blacklist(s)!` : 'Clean - not listed on any blacklist';
    html += `<p class="status ${cls}" style="margin-bottom:0.75rem">${escapeHtml(msg)}</p>`;

    html += '<div class="bl-list">';
    for (const bl of (data.listed || [])) {
        html += `<div class="bl-item"><span class="status status-fail"></span> ${escapeHtml(bl)}</div>`;
    }
    for (const bl of (data.clean || [])) {
        html += `<div class="bl-item"><span class="status status-pass"></span> ${escapeHtml(bl)}</div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}

// ===== Recommendations =====
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function defaultRetest(category, title, domain) {
    const target = domain || 'the domain';
    const cat = (category || '').toLowerCase();
    const titleL = (title || '').toLowerCase();
    if (cat.includes('ncsc') || cat === 'tls' || titleL.includes('cipher') || titleL.includes('hsts')) {
        return `Re-run DomainLens SSL/TLS (+ NCSC) for \`${target}\`. Cross-check https://internet.nl/site/${target}/ from NL/DE/BE if geo-restricted.`;
    }
    if (cat === 'email') {
        return `After DNS TTL, re-scan \`${target}\` in DomainLens E-mail Security (and optionally internet.nl mail).`;
    }
    if (cat === 'dns') {
        return `Re-scan \`${target}\` in DomainLens DNS/DNSSEC after propagation (\`dig +dnssec\`).`;
    }
    if (cat === 'web') {
        return `Re-run DomainLens Web Security for \`${target}\`; confirm with curl -sI from an allowed region.`;
    }
    return `Re-run a full DomainLens scan for \`${target}\` and confirm this advies item is gone.`;
}

function generateRecommendations(data) {
    const recs = [];
    const domain = data.domain;
    const add = (severity, category, title, problem, fix, reference, retest) => {
        const r = {
            severity,
            category,
            title,
            problem,
            fix,
            retest: retest || defaultRetest(category, title, domain),
        };
        if (reference) r.reference = reference;
        recs.push(r);
    };

    if (data.dnssec && !data.dnssec.signed) {
        add('medium', 'DNS', 'DNSSEC not configured',
            'DNSSEC is not fully set up. Responses cannot be cryptographically verified.',
            'Enable DNSSEC at your DNS provider. Publish a DS record at the registrar.');
    }

    if (data.spf && !data.spf.found) {
        add('high', 'Email', 'SPF record missing',
            'Anyone can spoof mail from this domain.',
            'Publish a TXT record: v=spf1 include:_spf.yourprovider.com -all');
    } else if (data.spf && data.spf.found && !data.spf.strict) {
        add('medium', 'Email', 'SPF is not strict',
            'SPF ends with ~all or ?all, so spoofed mail may still be accepted.',
            'After verifying sending sources, tighten to -all.');
    }

    if (data.dmarc && !data.dmarc.found) {
        add('high', 'Email', 'DMARC missing',
            'No DMARC policy is published.',
            'Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain; then move to quarantine/reject.');
    } else if (data.dmarc && data.dmarc.policy === 'none') {
        add('medium', 'Email', 'DMARC policy is p=none',
            'DMARC is only in monitor mode; spoofed mail is not blocked.',
            'After reviewing aggregate reports, change to p=quarantine or p=reject.');
    }

    if (data.dkim && !data.dkim.found) {
        add('medium', 'Email', 'No DKIM selectors detected',
            'Mail from this domain may not be DKIM-signed.',
            'Enable DKIM at your mail provider and publish the public key as <selector>._domainkey.');
    }

    if (data.mta_sts && !data.mta_sts.found) {
        add('low', 'Email', 'MTA-STS not configured',
            'Inbound mail may be delivered over insecure TLS.',
            'Publish _mta-sts TXT and host the policy at https://mta-sts.yourdomain/.well-known/mta-sts.txt.');
    }

    if (data.tlsrpt && !data.tlsrpt.found) {
        add('low', 'Email', 'TLS-RPT not configured',
            'No reporting of TLS failures on inbound mail.',
            'Publish _smtp._tls TXT: v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.');
    }

    if (data.tls_deep && data.tls_deep.success) {
        const tls = data.tls_deep;
        if (['D','F','T'].includes(tls.grade)) {
            add('critical', 'TLS', 'Poor TLS grade (' + tls.grade + ')',
                'Connections are exposed to known attacks.',
                'Disable obsolete protocols, remove weak ciphers, install a trusted certificate, enable HSTS.',
                'https://ssl-config.mozilla.org/');
        }
        const protos = {};
        (tls.protocols || []).forEach(p => { protos[p.name] = p.supported; });
        if (protos['TLS 1.0']) add('high', 'TLS', 'TLS 1.0 enabled', 'TLS 1.0 is deprecated and vulnerable to BEAST.', 'Disable TLS 1.0 in the web server config.');
        if (protos['TLS 1.1']) add('high', 'TLS', 'TLS 1.1 enabled', 'TLS 1.1 is deprecated (RFC 8996).', 'Require TLS 1.2 as a minimum.');
        if (!protos['TLS 1.3']) add('low', 'TLS', 'TLS 1.3 not available', 'Missing performance and security benefits of TLS 1.3.', 'Upgrade OpenSSL and enable TLS 1.3.');

        const cs = tls.cipher_summary || {};
        if ((cs.weak||0) + (cs.insecure||0) > 0) {
            add('high', 'TLS', 'Weak ciphers accepted',
                (cs.weak||0) + ' weak and ' + (cs.insecure||0) + ' insecure cipher suites are accepted.',
                'Restrict to modern AEAD suites (ECDHE-*-GCM, CHACHA20).',
                'https://ssl-config.mozilla.org/');
        }
        if (cs.total > 0 && cs.forward_secrecy < cs.total) {
            add('medium', 'TLS', 'Forward secrecy not universal',
                'Some cipher suites lack forward secrecy.',
                'Only allow ECDHE/DHE cipher suites.');
        }
        if (tls.tls_compression) {
            add('high', 'TLS', 'TLS compression enabled (CRIME)',
                'Server vulnerable to the CRIME attack.',
                'Disable TLS compression.');
        }
        if (!tls.ocsp_stapling) {
            add('low', 'TLS', 'OCSP stapling disabled',
                'Clients may query the CA directly (slower, privacy leak).',
                'Enable OCSP stapling in your web server.');
        }
        const hsts = tls.hsts || {};
        if (!hsts.enabled) {
            add('medium', 'TLS', 'HSTS missing',
                'First-visit downgrade attacks are possible.',
                'Return Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
                'https://hstspreload.org/');
        }
        const cert = tls.certificate || {};
        if (cert.expired) {
            add('critical', 'Certificate', 'Certificate expired',
                'Browsers block access.',
                'Renew immediately and automate with ACME.');
        } else if (cert.days_until_expiry !== undefined && cert.days_until_expiry < 30) {
            add('high', 'Certificate', 'Certificate expires soon',
                'Certificate expires in ' + cert.days_until_expiry + ' days.',
                'Renew now and automate renewals.');
        }
        if (cert.self_signed) {
            add('high', 'Certificate', 'Self-signed certificate',
                'Browsers show warnings.',
                'Use a trusted CA (e.g. Let\'s Encrypt).');
        }
    }

    if (data.https_redirect && !data.https_redirect.pass) {
        add('high', 'Web', 'HTTP does not redirect to HTTPS',
            'Plain HTTP exposes users to MITM.',
            'Force a 301 redirect from HTTP to HTTPS.');
    }

    if (data.http_headers && data.http_headers.success) {
        const missing = data.http_headers.headers_missing || [];
        if (missing.length > 0) {
            const sev = missing.length >= 4 ? 'medium' : 'low';
            add(sev, 'Web', missing.length + ' security header(s) missing',
                'Recommended HTTP security headers are not set.',
                'Add: ' + missing.join(', '),
                'https://owasp.org/www-project-secure-headers/');
        }
    }

    if (data.ipv6 && !data.ipv6.has_ipv6) {
        add('low', 'Network', 'No IPv6 (AAAA) record',
            'IPv6-only clients cannot reach the domain.',
            'Publish AAAA records for your web server.');
    }

    if (data.blacklist && data.blacklist.is_listed) {
        add('critical', 'Network', 'IP listed on DNSBL',
            'Listed on: ' + (data.blacklist.listed || []).join(', '),
            'Investigate the cause and request delisting after remediation.');
    }

    if (data.osint && data.osint.summary) {
        if (data.osint.summary.listed_in_threat_feeds) {
            add('critical', 'OSINT', 'Domain appears in open threat feeds',
                'ThreatFox / URLhaus / OTX returned indicators for this domain.',
                'Investigate compromise or abuse, then clean up and request delisting.');
        }
        if ((data.osint.summary.subdomain_count || 0) >= 25) {
            add('medium', 'OSINT', 'Large Certificate Transparency footprint',
                data.osint.summary.subdomain_count + ' related hostnames found in CT logs.',
                'Inventory and retire unused hostnames to reduce attack surface.');
        }
    }

    const risky = {21:'FTP unencrypted', 23:'Telnet unencrypted', 3306:'MySQL public', 3389:'RDP exposed', 5432:'PostgreSQL public'};
    if (data.ports && data.ports.open) {
        data.ports.open.forEach(p => {
            if (risky[p.port]) {
                add('high', 'Network', 'Risky port ' + p.port + '/' + p.service + ' open',
                    risky[p.port],
                    'Close the port on the public interface or restrict via firewall/VPN.');
            }
        });
    }

    // Security audit findings (from the backend) fold straight into the list
    if (data.security && data.security.findings) {
        data.security.findings.forEach(f => {
            let problem = f.detail || '';
            if (f.evidence) problem += ' (Evidence: ' + f.evidence + ')';
            add(f.severity || 'info', f.category || 'Security',
                f.title || 'Security finding', problem,
                f.fix || 'Review and remediate this finding.');
        });
    }

    recs.sort((a,b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
    return recs;
}

function renderRecommendations(data) {
    const el = $('recommendationsContent');
    const recs = Array.isArray(data.recommendations) && data.recommendations.length
        ? data.recommendations
        : generateRecommendations(data);
    const badge = $('recBadge');

    const counts = {critical:0,high:0,medium:0,low:0,info:0};
    recs.forEach(r => { counts[r.severity]++; });

    const total = recs.length;
    if (total === 0) {
        badge.textContent = '0';
        badge.className = 'tab-badge ok';
    } else {
        badge.textContent = String(total);
        badge.className = 'tab-badge';
    }

    if (recs.length === 0) {
        el.innerHTML = `<div class="rec-empty">${escapeHtml(t('advies.empty'))}</div>`;
        return;
    }

    let summary = '<div class="rec-summary">';
    SEVERITIES.forEach(s => {
        if (counts[s] > 0) {
            summary += `<span class="chip sev-${s}"><span class="chip-count">${counts[s]}</span> ${escapeHtml(s)}</span>`;
        }
    });
    summary += '</div>';

    let html = summary;
    recs.forEach(r => {
        const retest = r.retest || defaultRetest(r.category, r.title, data.domain);
        html += `<article class="rec sev-${escapeHtml(r.severity)}">
            <div class="rec-head">
                <span class="rec-badge sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity.toUpperCase())}</span>
                <span class="rec-category">${escapeHtml(r.category)}</span>
                <h4>${escapeHtml(r.title)}</h4>
            </div>
            <div class="rec-body">
                <p><strong>${escapeHtml(t('advies.problem'))}:</strong> ${escapeHtml(r.problem)}</p>
                <div class="rec-advies">
                    <p><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(r.fix)}</p>
                    <p><strong>${escapeHtml(t('advies.retest'))}:</strong> ${escapeHtml(retest)}</p>
                </div>
                ${r.reference ? `<p><strong>${escapeHtml(t('advies.reference'))}:</strong> <a href="${escapeHtml(r.reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.reference)}</a></p>` : ''}
            </div>
        </article>`;
    });

    el.innerHTML = html;
}

// ===== Report =====
function openReport() {
    if (!currentScanId) {
        showError('No saved scan yet. Run a scan first.');
        return;
    }
    window.open('/report/' + currentScanId, '_blank', 'noopener');
}

// ===== History Drawer =====
async function openHistory() {
    const drawer = $('historyDrawer');
    if (!drawer) return;
    drawer.classList.remove('hidden');
    showOverlay();
    await loadHistory();
}

function closeHistory() {
    // The drawers live on /reports and /monitoring now; on the scan page
    // there is nothing to close, and throwing here was being reported as a
    // network error by the caller's catch block.
    const drawer = $('historyDrawer');
    if (!drawer) return;
    // Rendered as a full page (/reports) it is a page-panel, not a drawer:
    // hiding it blanked the page with no way back but a reload.
    if (!drawer.classList.contains('drawer')) return;
    drawer.classList.add('hidden');
    syncOverlay();
}

async function loadHistory() {
    const list = $('historyList');
    const statsEl = $('historyStats');
    list.innerHTML = '<p class="history-empty">Loading…</p>';
    try {
        const resp = await fetch('/api/history?limit=100');
        const data = await resp.json();
        const stats = data.stats || {};
        statsEl.innerHTML = `<span><strong>${escapeHtml(String(stats.total_scans || 0))}</strong>scans</span>
            <span><strong>${escapeHtml(String(stats.unique_domains || 0))}</strong>domains</span>`;
        renderHistoryList(data.scans || []);
    } catch (err) {
        list.innerHTML = '<p class="history-empty">Failed to load history</p>';
    }
}

function renderHistoryList(scans) {
    const list = $('historyList');
    if (scans.length === 0) {
        list.innerHTML = '<p class="history-empty">No scans saved yet</p>';
        return;
    }
    list.innerHTML = '';
    scans.forEach(s => {
        const grade = s.grade || 'N/A';
        const gradeClass = 'g-' + grade.toLowerCase().replace('+', 'plus').replace('/', '');
        const when = s.created_at ? new Date(s.created_at).toLocaleString() : '';
        const item = document.createElement('div');
        item.className = 'history-item';

        const gradeDiv = document.createElement('div');
        gradeDiv.className = 'history-grade ' + (grade === 'N/A' ? 'g-na' : gradeClass);
        gradeDiv.textContent = grade;
        item.appendChild(gradeDiv);

        const main = document.createElement('div');
        main.className = 'history-main';
        const domainDiv = document.createElement('div');
        domainDiv.className = 'history-domain';
        domainDiv.textContent = s.domain;
        const metaDiv = document.createElement('div');
        metaDiv.className = 'history-meta';
        metaDiv.textContent = when + ' \u00b7 ' + (s.issues_count || 0) + ' finding(s)';
        main.appendChild(domainDiv);
        main.appendChild(metaDiv);
        item.appendChild(main);

        const actions = document.createElement('div');
        actions.className = 'history-item-actions';

        const loadBtn = document.createElement('button');
        loadBtn.textContent = 'Load';
        loadBtn.addEventListener('click', e => { e.stopPropagation(); loadScan(s.id); });
        actions.appendChild(loadBtn);

        const reportBtn = document.createElement('button');
        reportBtn.textContent = 'Report';
        reportBtn.addEventListener('click', e => { e.stopPropagation(); window.open('/report/' + s.id, '_blank', 'noopener'); });
        actions.appendChild(reportBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'danger';
        delBtn.textContent = '\u2715';
        delBtn.title = 'Delete';
        delBtn.addEventListener('click', e => { e.stopPropagation(); deleteScan(s.id); });
        actions.appendChild(delBtn);

        item.appendChild(actions);
        item.addEventListener('click', () => loadScan(s.id));
        list.appendChild(item);
    });
}

async function loadScan(scanId) {
    // History lives on its own page now, where there is nothing to render a
    // scan into — Load simply did nothing there. Hand it to the page that
    // can show it, which also makes a stored scan a shareable address.
    if (!$('domainInput')) {
        window.location.href = '/?scan=' + encodeURIComponent(scanId);
        return;
    }
    try {
        const resp = await fetch('/api/history/' + scanId);
        if (!resp.ok) { showError('Failed to load scan'); return; }
        const record = await resp.json();
        scanData = record.data;
        currentScanId = record.id;
        $('domainInput').value = record.domain;
        renderResults(record.data);
        closeHistory();
    } catch (err) {
        // Naming the cause matters: this fired after a successful render and
        // sent the reader off to check their connection.
        console.error('loadScan failed', err);
        showError('Could not open that scan: ' + (err && err.message ? err.message : err));
    }
}

async function deleteScan(scanId) {
    if (!confirm('Delete this scan from history?')) return;
    try {
        const resp = await fetch('/api/history/' + scanId, { method: 'DELETE' });
        if (!resp.ok) {
            showError('Failed to delete scan');
            return;
        }
        // Deleting a monitor's baseline is a side effect the database applies
        // silently, so it gets said out loud rather than discovered later in
        // monitoring as a report link that no longer goes anywhere.
        const data = await resp.json().catch(() => ({}));
        const affected = data.monitors_affected || [];
        if (affected.length) {
            const names = affected.map(m => m.name || m.target).join(', ');
            showError(`Deleted. ${names} lost the report it compares against; the next check re-establishes it.`);
        }
        await loadHistory();
    } catch (err) {
        showError('Failed to delete scan');
    }
}

async function clearHistory() {
    if (!confirm('Delete ALL saved scans? This cannot be undone.')) return;
    try {
        const resp = await fetch('/api/history', { method: 'DELETE' });
        if (resp.ok) await loadHistory();
    } catch (err) {
        showError('Failed to clear history');
    }
}

// ===== Monitor Drawer =====
async function openMonitors() {
    const drawer = $('monitorsDrawer');
    if (!drawer) return;
    monitorsDrawerOpen = true;
    drawer.classList.remove('hidden');
    showOverlay();
    syncImportMode();
    await loadMonitors();
    await loadRapid7Imports();
}

function closeMonitors() {
    const drawer = $('monitorsDrawer');
    if (!drawer) return;
    // Included as a full page (/monitoring) the block is a page-panel, not a
    // drawer: there are no results behind it to reveal, so closing it after a
    // scan just blanked the page.
    if (!drawer.classList.contains('drawer')) return;
    monitorsDrawerOpen = false;
    drawer.classList.add('hidden');
    syncOverlay();
}

function syncImportMode() {
    const mode = $('importModeInput').value;
    $('ovhFields').classList.toggle('hidden', mode !== 'ovhcloud');
    $('zoneTextInput').classList.toggle('hidden', mode !== 'zone_file');
}

async function loadMonitors() {
    const list = $('monitorList');
    const statsEl = $('monitorStats');
    const schedulerEl = $('schedulerStatus');
    list.innerHTML = '<p class="history-empty">Loading…</p>';
    try {
        const resp = await fetch('/api/monitors');
        const data = await resp.json();
        if (handleAuthFailure(resp, data)) return;
        const stats = data.stats || {};
        statsEl.innerHTML = `<span><strong>${escapeHtml(String(stats.total_monitors || 0))}</strong>monitors</span>
            <span><strong>${escapeHtml(String(stats.enabled_monitors || 0))}</strong>enabled</span>
            <span><strong>${escapeHtml(String(stats.due_monitors || 0))}</strong>due</span>
            <span><strong>${escapeHtml(String(stats.event_count || 0))}</strong>events</span>`;
        const scheduler = data.scheduler || {};
        schedulerEl.innerHTML = `<p class="status ${scheduler.enabled ? 'status-pass' : 'status-warn'}">${scheduler.enabled ? 'Background scheduler enabled' : 'Background scheduler disabled'}</p>
            <p class="monitor-meta">Poll interval: ${escapeHtml(String(scheduler.poll_seconds || 0))} seconds</p>`;
        renderMonitorList(data.monitors || []);
        renderMonitorEvents(data.events || []);
    } catch (err) {
        list.innerHTML = '<p class="history-empty">Failed to load monitors</p>';
        schedulerEl.innerHTML = '';
    }
}

function reportLink(scanId, label, timestamp) {
    const when = timestamp ? ' · ' + escapeHtml(new Date(timestamp).toLocaleString()) : '';
    return `<a href="/report/${escapeHtml(String(scanId))}" target="_blank" rel="noopener">${escapeHtml(label)}${when}</a>`;
}

function monitorReportLinks(m) {
    // Two reports, deliberately separate. The monitor check is the run that
    // change detection is based on; the latest scan is simply the newest
    // report for this domain, including manual scans the monitor never saw.
    // Showing only the monitor's own scan was what made the link look stale.
    const links = [];
    if (m.last_scan_id) {
        links.push(reportLink(m.last_scan_id, 'monitor check', m.last_scan_at));
    } else if (m.last_scan_at) {
        // The scan_id is a foreign key with ON DELETE SET NULL, so deleting a
        // scan from the history silently empties it. Saying "not scanned yet"
        // there is simply false — the monitor ran, its report is gone.
        links.push(`<span class="muted">monitor check · ${escapeHtml(new Date(m.last_scan_at).toLocaleString())} · report deleted</span>`);
    } else {
        links.push('<span class="muted">no monitor check yet</span>');
    }
    const latest = m.latest_scan;
    if (latest && latest.id && String(latest.id) !== String(m.last_scan_id)) {
        links.push(reportLink(latest.id, 'latest scan', latest.created_at));
    }
    return links.join(' · ');
}

function renderMonitorList(monitors) {
    const list = $('monitorList');
    if (monitors.length === 0) {
        list.innerHTML = '<p class="history-empty">No monitors configured yet</p>';
        return;
    }
    list.innerHTML = '';
    monitors.forEach(m => {
        const item = document.createElement('div');
        item.className = 'monitor-item';

        const main = document.createElement('div');
        main.className = 'monitor-main';
        main.innerHTML = `<div class="monitor-name">${escapeHtml(m.name)}</div>
            <div class="monitor-meta">${escapeHtml(m.target)} · ${escapeHtml(m.record_type)} · ${escapeHtml(formatFrequency(m.schedule_minutes))}</div>
            <div class="monitor-meta">${escapeHtml(m.source_label || m.source_type)}${m.next_scan_at ? ' · next: ' + escapeHtml(new Date(m.next_scan_at).toLocaleString()) : ''}</div>
            <div class="monitor-meta">${monitorReportLinks(m)}</div>`;
        item.appendChild(main);

        const actions = document.createElement('div');
        actions.className = 'monitor-actions';

        const scanBtn = document.createElement('button');
        scanBtn.textContent = 'Run now';
        scanBtn.title = 'Run this monitor\'s scan immediately, regardless of its schedule';
        scanBtn.addEventListener('click', e => {
            e.stopPropagation();
            runMonitorScan(m.id, scanBtn);
        });
        actions.appendChild(scanBtn);

        const toggleBtn = document.createElement('button');
        toggleBtn.textContent = m.enabled ? 'Pause' : 'Enable';
        toggleBtn.addEventListener('click', e => {
            e.stopPropagation();
            toggleMonitor(m);
        });
        actions.appendChild(toggleBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'danger';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', e => {
            e.stopPropagation();
            deleteMonitor(m.id);
        });
        actions.appendChild(delBtn);

        item.appendChild(actions);
        list.appendChild(item);
    });
}

async function createMonitor() {
    const domain = $('monitorDomainInput').value.trim();
    if (!domain) {
        showError('Enter a domain or hostname to monitor');
        return;
    }
    const name = $('monitorNameInput').value.trim();
    const schedule_minutes = Number($('monitorScheduleInput').value || 1440);
    const record_type = $('monitorTypeInput').value;
    try {
        const resp = await fetch('/api/monitors', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, target: domain, name, schedule_minutes, record_type }),
        });
        const data = await resp.json();
        if (!resp.ok || data.error) {
            showError(data.error || 'Failed to create monitor');
            return;
        }
        $('monitorDomainInput').value = '';
        $('monitorNameInput').value = '';
        await loadMonitors();
    } catch (err) {
        showError('Network error while creating monitor');
    }
}

async function importMonitors() {
    const mode = $('importModeInput').value;
    const domain = $('importDomainInput').value.trim();
    if (!domain) {
        showError('Enter the zone name to import');
        return;
    }

    const payload = {
        mode,
        domain,
        zone_name: domain,
        schedule_minutes: Number($('monitorScheduleInput').value || 1440),
    };
    if (mode === 'zone_file') {
        payload.zone_text = $('zoneTextInput').value;
    } else {
        payload.endpoint = $('ovhEndpointInput').value.trim();
        payload.app_key = $('ovhAppKeyInput').value.trim();
        payload.app_secret = $('ovhAppSecretInput').value.trim();
        payload.consumer_key = $('ovhConsumerKeyInput').value.trim();
    }

    try {
        const resp = await fetch('/api/monitors/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok || data.error) {
            showError(data.error || 'Failed to import monitors');
            return;
        }
        showToast(`Imported ${data.imported} monitor(s) from ${mode === 'zone_file' ? 'the zone file' : 'OVHcloud'}.`);
        await loadMonitors();
    } catch (err) {
        showError('Network error while importing monitors');
    }
}

async function runMonitorScan(monitorId, btn) {
    // The scan runs on the server either way; what was missing was any sign
    // that it had started. This block renders as its own page (/monitoring),
    // which has no progress bar at all, so the percentage goes on the button
    // that was just pressed.
    const label = btn ? btn.textContent : null;
    const setLabel = text => { if (btn) btn.textContent = text; };
    if (btn) btn.disabled = true;
    setLabel('Starting…');
    try {
        const resp = await fetch('/api/monitors/' + monitorId + '/scan/start', { method: 'POST' });
        const data = await resp.json();
        if (handleAuthFailure(resp, data)) return;
        // 409 means this domain is already being scanned — follow that job
        // instead of starting a second one against the same domain.
        if ((!resp.ok && resp.status !== 409) || !data.job_id) {
            showError(data.error || 'Monitor scan failed');
            return;
        }
        rememberJob(data.job_id, data.domain);
        showScanning(data.domain);
        await followJob(data.job_id, {
            onProgress: job => setLabel(job ? `Scanning… ${job.percent || 0}%` : 'Run now'),
            onDone: async job => {
                await loadMonitors();
                if (job.status !== 'error') closeMonitors();
            },
        });
    } catch (err) {
        showError('Network error while running monitor scan');
    } finally {
        // loadMonitors() re-renders the list, so this button may already be
        // detached; restoring it then would write to nothing.
        if (btn && btn.isConnected) {
            btn.disabled = false;
            if (label) btn.textContent = label;
        }
    }
}

async function runDueMonitors() {
    try {
        const resp = await fetch('/api/monitors/run-due', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok || data.error) {
            showError(data.error || 'Failed to run due monitors');
            return;
        }
        if ((data.processed || 0) === 0) {
            showError(data.running ? 'Scheduler is already processing monitors' : 'No due monitors to run');
        }
        await loadMonitors();
    } catch (err) {
        showError('Network error while running due monitors');
    }
}

async function toggleMonitor(monitor) {
    try {
        const resp = await fetch('/api/monitors/' + monitor.id, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: !monitor.enabled }),
        });
        const data = await resp.json();
        if (!resp.ok || data.error) {
            showError(data.error || 'Failed to update monitor');
            return;
        }
        await loadMonitors();
    } catch (err) {
        showError('Network error while updating monitor');
    }
}

async function deleteMonitor(monitorId) {
    if (!confirm('Delete this monitor?')) return;
    try {
        const resp = await fetch('/api/monitors/' + monitorId, { method: 'DELETE' });
        if (resp.ok) await loadMonitors();
        else showError('Failed to delete monitor');
    } catch (err) {
        showError('Network error while deleting monitor');
    }
}

function renderMonitorEvents(events) {
    const el = $('monitorEventList');
    if (!events.length) {
        el.innerHTML = '<p class="history-empty">No monitor events yet</p>';
        return;
    }
    el.innerHTML = events.map(event => {
        const when = event.created_at ? new Date(event.created_at).toLocaleString() : '';
        // An event is a point in time, so this links to the scan that
        // detected it — deliberately not the newest report. "open scan
        // report" read as "the current one" and made the link look stale.
        const scanLink = event.scan_id
            ? ` · <a href="/report/${escapeHtml(String(event.scan_id))}" target="_blank" rel="noopener">report at time of change</a>`
            : ' · <span class="muted">report deleted</span>';
        const snLink = event.servicenow_number
            ? ` · <span class="muted">${escapeHtml(event.servicenow_number)}</span>`
            : '';
        return `<div class="event-item sev-${escapeHtml(event.severity)}">
            <div class="event-head">
                <span class="rec-badge sev-${escapeHtml(event.severity)}">${escapeHtml((event.severity || 'info').toUpperCase())}</span>
                <span class="monitor-meta">${escapeHtml(event.monitor_name || event.monitor_target || '')} · ${escapeHtml(when)}</span>
            </div>
            <div class="event-summary">${escapeHtml(event.summary)}</div>
            <div class="monitor-meta">${escapeHtml(event.event_type || '')}${scanLink}${snLink}</div>
        </div>`;
    }).join('');
}

// ===== Remediation plan =====
function renderRemediationPlan(data) {
    const el = $('remediationPlan');
    if (!el) return;
    const plan = data.remediation_plan || (data.recommendations || [])
        .filter(r => ['critical', 'high', 'medium'].includes(r.severity))
        .slice(0, 12)
        .map((r, idx) => ({
            priority: idx + 1,
            severity: r.severity,
            title: r.title,
            action: r.fix || r.action,
            retest: r.retest,
        }));
    if (!plan.length) {
        el.innerHTML = `<div class="rec-empty">${escapeHtml(t('advies.none_priority'))}</div>`;
        return;
    }
    el.innerHTML = `<h4 style="margin:0 0 0.75rem;color:var(--accent)">${escapeHtml(t('advies.priority'))}</h4><ol class="remediation-list">` +
        plan.map(item => `<li class="sev-${escapeHtml(item.severity)}"><strong>${escapeHtml(String(item.priority))}. ${escapeHtml(item.title)}</strong><div class="monitor-meta"><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(item.action || '')}</div>${item.retest ? `<div class="monitor-meta"><strong>${escapeHtml(t('advies.retest'))}:</strong> ${escapeHtml(item.retest)}</div>` : ''}</li>`).join('') +
        '</ol>';
}

// ===== Weak authentication =====
function renderWeakAuth(data) {
    const el = $('weakAuthContent');
    if (!el) return;
    if (!data) {
        el.innerHTML = '<p class="status status-warn">Weak-auth check not selected.</p>';
        return;
    }
    if (data.skipped) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.detail || 'Disabled in config (weak_auth.enabled=false).')}</p>`;
        return;
    }
    if (!data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'Weak-auth scan failed')}</p>`;
        return;
    }
    const protectedCount = (data.protected_endpoints || []).length;
    const findings = data.findings || [];
    let html = `<p>${escapeHtml(data.detail || '')}</p>`;
    html += `<table class="data-table"><tr><th>Protected endpoints</th><td>${protectedCount}</td></tr>`;
    html += `<tr><th>Attempts</th><td>${escapeHtml(String(data.attempts || 0))}</td></tr>`;
    html += `<tr><th>Weak credentials</th><td><span class="status ${findings.length ? 'status-fail' : 'status-pass'}">${findings.length ? 'FOUND' : 'None detected'}</span></td></tr></table>`;
    if (findings.length) {
        html += '<table class="data-table"><thead><tr><th>URL</th><th>User</th><th>Password</th><th>Method</th><th>Status</th></tr></thead><tbody>';
        for (const f of findings) {
            html += `<tr><td><code>${escapeHtml(f.url || '')}</code></td><td>${escapeHtml(f.username || '')}</td><td><code>${escapeHtml(f.password_masked || '••••')}</code></td><td>${escapeHtml(f.method || '')}</td><td>${escapeHtml(String(f.status_code || ''))}</td></tr>`;
        }
        html += '</tbody></table>';
    }
    el.innerHTML = html;
}

// ===== JS Dependencies & Secrets (passive) =====
function renderJsScan(data) {
    const el = $('jsScanContent');
    if (!el) return;
    if (!data) {
        el.innerHTML = '<p class="status status-warn">JS scan not selected.</p>';
        return;
    }
    if (!data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'JS scan failed')}</p>`;
        return;
    }
    const libs = data.vulnerable_libraries || [];
    const secrets = data.secrets_found || [];
    const missingSri = data.missing_sri || [];

    let html = `<table class="data-table">`;
    html += `<tr><th>Base URL</th><td><code>${escapeHtml(data.base_url || '')}</code></td></tr>`;
    html += `<tr><th>Scripts analyzed</th><td>${escapeHtml(String(data.scripts_analyzed || 0))}</td></tr>`;
    html += `<tr><th>Vulnerable libraries</th><td><span class="status ${libs.length ? 'status-fail' : 'status-pass'}">${libs.length ? `${libs.length} found` : 'None detected'}</span></td></tr>`;
    html += `<tr><th>Exposed secrets</th><td><span class="status ${secrets.length ? 'status-fail' : 'status-pass'}">${secrets.length ? `${secrets.length} found` : 'None detected'}</span></td></tr>`;
    html += `<tr><th>Missing SRI</th><td><span class="status ${missingSri.length ? 'status-warn' : 'status-pass'}">${missingSri.length ? `${missingSri.length} tag(s)` : 'None'}</span></td></tr>`;
    html += `</table>`;

    if (libs.length) {
        html += '<p style="margin-top:0.75rem;font-weight:600">Vulnerable libraries:</p>';
        html += '<table class="data-table"><thead><tr><th>Library</th><th>Version</th><th>CVEs</th><th>Source</th></tr></thead><tbody>';
        for (const lib of libs) {
            html += `<tr><td>${escapeHtml(lib.library)}</td><td>${escapeHtml(lib.version)}</td><td>${escapeHtml((lib.cves || []).join(', '))}</td><td style="word-break:break-all"><code>${escapeHtml(lib.source || '')}</code></td></tr>`;
        }
        html += '</tbody></table>';
    }

    if (secrets.length) {
        html += '<p style="margin-top:0.75rem;font-weight:600">Exposed secrets:</p>';
        html += '<table class="data-table"><thead><tr><th>Type</th><th>Masked value</th><th>Source</th></tr></thead><tbody>';
        for (const s of secrets) {
            html += `<tr><td>${escapeHtml(s.type)}</td><td><code>${escapeHtml(s.masked_value)}</code></td><td style="word-break:break-all"><code>${escapeHtml(s.source || '')}</code></td></tr>`;
        }
        html += '</tbody></table>';
    }

    if (missingSri.length) {
        html += '<p style="margin-top:0.75rem;font-weight:600">Third-party tags without SRI:</p>';
        html += '<table class="data-table"><thead><tr><th>Tag</th><th>Source</th></tr></thead><tbody>';
        for (const m of missingSri) {
            html += `<tr><td>${escapeHtml(m.tag)}</td><td style="word-break:break-all"><code>${escapeHtml(m.src || '')}</code></td></tr>`;
        }
        html += '</tbody></table>';
    }

    el.innerHTML = html;
}

// ===== Active Vulnerability Scan =====
function renderActiveScan(data) {
    const el = $('activeScanContent');
    if (!el) return;
    if (!data) {
        el.innerHTML = '<p class="status status-warn">Active scan not selected.</p>';
        return;
    }
    if (data.skipped) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.detail || 'Disabled in config (active_scan.enabled=false).')}</p>`;
        return;
    }
    if (!data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'Active scan failed')}</p>`;
        return;
    }
    const findings = data.findings || [];
    let html = `<p>${escapeHtml(data.detail || '')}</p>`;
    html += `<table class="data-table">`;
    html += `<tr><th>Pages crawled</th><td>${escapeHtml(String(data.pages_crawled || 0))}</td></tr>`;
    html += `<tr><th>Targets discovered</th><td>${escapeHtml(String(data.targets_discovered || 0))}</td></tr>`;
    html += `<tr><th>Requests sent</th><td>${escapeHtml(String(data.attempts || 0))} / ${escapeHtml(String(data.max_requests || 0))}</td></tr>`;
    html += `<tr><th>Vulnerabilities</th><td><span class="status ${findings.length ? 'status-fail' : 'status-pass'}">${findings.length ? `${findings.length} FOUND` : 'None detected'}</span></td></tr>`;
    html += `</table>`;

    if (findings.length) {
        html += '<table class="data-table"><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Evidence</th></tr></thead><tbody>';
        for (const f of findings) {
            html += `<tr><td>${escapeHtml(f.type)}</td><td style="word-break:break-all"><code>${escapeHtml(f.url || '')}</code></td><td>${escapeHtml(f.param || '')}</td><td>${escapeHtml(f.evidence || '')}</td></tr>`;
        }
        html += '</tbody></table>';
    }

    el.innerHTML = html;
}

// ===== HubSpot / Cloudflare =====
function renderHubspot(data) {
    const summaryEl = $('hubspotSummary');
    const findingsEl = $('hubspotFindings');
    if (!summaryEl || !findingsEl) return;
    if (!data || !data.success) {
        summaryEl.innerHTML = `<p class="status status-warn">${escapeHtml(data?.error || 'HubSpot/Cloudflare scan not available')}</p>`;
        findingsEl.innerHTML = '';
        return;
    }
    const hs = data.hubspot || {};
    const cf = data.cloudflare || {};
    summaryEl.innerHTML = `<table class="data-table">
        <tr><th>HubSpot</th><td><span class="status ${hs.detected ? 'status-pass' : 'status-warn'}">${hs.detected ? 'Detected' : 'Not detected'}</span></td></tr>
        <tr><th>Cloudflare</th><td><span class="status ${cf.detected ? 'status-pass' : 'status-warn'}">${cf.detected ? 'Detected' : 'Not detected'}</span></td></tr>
        <tr><th>Behind Cloudflare</th><td>${data.behind_cloudflare ? 'Yes' : 'No'}</td></tr>
        <tr><th>Portal IDs</th><td>${escapeHtml((hs.portal_ids || []).join(', ') || '-')}</td></tr>
        <tr><th>Cookies</th><td>${escapeHtml((data.cookies_seen || []).join(', ') || '-')}</td></tr>
        <tr><th>Final status</th><td>${escapeHtml(String(data.final_status || '-'))}</td></tr>
    </table>`;

    const findings = data.findings || [];
    if (!findings.length) {
        findingsEl.innerHTML = '<div class="rec-empty">No HubSpot/Cloudflare remediation items.</div>';
        return;
    }
    findingsEl.innerHTML = findings.map(f => `<article class="rec sev-${escapeHtml(f.severity)}">
        <div class="rec-head">
            <span class="rec-badge sev-${escapeHtml(f.severity)}">${escapeHtml((f.severity || 'info').toUpperCase())}</span>
            <h4>${escapeHtml(f.title)}</h4>
        </div>
        <div class="rec-body">
            <p><strong>${escapeHtml(t('advies.problem'))}:</strong> ${escapeHtml(f.problem || '')}</p>
            <p><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(f.fix || '')}</p>
            ${f.reference ? `<p><strong>${escapeHtml(t('advies.reference'))}:</strong> <a href="${escapeHtml(f.reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(f.reference)}</a></p>` : ''}
        </div>
    </article>`).join('');
}

// ===== Rapid7 InsightVM / Nexpose =====
function renderRapid7(data) {
    const summaryEl = $('rapid7Summary');
    const findingsEl = $('rapid7Findings');
    if (!summaryEl || !findingsEl) return;

    if (!data) {
        summaryEl.innerHTML = `<p class="status status-warn">${escapeHtml(t('rapid7_ui.empty'))}</p>`;
        findingsEl.innerHTML = '';
        return;
    }
    if (data.disabled) {
        summaryEl.innerHTML = `<p class="status status-warn">${escapeHtml(t('rapid7_ui.disabled'))}</p>`;
        findingsEl.innerHTML = '';
        return;
    }
    if (!data.success) {
        summaryEl.innerHTML = `<p class="status status-warn">${escapeHtml(data.error || t('rapid7_ui.empty'))}</p>`;
        findingsEl.innerHTML = '';
        return;
    }

    const bySev = data.by_severity || {};
    const sevChips = Object.keys(bySev).map(s =>
        `<span class="chip sev-${escapeHtml(s)}"><span class="chip-count">${escapeHtml(String(bySev[s]))}</span> ${escapeHtml(s)}</span>`
    ).join('');
    summaryEl.innerHTML = `<table class="data-table">
        <tr><th>Matched findings</th><td>${escapeHtml(String(data.finding_count || 0))}</td></tr>
        <tr><th>By severity</th><td><div class="rec-summary">${sevChips || '-'}</div></td></tr>
        <tr><th>Source</th><td>InsightVM / Nexpose export</td></tr>
    </table>`;

    const findings = data.findings || [];
    if (!findings.length) {
        findingsEl.innerHTML = `<div class="rec-empty">${escapeHtml(t('rapid7_ui.empty'))}</div>`;
        return;
    }
    findingsEl.innerHTML = findings.map(f => {
        const cves = (f.cves || []).join(', ');
        const host = f.hostname || f.asset_ip || '-';
        const loc = f.port ? `${host}:${f.port}` : host;
        return `<article class="rec sev-${escapeHtml(f.severity || 'info')}">
            <div class="rec-head">
                <span class="rec-badge sev-${escapeHtml(f.severity || 'info')}">${escapeHtml((f.severity || 'info').toUpperCase())}</span>
                <h4>${escapeHtml(f.title || '')}</h4>
            </div>
            <div class="rec-body">
                <p><strong>Asset:</strong> ${escapeHtml(loc)}</p>
                ${f.cvss != null ? `<p><strong>CVSS:</strong> ${escapeHtml(String(f.cvss))}</p>` : ''}
                ${cves ? `<p><strong>CVE:</strong> ${escapeHtml(cves)}</p>` : ''}
                ${f.description ? `<p><strong>${escapeHtml(t('advies.problem'))}:</strong> ${escapeHtml(f.description)}</p>` : ''}
                ${f.solution ? `<p><strong>${escapeHtml(t('advies.fix'))}:</strong> ${escapeHtml(f.solution)}</p>` : ''}
            </div>
        </article>`;
    }).join('');
}

async function uploadRapid7Export() {
    const input = $('rapid7FileInput');
    const status = $('rapid7ImportStatus');
    if (!input || !input.files || !input.files[0]) {
        showError('Select a CSV or XLSX InsightVM/Nexpose export first.');
        return;
    }
    const form = new FormData();
    form.append('file', input.files[0]);
    if (status) status.innerHTML = `<p class="history-empty">${escapeHtml(t('common.loading'))}</p>`;
    try {
        const resp = await fetch('/api/vuln-imports', { method: 'POST', body: form });
        const data = await resp.json();
        if (handleAuthFailure(resp, data)) return;
        if (!resp.ok) {
            showError(data.error || 'Import failed');
            if (status) status.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'Import failed')}</p>`;
            return;
        }
        const s = data.summary || {};
        if (status) {
            status.innerHTML = `<p class="status status-pass">Imported ${escapeHtml(String(s.findings || 0))} findings across ${escapeHtml(String(s.assets || 0))} assets.</p>`;
        }
        await loadRapid7Imports();
    } catch (err) {
        showError(t('errors.network'));
    }
}

async function syncRapid7Api() {
    const status = $('rapid7ImportStatus');
    if (status) status.innerHTML = `<p class="history-empty">${escapeHtml(t('common.loading'))}</p>`;
    try {
        const resp = await fetch('/api/vuln-imports/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await resp.json();
        if (handleAuthFailure(resp, data)) return;
        if (!resp.ok || !data.ok) {
            showError(data.error || 'API sync failed');
            if (status) status.innerHTML = `<p class="status status-fail">${escapeHtml(data.error || 'API sync failed')}</p>`;
            return;
        }
        const s = data.summary || {};
        if (status) {
            status.innerHTML = `<p class="status status-pass">API sync (${escapeHtml(data.mode || '')}): ${escapeHtml(String(s.findings || data.findings_stored || 0))} findings · ${escapeHtml(String(s.assets || 0))} assets</p>`;
        }
        await loadRapid7Imports();
    } catch (err) {
        showError(t('errors.network'));
    }
}

async function loadRapid7Imports() {
    const list = $('rapid7ImportList');
    if (!list) return;
    list.innerHTML = `<p class="history-empty">${escapeHtml(t('common.loading'))}</p>`;
    try {
        const resp = await fetch('/api/vuln-imports');
        const data = await resp.json();
        if (handleAuthFailure(resp, data)) return;
        const imports = data.imports || [];
        if (!imports.length) {
            list.innerHTML = `<p class="history-empty">${escapeHtml(t('rapid7_ui.empty'))}</p>`;
            return;
        }
        list.innerHTML = imports.map(item => {
            const by = (item.summary && item.summary.by_severity) || {};
            const sev = Object.keys(by).map(k => `${k}:${by[k]}`).join(' · ') || '-';
            return `<div class="event-item">
                <strong>${escapeHtml(item.filename || ('#' + item.id))}</strong>
                <div class="monitor-meta">${escapeHtml(item.source_format || '')} · ${escapeHtml(String(item.finding_count || 0))} findings · ${escapeHtml(sev)}</div>
                <div class="monitor-meta">${escapeHtml(item.imported_at || '')}</div>
            </div>`;
        }).join('');
    } catch (err) {
        list.innerHTML = `<p class="status status-fail">${escapeHtml(t('errors.network'))}</p>`;
    }
}

function formatCacheAge(seconds) {
    const n = Number(seconds) || 0;
    if (n < 3600) return `${Math.max(1, Math.round(n / 60))} min`;
    const hours = n / 3600;
    return hours < 24 ? `${Math.round(hours)} h` : `${Math.round(hours / 24)} d`;
}

function cacheNote(section) {
    if (!section || !section.cached) return '';
    return `<p class="monitor-meta">Reused from an earlier lookup ${escapeHtml(formatCacheAge(section.cache_age_seconds))} ago — tick "Force fresh third-party lookups" to query again.</p>`;
}

// ===== OSINT =====
function renderOsint(data) {
    const summaryEl = $('osintSummary');
    const ctEl = $('osintCt');
    const ipEl = $('osintIp');
    const wbEl = $('osintWayback');
    const threatEl = $('osintThreats');
    if (!summaryEl) return;

    if (!data || !data.success) {
        const msg = `<p class="status status-warn">${escapeHtml(data?.error || 'OSINT not available')}</p>`;
        summaryEl.innerHTML = msg;
        ctEl.innerHTML = ipEl.innerHTML = wbEl.innerHTML = threatEl.innerHTML = '';
        return;
    }

    const s = data.summary || {};
    const threatCls = s.listed_in_threat_feeds ? 'status-fail' : 'status-pass';
    // Cached data is still an answer, but it is yesterday's answer, and a
    // silent reuse would read as a fresh confirmation that nothing changed.
    summaryEl.innerHTML = cacheNote(data) + `<table class="data-table">
        <tr><th>Related hostnames (CT)</th><td>${escapeHtml(String(s.subdomain_count || 0))}</td></tr>
        <tr><th>Wayback snapshots</th><td>${escapeHtml(String(s.wayback_count || 0))}</td></tr>
        <tr><th>Threat feed hits</th><td><span class="status ${threatCls}">${escapeHtml(String(s.threat_hits || 0))}</span></td></tr>
        <tr><th>IP</th><td>${escapeHtml(s.ip || '-')}</td></tr>
        <tr><th>ASN</th><td>${escapeHtml(s.asn || '-')}</td></tr>
        <tr><th>Country</th><td>${escapeHtml(s.country || '-')}</td></tr>
    </table>`;

    const ct = data.sources?.certificate_transparency || {};
    if (!ct.success) {
        ctEl.innerHTML = `<p class="status status-warn">${escapeHtml(ct.error || 'crt.sh lookup failed')}</p>`;
    } else {
        const hosts = (ct.subdomains || []).slice(0, 40).map(h => `<div class="dns-record"><span class="record-type">HOST</span><span class="dns-value">${escapeHtml(h)}</span></div>`).join('');
        ctEl.innerHTML = `<p class="status status-pass">${escapeHtml(String(ct.subdomain_count || 0))} related hostname(s) · ${escapeHtml(String(ct.certificate_count || 0))} cert row(s)</p>${hosts || '<p class="history-empty">No related hostnames found</p>'}`;
    }

    const ip = data.sources?.ip_context || {};
    if (!ip.success) {
        ipEl.innerHTML = `<p class="status status-warn">${escapeHtml(ip.error || 'IP context unavailable')}</p>`;
    } else {
        const g = ip.geo || {};
        ipEl.innerHTML = `<table class="data-table">
            <tr><th>IP</th><td>${escapeHtml(ip.ip || '-')}</td></tr>
            <tr><th>Country</th><td>${escapeHtml(g.country || '-')}</td></tr>
            <tr><th>City</th><td>${escapeHtml(g.city || '-')}</td></tr>
            <tr><th>ISP</th><td>${escapeHtml(g.isp || '-')}</td></tr>
            <tr><th>Org</th><td>${escapeHtml(g.org || '-')}</td></tr>
            <tr><th>ASN</th><td>${escapeHtml(g.asn || '-')}</td></tr>
            <tr><th>Hosting</th><td>${g.hosting ? 'Yes' : 'No'}</td></tr>
            <tr><th>Proxy</th><td>${g.proxy ? 'Yes' : 'No'}</td></tr>
        </table>`;
    }

    const wb = data.sources?.wayback || {};
    if (!wb.success) {
        wbEl.innerHTML = `<p class="status status-warn">${escapeHtml(wb.error || 'Wayback lookup failed')}</p>`;
    } else if (!(wb.snapshots || []).length) {
        wbEl.innerHTML = '<p class="history-empty">No Wayback snapshots found</p>';
    } else {
        wbEl.innerHTML = (wb.snapshots || []).map(s => `<div class="dns-record"><span class="record-type">${escapeHtml(String(s.status || ''))}</span><span class="dns-value"><a href="${escapeHtml(s.archive_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.timestamp)} · ${escapeHtml(s.url)}</a></span></div>`).join('');
    }

    const tf = data.sources?.threatfox || {};
    const uh = data.sources?.urlhaus || {};
    const otx = data.sources?.otx || {};
    let threatHtml = '';
    [tf, uh, otx].forEach(src => {
        if (!src || !src.source) return;
        if (src.skipped) {
            // The raw message is just a bare env var name; say where it goes.
            threatHtml += `<p class="status status-warn">${escapeHtml(src.source)}: ${escapeHtml(src.message || 'not configured')} — see <a href="/admin/settings">Settings → Optional API keys</a> for where to set this.</p>`;
            return;
        }
        if (!src.success) {
            threatHtml += `<p class="status status-warn">${escapeHtml(src.source)}: ${escapeHtml(src.error || 'failed')}</p>`;
            return;
        }
        const count = src.hit_count || src.url_count || src.pulses || 0;
        const cls = count > 0 ? 'status-fail' : 'status-pass';
        threatHtml += `<p class="status ${cls}">${escapeHtml(src.source)}: ${escapeHtml(String(count))} hit(s)</p>`;
        // A partial result: the threat signal came through, only the extra
        // context did not. Say so instead of implying the whole feed failed.
        if (src.passive_dns_error) {
            threatHtml += `<p class="http-meta"><span>Passive DNS unavailable (${escapeHtml(src.passive_dns_error)}) — the pulse count above is still valid.</span></p>`;
        }
    });
    threatEl.innerHTML = threatHtml || '<p class="history-empty">No threat intel results</p>';
}

// ===== Ports =====
function renderPorts(data) {
    const el = $('portsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }

    let html = '';
    if (data.ip) html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">IP: ${escapeHtml(data.ip)}</p>`;
    html += `<p style="margin-bottom:0.75rem">${escapeHtml(String(data.open?.length || 0))} open port(s) found</p>`;

    html += '<div class="port-grid">';
    for (const p of (data.open || [])) {
        html += `<div class="port-item port-open"><span class="port-dot"></span> ${escapeHtml(String(p.port))} <span style="color:var(--text-muted)">${escapeHtml(p.service)}</span></div>`;
    }
    for (const p of (data.closed || [])) {
        html += `<div class="port-item port-closed"><span class="port-dot"></span> ${escapeHtml(String(p.port))} <span style="color:var(--text-muted)">${escapeHtml(p.service)}</span></div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}

