// Tools -> Versions: known vulnerable software versions across the
// organisation's sites. Uses $, esc, requestJson and toast from lookup.js.
// The domains go to the server ten at a time, so a portfolio of hundreds
// is checked without one request running for minutes, and the table fills
// in as it goes.

const VC_BATCH = 10;
const VC_VERDICT = {
    vulnerable: ['Vulnerable', 'status-fail', 0],
    cannot_tell: ['Cannot tell from outside', 'status-warn', 1],
    fixed: ['Has the fix', 'status-pass', 3],
};
let vcRows = [];
let vcStop = false;

// The domains of the portfolio that have a website: held (not to cancel
// or only wanted), and web in use or not yet measured.
async function vcPortfolioDomains() {
    const data = await requestJson('/api/portfolio');
    return (data.domains || [])
        .filter(d => !['cancel', 'claim'].includes(d.lifecycle) && d.uses_web !== 'no')
        .map(d => d.domain);
}

function vcPasted() {
    return [...new Set($('vcDomains').value.split(/[\s,;]+/).map(s => s.trim().toLowerCase()
        .replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(s => s.includes('.')))];
}

// One row per domain: what the server shows, and the verdict per advisory.
// "No PHP seen" and "no response" are their own states, never "has the fix".
function vcState(r) {
    if (r.state !== 'measured') return ['No response', 'status-warn', 2];
    if (!(r.advisories || []).length) return ['No PHP seen', 'muted', 4];
    const worst = r.advisories.map(a => VC_VERDICT[a.verdict] || VC_VERDICT.cannot_tell).sort((a, b) => a[2] - b[2])[0];
    return worst;
}

function vcRender() {
    const sorted = [...vcRows].sort((a, b) => vcState(a)[2] - vcState(b)[2] || a.domain.localeCompare(b.domain));
    const count = label => vcRows.filter(r => vcState(r)[0] === label).length;
    const summary = ['Vulnerable', 'Cannot tell from outside', 'Has the fix', 'No PHP seen', 'No response']
        .map(label => `<span class="vc-count"><strong>${count(label)}</strong> ${esc(label)}</span>`).join('');
    $('vcResult').innerHTML = `<section class="card"><div class="lc-head"><h3>${esc(`${vcRows.length} site(s) checked`)}</h3>`
        + '<button class="btn-ghost-sm" id="vcExport" type="button">Export CSV</button></div>'
        + `<div class="vc-counts">${summary}</div>`
        + '<div class="users-table-wrap"><table class="data-table stack-table vc-table">'
        + '<tr><th>Domain</th><th>Result</th><th>Shown by the server</th><th>Why</th></tr>'
        + sorted.map(r => {
            const [label, cls] = vcState(r);
            const shown = [r.powered_by, r.server].filter(Boolean).join(' · ');
            // The advisory's name and its reason apart, each its own text.
            const why = r.state !== 'measured' ? `<span>${esc(r.error || '')}</span>`
                : (r.advisories || []).map(a => `<div><strong>${esc(a.name)}</strong> <span>${esc(a.reason)}</span></div>`).join('');
            return `<tr><td><code>${esc(r.domain)}</code></td><td><span class="status ${cls}">${esc(label)}</span></td>`
                + `<td>${shown ? `<code>${esc(shown)}</code>` : '<span class="muted">—</span>'}</td>`
                + `<td>${why}</td></tr>`;
        }).join('')
        + '</table></div></section>';
    $('vcExport').addEventListener('click', vcExport);
}

// The table as CSV, made on the server so every cell passes the formula
// guard the other exports use: the server headers are not ours to trust.
async function vcExport() {
    try {
        const resp = await fetch('/api/advisories/csv', { method: 'POST',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ results: vcRows }) });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const name = (resp.headers.get('Content-Disposition') || '').match(/filename=([^;]+)/);
        const link = document.createElement('a');
        link.href = URL.createObjectURL(await resp.blob());
        link.download = name ? name[1] : 'domainlens-versions.csv';
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    } catch (err) { toast(err.message); }
}

async function vcRun() {
    let domains;
    try {
        domains = $('vcScope').value === 'portfolio' ? await vcPortfolioDomains() : vcPasted();
    } catch (err) { toast(err.message); return; }
    if (!domains.length) { toast('No domains to check.'); return; }
    vcRows = [];
    vcStop = false;
    $('vcBtn').disabled = true;
    $('vcStop').classList.remove('hidden');
    for (let i = 0; i < domains.length && !vcStop; i += VC_BATCH) {
        $('vcScopeNote').textContent = `Checking ${Math.min(i + VC_BATCH, domains.length)} of ${domains.length}…`;
        try {
            const data = await requestJson('/api/advisories/check', { method: 'POST',
                headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domains: domains.slice(i, i + VC_BATCH) }) });
            vcRows.push(...(data.results || []));
        } catch (err) {
            toast(err.message);
            if (/Too many/.test(err.message)) { await new Promise(r => setTimeout(r, 15000)); i -= VC_BATCH; }
        }
        vcRender();
    }
    $('vcScopeNote').textContent = vcStop ? `Stopped after ${vcRows.length} of ${domains.length}.` : `${domains.length} checked.`;
    $('vcBtn').disabled = false;
    $('vcStop').classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
    if (!$('vcBtn')) return;
    $('vcScope').addEventListener('change', () => $('vcDomains').classList.toggle('hidden', $('vcScope').value !== 'paste'));
    $('vcBtn').addEventListener('click', vcRun);
    $('vcStop').addEventListener('click', () => { vcStop = true; });
});
