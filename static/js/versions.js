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
    not_affected: ['Not affected', 'status-pass', 3],
};
let vcRows = [];
let vcStop = false;

// Held domains with a website. The whole portfolio, or one organisation
// unit and the units under it. The server decides which domains that is.
async function vcPortfolioDomains() {
    const selected = $('vcScope').value;
    const query = selected.startsWith('unit:') ? ('?unit=' + encodeURIComponent(selected.slice(5))) : '';
    const data = await requestJson('/api/advisories/sites' + query);
    return data.domains || [];
}

// One option per organisation unit, in tree order. The path is the unit's
// own name, so it is not translated. Marked as loaded only once the units
// are in: a load that failed is tried again when the list is opened.
async function vcLoadUnits() {
    const select = $('vcScope');
    if (!select || select.dataset.units === '1') return;
    const data = await requestJson('/api/advisories/units');
    if (select.dataset.units === '1') return;   // a second load got there first
    select.dataset.units = '1';
    const units = data.units || [];
    if (!units.length) return;
    const group = document.createElement('optgroup');
    group.label = 'Organisation unit';
    for (const unit of units) {
        const option = document.createElement('option');
        option.value = 'unit:' + unit.id;
        option.textContent = unit.path;
        option.setAttribute('translate', 'no');
        group.appendChild(option);
    }
    const paste = select.querySelector('option[value="paste"]');
    select.insertBefore(group, paste);
}

function vcPasted() {
    // "https://example.org/home", "//example.org" and "/example.org" are all example.org.
    return [...new Set($('vcDomains').value.split(/[\s,;]+/).map(s => s.trim().toLowerCase()
        .replace(/^https?:/, '').replace(/^\/+/, '').replace(/\/.*$/, '')).filter(s => s.includes('.')))];
}

// One row per domain: what the server shows, and the verdict per rule.
// "Not seen" (none of the software the rules look for) and "no response"
// are their own states, never "has the fix".
function vcVerdict(side) {
    if (!(side.advisories || []).length) return ['None of the software seen', 'muted', 4];
    return side.advisories.map(a => VC_VERDICT[a.verdict] || VC_VERDICT.cannot_tell).sort((a, b) => a[2] - b[2])[0];
}

function vcState(r) {
    if (r.state === 'no_address') return ['No website in DNS', 'muted', 5];
    if (r.state === 'not_checked') return ['Not checked', 'muted', 5];
    if (r.state !== 'measured') return ['No response', 'status-warn', 2];
    return vcVerdict(r);
}

function vcShown(side) {
    const shown = [side.powered_by, side.server, side.generator].filter(Boolean).join(' · ');
    return shown ? `<code>${esc(shown)}</code>` : '<span class="muted">—</span>';
}

const VC_ADDRESS = {
    public: 'Public address', none: 'No address', failed: 'No answer from DNS', private: 'Inside a network, not asked',
};

// What was looked up and asked for one domain, and every answer on the way:
// the result can be followed by hand. Each text its own element, so the
// page's translation finds it.
function vcDetails(r) {
    const value = (name, v) => (v ? ` · <span>${esc(name)}</span> <code>${esc(v)}</code>` : '');
    let html = '<div class="vc-detail-block"><strong>DNS</strong><ul>'
        + (r.lookups || []).map(l => `<li><code>${esc(l.host)}</code> <span>${esc(VC_ADDRESS[l.address] || l.address)}</span></li>`).join('')
        + '</ul></div>';
    if ((r.attempts || []).length) {
        html += '<div class="vc-detail-block"><strong>Asked for</strong><ul>'
            + r.attempts.map(a => `<li><code>${esc(a.url)}</code> `
                + (a.error ? `<span>${esc(`No answer: ${a.error}`)}</span>` : '<span>Answered</span>') + '</li>').join('')
            + '</ul></div>';
    }
    if ((r.hops || []).length) {
        const other = (r.redirect || {}).domain || '';
        html += '<div class="vc-detail-block"><strong>Steps</strong><ol>'
            + r.hops.map(h => `<li><code>${esc(h.url || '')}</code> <span class="vc-hop-status">${esc(String(h.status ?? ''))}</span>`
                + value('Server', h.server) + value('X-Powered-By', h.powered_by)
                + ` · <span class="${h.own ? '' : 'vc-hop-other'}">${h.own ? 'This domain' : esc(`Other domain: ${other}`)}</span></li>`).join('')
            + '</ol></div>';
    }
    return `<details class="vc-details"><summary>Details</summary>${html}</details>`;
}

// The advisory's name and its reason apart, each its own text.
function vcWhy(side, where) {
    return (side.advisories || []).map(a => `<div><strong>${esc(a.name)}</strong> `
        + (where ? `<span class="muted">${esc(`On ${where}:`)}</span> ` : '') + `<span>${esc(a.reason)}</span></div>`).join('');
}

function vcRender() {
    const sorted = [...vcRows].sort((a, b) => vcState(a)[2] - vcState(b)[2] || a.domain.localeCompare(b.domain));
    const count = label => vcRows.filter(r => vcState(r)[0] === label).length;
    const summary = ['Vulnerable', 'Cannot tell from outside', 'Has the fix', 'Not affected', 'None of the software seen', 'No response',
        'No website in DNS', 'Not checked']
        .map(label => `<span class="vc-count"><strong>${count(label)}</strong> ${esc(label)}</span>`).join('');
    $('vcResult').innerHTML = `<section class="card"><div class="lc-head"><h3>${esc(`${vcRows.length} site(s) checked`)}</h3>`
        + '<button class="btn-ghost-sm" id="vcExport" type="button">Export CSV</button></div>'
        + `<div class="vc-counts">${summary}</div>`
        + '<div class="users-table-wrap"><table class="data-table stack-table vc-table">'
        + '<tr><th>Domain</th><th>Result</th><th>Shown by the server</th><th>Why</th></tr>'
        + sorted.map(r => {
            const [label, cls] = vcState(r);
            const details = `<tr class="vc-detail-row"><td colspan="4">${vcDetails(r)}</td></tr>`;
            if (r.state !== 'measured') {
                return `<tr><td><code>${esc(r.domain)}</code></td><td><span class="status ${cls}">${esc(label)}</span></td>`
                    + `<td><span class="muted">—</span></td><td><span>${esc(r.error || '')}</span></td></tr>` + details;
            }
            // A redirect to another domain ends on another server: its
            // verdict is that domain's, shown under the domain's own.
            const to = r.redirect;
            const [toLabel, toCls] = to ? vcVerdict(to) : [];
            const toName = to ? `<code>${esc(to.domain)}</code>` : '';
            return `<tr><td><code>${esc(r.domain)}</code></td><td><span class="status ${cls}">${esc(label)}</span>`
                + (to ? `<div class="vc-redirect"><span>Redirects to</span> ${toName}: <span class="status ${toCls}">${esc(toLabel)}</span></div>` : '')
                + `</td><td>${vcShown(r)}`
                + (to ? `<div class="vc-redirect">${toName}: ${vcShown(to)}</div>` : '')
                + `</td><td>${vcWhy(r)}${to ? vcWhy(to, to.domain) : ''}</td></tr>` + details;
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
        domains = $('vcScope').value === 'paste' ? vcPasted() : await vcPortfolioDomains();
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
    $('vcScope').addEventListener('change', () => {
        const selected = $('vcScope').value;
        $('vcDomains').classList.toggle('hidden', selected !== 'paste');
        $('vcScopeNote').textContent = selected.startsWith('unit:') ? 'Includes the units under it.' : '';
    });
    vcLoadUnits().catch(err => toast(err.message));
    $('vcScope').addEventListener('focus', () => vcLoadUnits().catch(err => toast(err.message)));
    $('vcBtn').addEventListener('click', vcRun);
    $('vcStop').addEventListener('click', () => { vcStop = true; });
});
