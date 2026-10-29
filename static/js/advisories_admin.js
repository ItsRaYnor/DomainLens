// Admin -> Vulnerability rules: the rules the version check and every scan
// use. Uses $, esc and toast from lookup.js. The built-in rules are shown
// read-only and can be copied into a new rule; the test runs the rule in
// the form against pasted headers, without saving it. Own rules export to
// a file and import from one; the example rules are added by id.

const AR_VERDICT = {
    vulnerable: ['Vulnerable', 'status-fail'],
    cannot_tell: ['Cannot tell from outside', 'status-warn'],
    not_affected: ['Not affected', 'status-pass'],
    fixed: ['Has the fix', 'status-pass'],
};
let arRules = [];
let arExamples = [];
let arEditing = null;   // the id of the rule in the form, or null for a new one

// A request whose refusal carries the reasons: requestJson keeps only the
// error line, and a rule refused for three reasons should show all three.
async function arSend(url, method, body) {
    let resp;
    try {
        resp = await fetch(url, { method, headers: { 'Content-Type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
        throw new Error('Could not reach the server. Is DomainLens still running?');
    }
    let data = {};
    try { data = await resp.json(); } catch (e) { data = { error: `The server returned HTTP ${resp.status}.` }; }
    return { ok: resp.ok, data };
}

function arLines(id) {
    return $(id).value.split(/\n/).map(s => s.trim()).filter(Boolean);
}

function arCommas(id) {
    return $(id).value.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
}

function arRead() {
    return {
        id: $('arId').value.trim(), name: $('arName').value.trim(), product: $('arProduct').value.trim(),
        token: $('arToken').value.trim(), severity: $('arSeverity').value, published: $('arPublished').value,
        cves: arLines('arCves'), fixed: arLines('arFixed'), introduced: $('arIntroduced').value.trim(),
        older_branches: $('arOlder').value,
        sources: arCommas('arSources'), seen_cookies: arCommas('arSeenCookies'), seen_paths: arCommas('arSeenPaths'),
        summary: $('arSummary').value.trim(), impact: $('arImpact').value.trim(), fix: $('arFix').value.trim(),
        check: $('arCheck').value.trim(), references: arLines('arReferences'),
    };
}

function arProblems(problems) {
    const box = $('arProblems');
    box.classList.toggle('hidden', !problems.length);
    box.innerHTML = problems.length
        ? '<strong>The rule cannot be used:</strong><ul>' + problems.map(p => `<li>${esc(p)}</li>`).join('') + '</ul>'
        : '';
}

// Into the form: a rule of your own to change, or any rule to start a new
// one from (its id left empty, since an id cannot be taken twice).
function arFill(rule, editing) {
    arEditing = editing ? rule.id : null;
    $('arEditorTitle').textContent = editing ? 'Change rule' : 'New rule';
    $('arId').value = editing ? rule.id : '';
    $('arId').disabled = !!editing;
    $('arName').value = rule.name || '';
    $('arProduct').value = rule.product || '';
    $('arToken').value = rule.token || '';
    $('arSeverity').value = rule.severity || 'high';
    $('arPublished').value = rule.published || '';
    $('arCves').value = (rule.cves || []).join('\n');
    $('arFixed').value = (rule.fixed || []).join('\n');
    $('arIntroduced').value = rule.introduced || '';
    $('arOlder').value = rule.older_branches || 'unfixed';
    $('arSources').value = (rule.sources || []).join(', ');
    $('arSeenCookies').value = (rule.seen_cookies || []).join(', ');
    $('arSeenPaths').value = (rule.seen_paths || []).join(', ');
    $('arSummary').value = rule.summary || '';
    $('arImpact').value = rule.impact || '';
    $('arFix').value = rule.fix || '';
    $('arCheck').value = rule.check || '';
    $('arReferences').value = (rule.references || []).join('\n');
    arProblems([]);
    $('arEditor').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function arRender() {
    $('arRules').innerHTML = arRules.map((r, i) => {
        const kind = r.builtin ? 'Built-in' : 'Own rule';
        let state = r.builtin ? '<span class="status status-pass">Always on</span>'
            : r.enabled ? '<span class="status status-pass">On</span>' : '<span class="status muted">Off</span>';
        if ((r.problems || []).length) {
            state = `<span class="status status-warn">Not used</span><div class="ct-desc">${esc(r.problems.join(' '))}</div>`;
        }
        const actions = r.builtin
            ? `<button class="btn-ghost-sm" type="button" data-copy="${i}">Use as start</button>`
            : `<button class="btn-ghost-sm" type="button" data-edit="${i}">Change</button>`
              + `<button class="btn-ghost-sm" type="button" data-toggle="${i}">${r.enabled ? 'Turn off' : 'Turn on'}</button>`
              + `<button class="btn-ghost-sm danger" type="button" data-remove="${i}">Remove</button>`;
        return `<tr><td><strong translate="no">${esc(r.name)}</strong><div class="muted"><code>${esc(r.id)}</code> · ${esc((r.cves || []).join(', '))}</div></td>`
            + `<td translate="no">${esc(r.product)}</td><td><code>${esc((r.fixed || []).join(', '))}</code></td>`
            + `<td>${esc(kind)}</td><td>${state}</td><td class="user-actions">${actions}</td></tr>`;
    }).join('') || '<tr><td colspan="6" class="muted">No rules.</td></tr>';
}

async function arLoad() {
    const { ok, data } = await arSend('/api/admin/advisories', 'GET');
    if (!ok) { toast(data.error || 'The rules could not be read.'); return; }
    arRules = data.rules || [];
    arRender();
    await arLoadExamples();
}

function arRenderExamples() {
    $('arExamples').innerHTML = arExamples.map((r, i) => {
        const action = r.added ? '<span class="status status-pass">Added</span>'
            : `<button class="btn-ghost-sm" type="button" data-example="${i}">Add</button>`;
        return `<tr><td><strong translate="no">${esc(r.name)}</strong><div class="muted">${esc((r.cves || []).join(', '))}</div>`
            + `<div class="ct-desc">${esc(r.summary)}</div></td>`
            + `<td translate="no">${esc(r.product)}</td><td><code>${esc((r.fixed || []).join(', '))}</code></td>`
            + `<td>${esc(r.severity)}</td><td>${action}</td></tr>`;
    }).join('') || '<tr><td colspan="5" class="muted">No examples.</td></tr>';
    $('arAddAllExamples').disabled = !arExamples.some(r => !r.added);
}

async function arLoadExamples() {
    const { ok, data } = await arSend('/api/admin/advisories/examples', 'GET');
    if (!ok) { toast(data.error || 'The examples could not be read.'); return; }
    arExamples = data.examples || [];
    arRenderExamples();
}

async function arAddExamples(ids) {
    if (!ids.length) return;
    const { ok, data } = await arSend('/api/admin/advisories/examples', 'POST', { ids });
    if (!ok) { toast((data.problems || [data.error || 'The examples could not be added.']).join(' ')); return; }
    toast(`${data.added.length} example rule(s) added. Scans and the version check use them from now on.`);
    await arLoad();
}

// The file is read here and sent as it is; the server checks every rule
// before it stores any, so a file with one bad rule adds nothing.
async function arImport() {
    const file = $('arImportFile').files[0];
    $('arImportResult').textContent = '';
    arImportProblems([]);
    if (!file) { toast('Choose a rules file first.'); return; }
    let payload;
    try {
        payload = JSON.parse(await file.text());
    } catch (e) {
        arImportProblems(['The file is not JSON.']);
        return;
    }
    const replace = $('arImportReplace').checked ? '1' : '0';
    const { ok, data } = await arSend(`/api/admin/advisories/import?replace=${replace}`, 'POST', payload);
    if (!ok) { arImportProblems(data.problems || [data.error || 'The file could not be imported.']); return; }
    $('arImportResult').textContent = `Added ${data.added.length}, replaced ${data.replaced.length}, `
        + `skipped ${data.skipped.length} (already there).`;
    await arLoad();
}

function arImportProblems(problems) {
    const box = $('arImportProblems');
    box.classList.toggle('hidden', !problems.length);
    box.innerHTML = problems.length
        ? '<strong>Nothing was imported:</strong><ul>' + problems.map(p => `<li>${esc(p)}</li>`).join('') + '</ul>'
        : '';
}

async function arSave() {
    const rule = arRead();
    const { ok, data } = arEditing
        ? await arSend(`/api/admin/advisories/${encodeURIComponent(arEditing)}`, 'PUT', rule)
        : await arSend('/api/admin/advisories', 'POST', rule);
    if (!ok) { arProblems(data.problems || [data.error || 'The rule could not be saved.']); return; }
    arProblems([]);
    toast('Rule saved. Scans and the version check use it from now on.');
    arFill(data.rule, true);
    await arLoad();
}

async function arToggle(rule) {
    const { ok, data } = await arSend(`/api/admin/advisories/${encodeURIComponent(rule.id)}/enabled`, 'POST',
        { enabled: !rule.enabled });
    if (!ok) { toast(data.error || 'The rule could not be changed.'); return; }
    await arLoad();
}

async function arRemove(rule) {
    if (!confirm(`Remove the rule ${rule.name}? Scans stop looking for it.`)) return;
    const { ok, data } = await arSend(`/api/admin/advisories/${encodeURIComponent(rule.id)}`, 'DELETE');
    if (!ok) { toast(data.error || 'The rule could not be removed.'); return; }
    if (arEditing === rule.id) arFill({}, false);
    await arLoad();
}

async function arTest() {
    const { ok, data } = await arSend('/api/admin/advisories/test', 'POST', {
        rule: { ...arRead(), id: arEditing || $('arId').value.trim() || 'test-rule' },
        headers: $('arHeaders').value, url: $('arUrl').value, body: $('arBody').value,
    });
    const out = $('arTestResult');
    if (!ok) {
        arProblems(data.problems || [data.error || 'The rule could not be tested.']);
        out.innerHTML = '';
        return;
    }
    arProblems([]);
    const read = Object.entries(data.read.headers || {}).map(([k, v]) => `<div><code>${esc(k)}: ${esc(v)}</code></div>`);
    if (data.read.generator) read.push(`<div><code>generator: ${esc(data.read.generator)}</code></div>`);
    const result = (data.results || [])[0];
    let verdict;
    if (!result) {
        verdict = '<p class="muted">The product is not seen in this response, so the rule does not apply: no finding, and not "has the fix" either.</p>';
    } else {
        const [label, cls] = AR_VERDICT[result.verdict] || AR_VERDICT.cannot_tell;
        verdict = `<p><span class="status ${cls}">${esc(label)}</span> <span>${esc(result.reason)}</span></p>`;
        if (data.finding) {
            verdict += `<p class="ct-desc"><strong>Scan finding (${esc(data.finding.severity)}):</strong> <span>${esc(data.finding.title)}</span></p>`;
        }
    }
    out.innerHTML = '<h3>Read from the response</h3>'
        + (read.length ? read.join('') : '<p class="muted">Nothing: none of the sources is in the pasted headers.</p>')
        + '<h3>Verdict</h3>' + verdict;
}

// Known CVEs (cve_feed.py): how current the data is per product, and the
// NCSC-NL advisories about followed products as rules to start from.
let cfCandidates = [];

function cfWhen(iso) {
    return iso ? new Date(iso).toLocaleString() : 'never';
}

const CF_FRESHNESS = {
    off: ['Switched off: scans say nothing about known CVEs.', 'muted'],
    never: ['Not synced yet: scans report the comparison as not measured.', 'status-warn'],
    stale: ['Older than the setting allows: scans report the comparison as not measured.', 'status-warn'],
    current: ['Current.', 'status-pass'],
};

function cfRender(data) {
    const [text, cls] = CF_FRESHNESS[data.freshness.state] || CF_FRESHNESS.off;
    const key = data.api_key ? 'With an NVD API key.' : 'Without an NVD API key (allowed; the sync pauses six seconds between requests).';
    $('cfState').innerHTML = `<span class="status ${cls}">${esc(text)}</span> `
        + (data.enabled ? `${esc(key)} Data may be ${data.max_age_days} day(s) old.` : '')
        + (data.running ? ' <span class="status status-warn">A sync is running.</span>' : '');
    $('cfSync').disabled = !data.enabled || data.running;
    $('cfProducts').innerHTML = data.products.map(p =>
        `<tr><td translate="no">${esc(p.product)}</td><td>${p.cves === null || p.cves === undefined ? '–' : p.cves}</td>`
        + `<td>${esc(cfWhen(p.synced_at))}</td><td>${p.error ? `<span class="status status-warn">${esc(p.error)}</span>` : '–'}</td></tr>`
    ).join('');
    const ncsc = data.ncsc;
    $('cfNcsc').textContent = !data.ncsc_enabled ? 'NCSC-NL advisories: switched off.'
        : `NCSC-NL advisories: ${ncsc.advisories ?? 0} kept, synced ${cfWhen(ncsc.synced_at)}.`
          + (ncsc.error ? ` Last problem: ${ncsc.error}` : '');
    $('cfAttribution').textContent = data.attribution;
}

// What the NVD data adds to an advisory: the releases with the fix that
// "Use as start" fills in, or that there are none to fill in.
function cfNvdLine(c) {
    const nvd = c.nvd || {};
    if (!nvd.listed) {
        return `<div class="status status-warn">The NVD lists none of these CVEs for ${esc(c.product)}: add the releases with the fix yourself.</div>`;
    }
    let html = (nvd.fixed || []).length
        ? `<div class="status status-pass">Releases with the fix, from the NVD: <span translate="no">${esc(nvd.fixed.join(', '))}</span></div>`
        : `<div class="status status-warn">The NVD gives no release with the fix for these CVEs: add them yourself.</div>`;
    if ((nvd.without_fix || []).length && (nvd.fixed || []).length) {
        html += `<div class="ct-desc">No fixed release in the NVD for <span translate="no">${esc(nvd.without_fix.join(', '))}</span>: check those yourself.</div>`;
    }
    return html;
}

function cfRenderCandidates(data) {
    cfCandidates = data.candidates || [];
    $('cfCandidates').innerHTML = !data.enabled
        ? '<tr><td colspan="4" class="muted">The CVE data or the NCSC-NL advisories are switched off.</td></tr>'
        : cfCandidates.map((c, i) => {
            const action = c.rule_added ? '<span class="status status-pass">Rule added</span>'
                : `<button class="btn-ghost-sm" type="button" data-candidate="${i}">Use as start</button>`;
            const more = c.cve_count > c.cves.length ? ` and ${c.cve_count - c.cves.length} more` : '';
            return `<tr><td><a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer" translate="no">${esc(c.id)}</a>`
                + `<div class="ct-desc" translate="no">${esc(c.title)}</div><div class="muted">${esc(c.cves.join(', '))}${esc(more)}</div>`
                + `${cfNvdLine(c)}</td>`
                + `<td translate="no">${esc(c.product)}</td><td>${esc(c.kans || '?')} / ${esc(c.schade || '?')}</td><td>${action}</td></tr>`;
        }).join('') || '<tr><td colspan="4" class="muted">No advisory about a followed product has been read.</td></tr>';
}

async function cfLoad() {
    const { ok, data } = await arSend('/api/admin/cve-feed', 'GET');
    if (!ok) { toast(data.error || 'The CVE data state could not be read.'); return; }
    cfRender(data);
    const candidates = await arSend('/api/admin/cve-feed/candidates', 'GET');
    if (candidates.ok) cfRenderCandidates(candidates.data);
}

async function cfSync() {
    const { ok, data } = await arSend('/api/admin/cve-feed/sync', 'POST');
    if (!ok) { toast(data.error || 'The sync could not be started.'); return; }
    toast('The CVE data is being synced. This can take a few minutes without an NVD API key.');
    setTimeout(() => cfLoad().catch(() => {}), 3000);
}

document.addEventListener('DOMContentLoaded', () => {
    if ($('cfSection')) {
        $('cfSync').addEventListener('click', () => cfSync().catch(err => toast(err.message)));
        $('cfCandidates').addEventListener('click', event => {
            const button = event.target.closest('button[data-candidate]');
            const candidate = button && cfCandidates[Number(button.dataset.candidate)];
            if (!candidate) return;
            arFill(candidate.rule, false);
            // A new rule, but with the id that marks it as made from this
            // advisory, so the list can say the rule was added.
            $('arId').value = candidate.rule.id;
        });
        cfLoad().catch(err => toast(err.message));
    }
});

document.addEventListener('DOMContentLoaded', () => {
    if (!$('arRules')) return;
    $('arRules').addEventListener('click', event => {
        const button = event.target.closest('button');
        if (!button) return;
        const rule = arRules[Number(button.dataset.copy ?? button.dataset.edit ?? button.dataset.toggle ?? button.dataset.remove)];
        if (!rule) return;
        if (button.dataset.copy !== undefined) arFill(rule, false);
        else if (button.dataset.edit !== undefined) arFill(rule, true);
        else if (button.dataset.toggle !== undefined) arToggle(rule).catch(err => toast(err.message));
        else arRemove(rule).catch(err => toast(err.message));
    });
    $('arExamples').addEventListener('click', event => {
        const button = event.target.closest('button[data-example]');
        const example = button && arExamples[Number(button.dataset.example)];
        if (example) arAddExamples([example.id]).catch(err => toast(err.message));
    });
    $('arAddAllExamples').addEventListener('click',
        () => arAddExamples(arExamples.filter(r => !r.added).map(r => r.id)).catch(err => toast(err.message)));
    $('arImport').addEventListener('click', () => arImport().catch(err => toast(err.message)));
    $('arNew').addEventListener('click', () => arFill({}, false));
    $('arSave').addEventListener('click', () => arSave().catch(err => toast(err.message)));
    $('arTest').addEventListener('click', () => arTest().catch(err => toast(err.message)));
    arLoad().catch(err => toast(err.message));
});
