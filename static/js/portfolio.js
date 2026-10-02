// Monitoring -> Domain portfolio. Uses $, esc, requestJson and toast from
// lookup.js, which this page loads first.

const PF_PHASE_CLASS = {
    registered: 'status-pass', quarantine: 'status-fail', pending_delete: 'status-fail',
    not_registered: 'status-fail', redemption: 'status-warn', not_in_dns: 'status-warn',
};
const PF_FLAG_TEXT = {
    attention: 'Quarantine / deleted', expiring: 'Expiring ≤ 30 days',
    move: 'To move', unmeasured: 'Not measured',
};
const pf = { data: null, selected: new Set(), canEdit: false };

function pfWhen(iso) {
    const d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

// Three states, never blended: a date, "not published" (.nl), or unknown.
function pfExpiry(d) {
    if (d.expiry_state === 'not_published') {
        return '<span class="muted" title="SIDN publishes no expiry date: the registrar renews until the holder cancels.">Not published</span>';
    }
    if (d.expiry_state !== 'known') return '<span class="muted">&mdash;</span>';
    const days = d.days_left;
    const cls = days === null ? '' : days <= 7 ? 'status-fail' : days <= 30 ? 'status-warn' : '';
    const left = days === null ? '' : days < 0 ? ' (expired)' : ` (${days} d)`;
    return `<span class="${cls}">${esc(d.expires)}${esc(left)}</span>`;
}

function pfTransfer(d) {
    if (d.transfer === 'move') return '<span class="status-warn">To move</span>';
    if (d.transfer === 'ok') return '<span class="status-pass">At expected registrar</span>';
    if (d.transfer === 'unmeasured') return '<span class="muted">Registrar not known yet</span>';
    return '';
}

function pfRow(d) {
    const phase = `<span class="${PF_PHASE_CLASS[d.phase] || ''}">${esc(d.phase_text)}</span>`
        + (d.released_from ? `<div class="muted">Released from ${esc(pfWhen(d.released_from))}</div>` : '')
        + (d.stale ? `<div class="muted" title="${esc(d.last_error)}">Last lookup failed; showing the answer from ${esc(pfWhen(d.last_ok_at))}</div>` : '')
        + (d.phase === 'unmeasured' && d.last_error ? `<div class="muted">${esc(d.last_error)}</div>` : '');
    const registrar = d.registrar ? esc(d.registrar) + (d.reseller ? `<div class="muted">via ${esc(d.reseller)}</div>` : '') : '<span class="muted">&mdash;</span>';
    const check = pf.canEdit
        ? `<td><input type="checkbox" class="pf-select" value="${d.id}"${pf.selected.has(String(d.id)) ? ' checked' : ''} aria-label="Select ${esc(d.domain)}"></td>` : '';
    const actions = pf.canEdit ? '<button class="btn-ghost-sm pf-check" type="button">Check now</button>' : '';
    return `<tr data-id="${d.id}">${check}<td><a href="/tools/whois?domain=${encodeURIComponent(d.domain)}"><code>${esc(d.domain)}</code></a>`
        + (d.note ? `<div class="muted">${esc(d.note)}</div>` : '') + '</td>'
        + `<td>${registrar}<div>${pfTransfer(d)}</div></td>`
        + `<td class="nowrap">${pfExpiry(d)}</td>`
        + `<td>${phase}</td>`
        + `<td class="nowrap">${d.last_checked_at ? esc(pfWhen(d.last_checked_at)) : '&mdash;'}</td>`
        + `<td class="nowrap">${actions}</td></tr>`;
}

function pfCounts(c) {
    return Object.keys(PF_FLAG_TEXT).filter(f => c[f])
        .map(f => `<span class="${f === 'unmeasured' ? 'muted' : 'pf-count-warn'}">${c[f]} ${esc(PF_FLAG_TEXT[f].toLowerCase())}</span>`)
        .join(' &middot; ');
}

function pfMatches(d) {
    const q = ($('pfSearch').value || '').trim().toLowerCase();
    const flag = $('pfFlagFilter').value;
    if (flag && !d.flags.includes(flag)) return false;
    if (!q) return true;
    return [d.domain, d.registrar, d.reseller, d.note, d.group].some(v => v && v.toLowerCase().includes(q));
}

function pfRender() {
    const data = pf.data;
    if (!data) return;
    const groupFilter = $('pfGroupFilter').value;
    // A unit shows with the units below it: a company's view covers its parts.
    const inScope = groupFilter === '' ? null
        : groupFilter === 'g' ? new Set([''])
        : new Set([...pfDescendants(data.groups, Number(groupFilter.slice(1)))].map(String));
    const sections = data.groups.map(g => ({ key: String(g.id), name: g.path, depth: g.depth,
        expected: g.effective_registrar, inherited: g.registrar_inherited }));
    sections.push({ key: '', name: 'Not in a unit', depth: 0, expected: null });
    const summaries = Object.fromEntries(data.summary.groups.map(g => [String(g.id), g]));
    summaries[''] = data.summary.ungrouped;
    const html = sections.filter(s => !inScope || inScope.has(s.key)).map(s => {
        const all = data.domains.filter(d => String(d.group_id || '') === s.key);
        const shown = all.filter(pfMatches);
        if (!all.length && s.key === '') return '';
        // Filtering is asking "where are the problems": groups without any
        // answer to that are noise.
        const filtering = $('pfFlagFilter').value || $('pfSearch').value.trim();
        if (filtering && !shown.length) return '';
        // An empty unit that only holds other units is a heading, not a gap.
        if (!all.length && data.groups.some(g => String(g.parent_id) === s.key)) {
            return `<h4 class="pf-unit-heading" style="margin-left:${s.depth * 1.25}rem">${esc(s.name)}</h4>`;
        }
        const head = pf.canEdit ? '<th><input type="checkbox" class="pf-select-all" aria-label="Select all in this group"></th>' : '';
        const table = shown.length
            ? `<div class="users-table-wrap"><table class="data-table portfolio-table">`
              + `<tr>${head}<th>Domain</th><th>Registrar</th><th>Expires</th><th>Status</th><th>Last looked up</th><th></th></tr>`
              + shown.map(pfRow).join('') + '</table></div>'
            : `<p class="muted">${all.length ? 'No domains in this unit match the filter.' : 'No domains in this unit yet.'}</p>`;
        const counts = pfCounts(summaries[s.key] || {});
        return `<details class="monitor-fold discovered-zone" open data-group="${esc(s.key)}" style="margin-left:${s.depth * 1.25}rem">`
            + `<summary><h4>${esc(s.name)}</h4><span class="muted">${all.length} domain${all.length === 1 ? '' : 's'}`
            + (s.expected ? ` &middot; expected at ${esc(s.expected)}${s.inherited ? ' (inherited)' : ''}` : '') + '</span>'
            + (counts ? ` &middot; ${counts}` : '') + `</summary>${table}</details>`;
    }).join('');
    $('pfGroups').innerHTML = html || (data.domains.length
        ? '<p class="muted">No domains match the filter.</p>'
        : '<p class="muted">No domains in the portfolio yet. Add them below.</p>');
    pfUpdateSelected();
}

function pfRenderChrome() {
    const data = pf.data;
    const t = data.summary.total;
    const tile = (label, value, flag, cls) => `<button type="button" class="portfolio-tile ${value && cls ? cls : ''}" data-flag="${flag}">`
        + `<span class="portfolio-tile-value">${value}</span><span class="portfolio-tile-label">${esc(label)}</span></button>`;
    $('pfTiles').innerHTML = tile('Domains', t.total, '', '')
        + tile('Quarantine or deleted', t.attention, 'attention', 'tile-bad')
        + tile('Expiring within 30 days', t.expiring, 'expiring', 'tile-warn')
        + tile('To move', t.move, 'move', 'tile-warn')
        + tile('Not measured', t.unmeasured, 'unmeasured', '');
    $('pfSchedulerOff').classList.toggle('hidden', data.scheduler_enabled !== false);

    const current = pf.initialGroup || $('pfGroupFilter').value;
    pf.initialGroup = null;
    const indent = g => '  '.repeat(g.depth);
    $('pfGroupFilter').innerHTML = '<option value="">All units</option>'
        + data.groups.map(g => `<option value="g${g.id}" title="${esc(g.path)}">${indent(g)}${esc(g.name)}</option>`).join('')
        + '<option value="g">Not in a unit</option>';
    $('pfGroupFilter').value = current;
    if ($('pfMoveTarget')) {
        $('pfMoveTarget').innerHTML = data.groups.map(g => `<option value="${g.id}" title="${esc(g.path)}">${indent(g)}${esc(g.name)}</option>`).join('')
            + '<option value="">Not in a unit</option>';
        $('pfGroupNames').innerHTML = data.groups.map(g => `<option value="${esc(g.path.replace(/ › /g, ' > '))}">`).join('');
    }
    const groupKey = current.startsWith('g') ? current.slice(1) : '';
    $('pfCsvBtn').href = '/api/portfolio/csv' + (groupKey ? `?group=${encodeURIComponent(groupKey)}` : '');
    $('pfEvents').innerHTML = (data.events || []).slice(0, 15)
        .map(e => `<div>${esc(pfWhen(e.at))} &mdash; ${esc(e.detail)}</div>`).join('')
        || '<span class="muted">No changes yet. The first lookup of a domain is its baseline, not a change.</span>';
}

function pfDescendants(groups, id) {
    const found = new Set([id]);
    let grew = true;
    while (grew) {
        grew = false;
        groups.forEach(g => { if (found.has(g.parent_id) && !found.has(g.id)) { found.add(g.id); grew = true; } });
    }
    return found;
}

async function pfLoad() {
    try {
        pf.data = await requestJson('/api/portfolio');
    } catch (err) { toast(err.message); return; }
    const ids = new Set(pf.data.domains.map(d => String(d.id)));
    pf.selected = new Set([...pf.selected].filter(id => ids.has(id)));
    pfRenderChrome();
    pfRender();
}

function pfUpdateSelected() {
    if ($('pfSelected')) $('pfSelected').textContent = `${pf.selected.size} selected`;
}

async function pfPost(url, body, method) {
    return requestJson(url, {
        method: method || 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
    });
}

function pfShowImport(res) {
    const parts = [`${res.added.length} added, ${res.moved.length} moved to another group, `
        + `${res.unchanged.length} already there.`];
    if (res.converted && res.converted.length) {
        parts.push('Subdomains replaced by their registered domain: '
            + res.converted.map(c => `${c.from} → ${c.to}`).join(', ') + '.');
    }
    if (res.rejected.length) parts.push(`Not a domain name: ${res.rejected.join(', ')}.`);
    if (res.added.length) parts.push('New domains are looked up within a few minutes.');
    $('pfImportResult').textContent = parts.join(' ');
}

async function pfBulk(action) {
    if (!pf.selected.size) { toast('Select domains first.'); return; }
    const body = { action, ids: [...pf.selected] };
    if (action === 'move') body.group_id = $('pfMoveTarget').value;
    if (action === 'remove' && !confirm(`Remove ${pf.selected.size} domain(s) from the portfolio?`)) return;
    try {
        const res = await pfPost('/api/portfolio/domains', body);
        toast(`${res.count} domain(s) ${action === 'move' ? 'moved' : 'removed'}.`);
        pf.selected.clear();
    } catch (err) { toast(err.message); }
    pfLoad();
}

function initPortfolio() {
    if (!$('pfGroups')) return;
    try { pf.canEdit = JSON.parse($('pfCanEdit').textContent); } catch (e) { pf.canEdit = false; }
    ['pfSearch', 'pfFlagFilter'].forEach(id => $(id).addEventListener('input', pfRender));
    $('pfGroupFilter').addEventListener('change', () => {
        const value = $('pfGroupFilter').value;
        history.replaceState(null, '', value.length > 1 ? `?group=${value.slice(1)}` : location.pathname);
        pfRenderChrome(); pfRender();
    });
    const wanted = new URLSearchParams(location.search).get('group');
    if (wanted) pf.initialGroup = `g${wanted}`;
    $('pfTiles').addEventListener('click', e => {
        const tile = e.target.closest('.portfolio-tile');
        if (!tile) return;
        $('pfFlagFilter').value = tile.dataset.flag;
        pfRender();
    });
    $('pfGroups').addEventListener('change', e => {
        if (e.target.classList.contains('pf-select')) {
            e.target.checked ? pf.selected.add(e.target.value) : pf.selected.delete(e.target.value);
        } else if (e.target.classList.contains('pf-select-all')) {
            e.target.closest('table').querySelectorAll('.pf-select').forEach(box => {
                box.checked = e.target.checked;
                box.checked ? pf.selected.add(box.value) : pf.selected.delete(box.value);
            });
        }
        pfUpdateSelected();
    });
    $('pfGroups').addEventListener('click', async e => {
        if (!e.target.classList.contains('pf-check')) return;
        const id = e.target.closest('tr[data-id]').getAttribute('data-id');
        e.target.disabled = true;
        try { await pfPost(`/api/portfolio/domains/${id}/check`); } catch (err) { toast(err.message); }
        pfLoad();
    });
    if (pf.canEdit) {
        $('pfMoveBtn').addEventListener('click', () => pfBulk('move'));
        $('pfRemoveBtn').addEventListener('click', () => pfBulk('remove'));
        $('pfImportBtn').addEventListener('click', async () => {
            const text = $('pfImportInput').value;
            const sheet = pf.sheet;
            if (!text.trim() && !sheet) { toast('Paste domains or choose a file first.'); return; }
            try {
                let res;
                if (sheet) {
                    // A workbook is read on the server; the browser cannot.
                    const form = new FormData();
                    form.append('file', sheet);
                    form.append('group', $('pfImportGroup').value);
                    res = await requestJson('/api/portfolio/import', { method: 'POST', body: form });
                } else {
                    res = await pfPost('/api/portfolio/import', { text, group: $('pfImportGroup').value });
                }
                pfShowImport(res);
                $('pfImportInput').value = '';
                pf.sheet = null;
                $('pfImportFile').value = '';
                $('pfImportInput').disabled = false;
            } catch (err) { toast(err.message); }
            pfLoad();
        });
        $('pfImportFile').addEventListener('change', e => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            if (/\.xlsx$/i.test(file.name)) {
                pf.sheet = file;
                $('pfImportInput').value = '';
                $('pfImportInput').disabled = true;
                $('pfImportResult').textContent = `${file.name} is ready; press "Add to portfolio".`;
                return;
            }
            pf.sheet = null;
            $('pfImportInput').disabled = false;
            const reader = new FileReader();
            reader.onload = () => {
                const box = $('pfImportInput');
                box.value = (box.value.trim() ? box.value.trim() + '\n' : '') + String(reader.result || '');
            };
            reader.readAsText(file);
        });
    }
    pfLoad();
}

document.addEventListener('DOMContentLoaded', initPortfolio);
