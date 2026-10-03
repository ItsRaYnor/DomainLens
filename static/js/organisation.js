// Monitoring -> Organisation. Uses $, esc, requestJson and toast from lookup.js.

const ORG_RATING_COLOR = {
    A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)', D: 'var(--grade-d)', F: 'var(--grade-f)',
};

// One option list for every unit picker, by full path: a closed list shows
// one line, and "Marketing" under two companies looked the same.
function orgUnitOptions(units, { blank, exclude } = {}) {
    return (blank ? `<option value="">${esc(blank)}</option>` : '')
        + units.filter(u => !(exclude && exclude.has(u.id)))
            .map(u => `<option value="${u.id}">${esc(u.path)}</option>`).join('');
}

function orgDescendants(units, id) {
    const found = new Set([id]);
    let grew = true;
    while (grew) {
        grew = false;
        units.forEach(u => { if (found.has(u.parent_id) && !found.has(u.id)) { found.add(u.id); grew = true; } });
    }
    return found;
}

function orgRatingBar(ratings, scanned) {
    if (!scanned) return '<span class="muted">No scans in 90 days</span>';
    const parts = Object.entries(ratings).filter(([, n]) => n).map(([r, n]) =>
        `<span style="width:${100 * n / scanned}%;background:${ORG_RATING_COLOR[r]}" title="${r}: ${n}"></span>`).join('');
    const inOrder = (ratings.A || 0) + (ratings.B || 0);
    return `<div class="mgmt-bar" title="A ${ratings.A}, B ${ratings.B}, C ${ratings.C}, D ${ratings.D}, F ${ratings.F}">${parts}</div>`
        + `<div class="muted">${inOrder} of ${scanned} in order</div>`;
}

function orgCount(n, cls) {
    return n ? `<span class="${cls}">${n}</span>` : '<span class="muted">0</span>';
}

function orgRow(u) {
    const s = u.security, r = u.registration || {};
    const ev = s.events.critical + s.events.high;
    const findings = (s.critical || s.high)
        ? `${orgCount(s.critical, 'pf-count-bad')} critical, ${orgCount(s.high, 'pf-count-warn')} high` : '<span class="muted">none open</span>';
    const reg = r.total
        ? `${r.total} domain${r.total === 1 ? '' : 's'}`
          + (r.attention ? ` &middot; <span class="pf-count-bad">${r.attention} at risk</span>` : '')
          + (r.expiring ? ` &middot; <span class="pf-count-warn">${r.expiring} expiring</span>` : '')
          + (r.move ? ` &middot; <span class="pf-count-warn">${r.move} to move</span>` : '')
          + (r.unmeasured ? ` &middot; <span class="muted">${r.unmeasured} not measured</span>` : '')
        : '<span class="muted">No domains</span>';
    const links = `<a href="/reports/dashboard?unit=${u.id}">Dashboard</a> &middot; `
        + `<a href="/monitoring?unit=${u.id}">Monitors</a> &middot; <a href="/monitoring/domains?unit=${u.id}">Domains</a>`
        + (org.canEdit
            ? `<div class="org-row-add"><button type="button" class="btn-ghost-sm org-add-sub" data-id="${u.id}">+ Unit under it</button> `
              + `<a class="btn-ghost-sm" href="/monitoring/domains?unit=${u.id}&amp;add=1">+ Domains</a></div>`
            : '');
    const parent = org.units.some(c => c.parent_id === u.id);
    const toggle = parent
        ? `<button type="button" class="org-toggle" data-id="${u.id}" aria-expanded="${!org.collapsed.has(u.id)}" `
          + `aria-label="${org.collapsed.has(u.id) ? 'Expand' : 'Collapse'} ${esc(u.name)}">${org.collapsed.has(u.id) ? '▸' : '▾'}</button>`
        : '<span class="org-toggle-space"></span>';
    return `<tr><td class="org-unit" style="padding-left:${0.6 + u.depth * 1.25}rem">${toggle}<a href="/monitoring/organisation/${u.id}"><strong>${esc(u.name)}</strong></a>`
        + (u.effective_registrar ? `<div class="muted">Registrar: ${esc(u.effective_registrar)}${u.registrar_inherited ? ' (inherited)' : ''}</div>` : '')
        + `</td><td>${orgRatingBar(s.ratings, s.scanned)}</td><td>${findings}</td>`
        + `<td>${s.monitors} <span class="muted">(${s.monitors_enabled} on)</span>`
        + (ev ? `<div class="pf-count-warn">${ev} high or critical events, 7 d</div>` : '') + '</td>'
        + `<td>${reg}</td><td class="nowrap">${links}</td></tr>`;
}

const org = { units: [], canEdit: false, collapsed: new Set(), data: null };

// Collapsed units, remembered per browser: with many companies the tree is
// read one company at a time. Storage may be unavailable; the tree then
// simply starts open.
const ORG_COLLAPSED_KEY = 'domainlens.org.collapsed';

function orgLoadCollapsed() {
    try { return new Set(JSON.parse(localStorage.getItem(ORG_COLLAPSED_KEY) || '[]')); } catch (e) { return new Set(); }
}

function orgSaveCollapsed() {
    try { localStorage.setItem(ORG_COLLAPSED_KEY, JSON.stringify([...org.collapsed])); } catch (e) { /* per-browser only */ }
}

// Hidden when any unit above it is collapsed.
function orgHidden(u) {
    const byId = new Map(org.units.map(x => [x.id, x]));
    let parent = byId.get(u.parent_id);
    const seen = new Set();
    while (parent && !seen.has(parent.id)) {
        if (org.collapsed.has(parent.id)) return true;
        seen.add(parent.id);
        parent = byId.get(parent.parent_id);
    }
    return false;
}

function orgRenderTable() {
    if (!org.data) return;
    const data = org.data;
    $('orgTable').innerHTML = data.units.length
        ? '<tr><th>Unit</th><th>Security rating</th><th>Open findings</th><th>Monitors</th><th>Registration</th><th></th></tr>'
          + data.units.filter(u => !orgHidden(u)).map(orgRow).join('')
        : `<tr><td class="muted">${org.canEdit
            ? 'No units yet. Start with your company: give it a name under "Add a company or business unit" and leave "Part of" as it is.'
            : 'No units yet.'}</td></tr>`;
}

async function orgLoad() {
    let data;
    try { data = await requestJson('/api/organisation'); } catch (err) { toast(err.message); return; }
    org.units = data.units;
    org.data = data;
    if ($('orgEmailOff')) $('orgEmailOff').classList.toggle('hidden', data.unit_email_ready !== false);
    orgRenderTable();
    const un = data.unassigned;
    $('orgUnassigned').textContent = (un.scanned || un.monitors)
        ? `Not in any unit: ${un.scanned} scanned domain(s) and ${un.monitors} monitor(s). Put their domains in a unit to count them here.`
        : '';
    if (org.canEdit) orgRenderManage();
}

function orgRenderManage() {
    const units = org.units;
    const parent = $('orgNewParent').value || org.wantedParent || '';
    $('orgNewParent').innerHTML = orgUnitOptions(units, { blank: 'Nothing — this is a company' });
    $('orgNewParent').value = units.some(u => String(u.id) === String(parent)) ? String(parent) : '';
    org.wantedParent = null;
    const from = $('orgMergeFrom').value, into = $('orgMergeInto').value;
    $('orgMergeFrom').innerHTML = orgUnitOptions(units, { blank: 'Choose a unit' });
    $('orgMergeInto').innerHTML = orgUnitOptions(units, { blank: 'Choose a unit' });
    $('orgMergeFrom').value = units.some(u => String(u.id) === from) ? from : '';
    $('orgMergeInto').value = units.some(u => String(u.id) === into) ? into : '';
    $('orgManageTable').innerHTML = units.length
        ? '<tr><th>Unit</th><th>Under</th><th>Expected registrar</th><th>Notify</th><th></th></tr>' + units.map(u => {
            const parent = `<select class="org-parent" aria-label="Under">${orgUnitOptions(units, { blank: 'Top level', exclude: orgDescendants(units, u.id) })}</select>`;
            return `<tr data-id="${u.id}"><td style="padding-left:${0.6 + u.depth * 1.25}rem"><input type="text" class="org-name" value="${esc(u.name)}" aria-label="Name"></td>`
                + `<td>${parent}</td>`
                + `<td><input type="text" class="org-registrar" value="${esc(u.expected_registrar || '')}" placeholder="${u.effective_registrar ? esc(u.effective_registrar) + ' (inherited)' : 'Any registrar'}" aria-label="Expected registrar"></td>`
                + `<td><input type="text" class="org-notify" value="${esc((u.notify_emails || []).join(', '))}" placeholder="e-mail addresses" aria-label="Notify"></td>`
                + '<td class="nowrap"><button class="btn-ghost-sm org-save" type="button">Save</button> '
                + '<button class="btn-ghost-sm danger org-delete" type="button">Delete</button></td></tr>';
        }).join('')
        : '<tr><td class="muted">No units yet.</td></tr>';
    $('orgManageTable').querySelectorAll('tr[data-id]').forEach(row => {
        const u = units.find(x => String(x.id) === row.dataset.id);
        row.querySelector('.org-parent').value = u.parent_id || '';
    });
}

function initOrganisation() {
    if (!$('orgTable')) return;
    try { org.canEdit = JSON.parse($('orgCanEdit').textContent); } catch (e) { org.canEdit = false; }
    // From a unit page: /monitoring/organisation?parent=ID opens the form for a unit under it.
    org.wantedParent = new URLSearchParams(location.search).get('parent');
    if (org.wantedParent && org.canEdit) setTimeout(() => $('orgNewName').focus(), 300);
    org.collapsed = orgLoadCollapsed();
    $('orgTable').addEventListener('click', e => {
        const btn = e.target.closest('.org-toggle');
        if (!btn) return;
        const id = Number(btn.dataset.id);
        org.collapsed.has(id) ? org.collapsed.delete(id) : org.collapsed.add(id);
        orgSaveCollapsed();
        orgRenderTable();
    });
    $('orgCollapseAll').addEventListener('click', () => {
        org.collapsed = new Set(org.units.filter(u => org.units.some(c => c.parent_id === u.id)).map(u => u.id));
        orgSaveCollapsed();
        orgRenderTable();
    });
    $('orgExpandAll').addEventListener('click', () => {
        org.collapsed = new Set();
        orgSaveCollapsed();
        orgRenderTable();
    });
    if (org.canEdit) {
        $('orgNewBtn').addEventListener('click', async () => {
            if (!$('orgNewName').value.trim()) { toast('Give the unit a name first.'); $('orgNewName').focus(); return; }
            try {
                const unit = await requestJson('/api/organisation/units', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: $('orgNewName').value, parent_id: $('orgNewParent').value,
                        expected_registrar: $('orgNewRegistrar').value, notify_emails: $('orgNewNotify').value }),
                });
                $('orgNewName').value = '';
                $('orgNewRegistrar').value = '';
                $('orgNewNotify').value = '';
                // What next: its domains, or a unit under it.
                const added = $('orgAdded');
                added.innerHTML = `<span class="status-pass"></span> <span>Unit added:</span> <strong>${esc(unit.path)}</strong> `
                    + `<a class="btn-primary-lite" href="/monitoring/domains?unit=${unit.id}&amp;add=1">Add domains to it</a> `
                    + `<button type="button" class="btn-ghost org-add-sub" data-id="${unit.id}">Add a unit under it</button>`;
                added.classList.remove('hidden');
                org.wantedParent = null;
            } catch (err) { toast(err.message); }
            await orgLoad();
        });
        $('orgNewName').addEventListener('keydown', e => { if (e.key === 'Enter') $('orgNewBtn').click(); });
        // "+ Unit under it", from a row or from the confirmation: the form,
        // with that unit already chosen as the parent.
        document.addEventListener('click', e => {
            const btn = e.target.closest('.org-add-sub');
            if (!btn) return;
            $('orgNewParent').value = btn.dataset.id;
            $('orgAdd').scrollIntoView({ behavior: 'smooth', block: 'start' });
            $('orgNewName').focus();
        });
        $('orgMergeBtn').addEventListener('click', async () => {
            const from = org.units.find(u => String(u.id) === $('orgMergeFrom').value);
            const into = org.units.find(u => String(u.id) === $('orgMergeInto').value);
            if (!from || !into) { toast('Choose both units first.'); return; }
            if (!confirm(`Merge ${from.path} into ${into.path}? ${from.path} is removed; its domains and units go to ${into.path}.`)) return;
            try {
                const res = await requestJson(`/api/organisation/units/${from.id}/merge`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ into: into.id }),
                });
                toast(`Merged: ${res.domains} domain(s) and ${res.units_moved + res.units_merged} unit(s) now in ${res.into.path}.`);
            } catch (err) { toast(err.message); }
            orgLoad();
        });
        $('orgManageTable').addEventListener('click', async e => {
            const row = e.target.closest('tr[data-id]');
            if (!row) return;
            const url = '/api/organisation/units/' + row.dataset.id;
            try {
                if (e.target.classList.contains('org-save')) {
                    await requestJson(url, {
                        method: 'PUT', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name: row.querySelector('.org-name').value,
                            parent_id: row.querySelector('.org-parent').value,
                            expected_registrar: row.querySelector('.org-registrar').value,
                            notify_emails: row.querySelector('.org-notify').value }),
                    });
                    toast('Unit saved.');
                } else if (e.target.classList.contains('org-delete')) {
                    if (!confirm('Delete this unit? Its domains and units move one level up.')) return;
                    await requestJson(url, { method: 'DELETE' });
                } else {
                    return;
                }
            } catch (err) { toast(err.message); }
            orgLoad();
        });
    }
    orgLoad();
}

document.addEventListener('DOMContentLoaded', initOrganisation);
