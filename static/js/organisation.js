// Monitoring -> Organisation. Uses $, esc, requestJson and toast from lookup.js.

const ORG_RATING_COLOR = {
    A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)', D: 'var(--grade-d)', F: 'var(--grade-f)',
};

// One option list for every unit picker: indented by depth, full path as title.
function orgUnitOptions(units, { blank, exclude } = {}) {
    return (blank ? `<option value="">${esc(blank)}</option>` : '')
        + units.filter(u => !(exclude && exclude.has(u.id)))
            .map(u => `<option value="${u.id}" title="${esc(u.path)}">${'  '.repeat(u.depth)}${esc(u.name)}</option>`).join('');
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
    const links = `<a href="/reports/dashboard?group=${u.id}">Dashboard</a> &middot; `
        + `<a href="/monitoring?unit=${u.id}">Monitors</a> &middot; <a href="/monitoring/domains?group=${u.id}">Domains</a>`;
    return `<tr><td class="org-unit" style="padding-left:${0.6 + u.depth * 1.25}rem"><strong>${esc(u.name)}</strong>`
        + (u.effective_registrar ? `<div class="muted">Registrar: ${esc(u.effective_registrar)}${u.registrar_inherited ? ' (inherited)' : ''}</div>` : '')
        + `</td><td>${orgRatingBar(s.ratings, s.scanned)}</td><td>${findings}</td>`
        + `<td>${s.monitors} <span class="muted">(${s.monitors_enabled} on)</span>`
        + (ev ? `<div class="pf-count-warn">${ev} high or critical events, 7 d</div>` : '') + '</td>'
        + `<td>${reg}</td><td class="nowrap">${links}</td></tr>`;
}

const org = { units: [], canEdit: false };

async function orgLoad() {
    let data;
    try { data = await requestJson('/api/organisation'); } catch (err) { toast(err.message); return; }
    org.units = data.units;
    $('orgTable').innerHTML = data.units.length
        ? '<tr><th>Unit</th><th>Security rating</th><th>Open findings</th><th>Monitors</th><th>Registration</th><th></th></tr>'
          + data.units.map(orgRow).join('')
        : '<tr><td class="muted">No units yet. Add one below, or import domains with a unit path in the domain portfolio.</td></tr>';
    const un = data.unassigned;
    $('orgUnassigned').textContent = (un.scanned || un.monitors)
        ? `Not in any unit: ${un.scanned} scanned domain(s) and ${un.monitors} monitor(s). Put their domains in a unit to count them here.`
        : '';
    if (org.canEdit) orgRenderManage();
}

function orgRenderManage() {
    const units = org.units;
    $('orgNewParent').innerHTML = orgUnitOptions(units, { blank: 'Top level' });
    $('orgManageTable').innerHTML = units.length
        ? '<tr><th>Unit</th><th>Under</th><th>Expected registrar</th><th></th></tr>' + units.map(u => {
            const parent = `<select class="org-parent" aria-label="Under">${orgUnitOptions(units, { blank: 'Top level', exclude: orgDescendants(units, u.id) })}</select>`;
            return `<tr data-id="${u.id}"><td style="padding-left:${0.6 + u.depth * 1.25}rem"><input type="text" class="org-name" value="${esc(u.name)}" aria-label="Name"></td>`
                + `<td>${parent}</td>`
                + `<td><input type="text" class="org-registrar" value="${esc(u.expected_registrar || '')}" placeholder="${u.effective_registrar ? esc(u.effective_registrar) + ' (inherited)' : 'Any registrar'}" aria-label="Expected registrar"></td>`
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
    if (org.canEdit) {
        $('orgNewBtn').addEventListener('click', async () => {
            try {
                await requestJson('/api/portfolio/groups', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: $('orgNewName').value, parent_id: $('orgNewParent').value,
                        expected_registrar: $('orgNewRegistrar').value }),
                });
                $('orgNewName').value = '';
                $('orgNewRegistrar').value = '';
            } catch (err) { toast(err.message); }
            orgLoad();
        });
        $('orgManageTable').addEventListener('click', async e => {
            const row = e.target.closest('tr[data-id]');
            if (!row) return;
            const url = '/api/portfolio/groups/' + row.dataset.id;
            try {
                if (e.target.classList.contains('org-save')) {
                    await requestJson(url, {
                        method: 'PUT', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name: row.querySelector('.org-name').value,
                            parent_id: row.querySelector('.org-parent').value,
                            expected_registrar: row.querySelector('.org-registrar').value }),
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
