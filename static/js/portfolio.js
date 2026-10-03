// Monitoring -> Domain portfolio. Uses $, esc, requestJson and toast from
// lookup.js, which this page loads first.

const PF_PHASE_CLASS = {
    registered: 'status-pass', quarantine: 'status-fail', pending_delete: 'status-fail',
    not_registered: 'status-fail', redemption: 'status-warn', not_in_dns: 'status-warn',
};
const PF_FLAG_TEXT = {
    attention: 'Quarantine / deleted', expiring: 'Expiring ≤ 30 days',
    move: 'To move', intel: 'In use, no threat intel', claimable: 'Free to request',
    unmeasured: 'Not measured',
};
const PF_LIFECYCLE_CLASS = { keep: '', review: 'status-warn', cancel: 'muted', claim: '' };
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

// Mail and web, each measured yes or no, or not measured: never "no" for unknown.
function pfUse(d) {
    const word = v => v === 'yes' ? 'yes' : v === 'no' ? 'no' : 'not measured';
    if (!d.uses_mail && !d.uses_web) return '<div class="muted">Use not measured yet</div>';
    return `<div class="muted">Mail ${word(d.uses_mail)} &middot; Web ${word(d.uses_web)}</div>`;
}

function pfIntel(d) {
    // An editor switches enrolment right here; the state text says what it means.
    if (!pf.canEdit) return pfIntelState(d);
    return '<div class="pf-intel-cell">'
        + `<button type="button" class="switch pf-intel" role="switch" aria-checked="${d.threat_intel}" `
        + `aria-label="Threat intelligence for ${esc(d.domain)}" `
        + `title="${d.threat_intel ? 'Remove from threat intelligence' : 'Add to threat intelligence'}"></button>`
        + `<span>${pfIntelState(d)}</span></div>`;
}

function pfIntelState(d) {
    const s = d.threat_intel_state;
    if (s === 'enrolled') return '<span class="status-pass">Enrolled</span>' + pfUse(d);
    if (s === 'missing') return '<span class="status-warn" title="In use: it belongs with the threat intelligence service">Not enrolled</span>' + pfUse(d);
    if (s === 'not_needed') {
        return '<span class="muted">Not needed</span>'
            + (['cancel', 'claim'].includes(d.lifecycle) ? '' : pfUse(d));
    }
    return '<span class="muted">Use not measured yet</span>';
}

function pfLifecycle(d) {
    return `<span class="${PF_LIFECYCLE_CLASS[d.lifecycle] || ''}">${esc(d.lifecycle_text)}</span>`
        + (d.flags.includes('claimable') ? '<div class="status-pass">Free: can be requested now</div>' : '');
}

function pfContact(d) {
    const c = d.contact;
    const link = pf.canEdit
        ? `<div><button type="button" class="btn-ghost-sm pf-contact-link">${c && !d.contact_inherited ? 'Change contact' : 'Link contact'}</button></div>` : '';
    if (!c) return '<span class="muted">&mdash;</span>' + link;
    const gone = c.account && c.account.state !== 'enabled'
        ? `<div class="status-warn">${c.account.state === 'removed' ? 'Account removed' : 'Account disabled'}</div>` : '';
    return esc(c.name) + (c.email && c.email !== c.name ? `<div class="muted">${esc(c.email)}</div>` : '')
        + (d.contact_inherited ? '<div class="muted">From the unit</div>' : '') + gone + link;
}

// The picker in a contact cell: a contact, an account, or a new one; blank
// goes back to the unit's contact.
function pfContactEdit(cell, d) {
    cell.innerHTML = '<div class="contact-pick">'
        + `<select class="pf-contact-choice" aria-label="Contact for ${esc(d.domain)}">`
        + contactOptions("The unit's contact", d.contact && !d.contact_inherited ? d.contact.id : '') + '</select>'
        + contactNewFields('row') + '</div>'
        + '<div class="nowrap"><button type="button" class="btn-ghost-sm pf-contact-save">Save</button> '
        + '<button type="button" class="btn-ghost-sm pf-contact-cancel">Cancel</button></div>';
    const select = cell.querySelector('.pf-contact-choice');
    // Nobody to choose yet: start with a new one.
    if (!contactBook.contacts.length && !contactBook.accounts.length) select.value = 'new';
    contactToggleNew(select);
    if (select.value !== 'new') select.focus();
}

function pfRow(d) {
    const phase = `<span class="${PF_PHASE_CLASS[d.phase] || ''}">${esc(d.phase_text)}</span>`
        + (d.released_from ? `<div class="muted">Released from ${esc(pfWhen(d.released_from))}</div>` : '')
        + (d.stale ? `<div class="muted" title="${esc(d.last_error)}">Last lookup failed; showing the answer from ${esc(pfWhen(d.last_ok_at))}</div>` : '')
        + (d.phase === 'unmeasured' && d.last_error ? `<div class="muted">${esc(d.last_error)}</div>` : '')
        + (d.last_checked_at ? `<div class="muted">Looked up ${esc(pfWhen(d.last_checked_at))}</div>` : '');
    const registrar = d.registrar ? esc(d.registrar) + (d.reseller ? `<div class="muted">via ${esc(d.reseller)}</div>` : '') : '<span class="muted">&mdash;</span>';
    const check = pf.canEdit
        ? `<td><input type="checkbox" class="pf-select" value="${d.id}"${pf.selected.has(String(d.id)) ? ' checked' : ''} aria-label="Select ${esc(d.domain)}"></td>` : '';
    const actions = pf.canEdit ? '<button class="btn-ghost-sm pf-check" type="button">Check now</button>' : '';
    return `<tr data-id="${d.id}">${check}<td><a href="/tools/whois?domain=${encodeURIComponent(d.domain)}"><code>${esc(d.domain)}</code></a>`
        + (d.note ? `<div class="muted">${esc(d.note)}</div>` : '')
        + (d.monitored ? '<div class="muted" title="A security monitor scans this domain or one of its hosts">Security monitored</div>' : '')
        + '</td>'
        + `<td>${registrar}<div>${pfTransfer(d)}</div></td>`
        + `<td class="nowrap">${pfExpiry(d)}</td>`
        + `<td>${phase}</td>`
        + `<td>${pfIntel(d)}</td>`
        + `<td>${pfLifecycle(d)}</td>`
        + `<td>${pfContact(d)}</td>`
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
    return [d.domain, d.registrar, d.reseller, d.note, d.group, d.lifecycle_text, d.contact && d.contact.name,
        d.contact && d.contact.email].some(v => v && v.toLowerCase().includes(q));
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
        const head = pf.canEdit ? '<th><input type="checkbox" class="pf-select-all" aria-label="Select all in this unit"></th>' : '';
        const table = shown.length
            ? `<div class="users-table-wrap"><table class="data-table portfolio-table">`
              + `<tr>${head}<th>Domain</th><th>Registrar</th><th>Expires</th><th>Status</th>`
              + `<th>Threat intel</th><th>Decision</th><th>Contact</th><th></th></tr>`
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
        + tile('In use, no threat intel', t.intel, 'intel', 'tile-warn')
        + tile('Not measured', t.unmeasured, 'unmeasured', '');

    const current = pf.initialGroup || $('pfGroupFilter').value;
    pf.initialGroup = null;
    $('pfGroupFilter').innerHTML = '<option value="">All units</option>'
        + data.groups.map(g => `<option value="g${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('')
        + '<option value="g">Not in a unit</option>';
    $('pfGroupFilter').value = current;
    if ($('pfMoveTarget')) {
        $('pfMoveTarget').innerHTML = data.groups.map(g => `<option value="${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('')
            + '<option value="">Not in a unit</option>';
        $('pfGroupNames').innerHTML = data.groups.map(g => `<option value="${esc(g.path.replace(/ › /g, ' > '))}">`).join('');
        // The unit new domains go to: a choice, not a name to type and get
        // slightly wrong. Arriving from a unit (?unit=) chooses it.
        const unit = $('pfImportUnit');
        const chosen = pf.importUnit || unit.value;
        pf.importUnit = null;
        unit.innerHTML = '<option value="">Not in a unit</option>'
            + data.groups.map(g => `<option value="${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('')
            + '<option value="new">New unit…</option>';
        unit.value = chosen === 'new' || data.groups.some(g => String(g.id) === String(chosen)) ? String(chosen) : '';
        $('pfImportNewField').classList.toggle('hidden', unit.value !== 'new');
    }
    if ($('pfLifecycleValue')) {
        const life = $('pfLifecycleValue').value;
        $('pfLifecycleValue').innerHTML = (data.lifecycles || [])
            .map(l => `<option value="${esc(l.value)}">${esc(l.text)}</option>`).join('');
        if (life) $('pfLifecycleValue').value = life;
        const person = $('pfContactValue').value;
        $('pfContactValue').innerHTML = contactOptions("The unit's contact");
        if ([...$('pfContactValue').options].some(o => o.value === person)) $('pfContactValue').value = person;
        if (!$('pfContactValue').parentElement.querySelector('.contact-new')) {
            $('pfContactValue').insertAdjacentHTML('afterend', contactNewFields('bulk'));
        }
    }
    const groupKey = current.startsWith('g') ? current.slice(1) : '';
    $('pfCsvBtn').href = '/api/portfolio/csv' + (groupKey ? `?unit=${encodeURIComponent(groupKey)}` : '');
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

function pfShowImport(res, unitName) {
    const parts = [`${res.added.length} added, ${res.moved.length} moved to another unit, `
        + `${res.unchanged.length} already there.`];
    if (unitName && (res.added.length || res.moved.length)) parts.push(`Lines without a unit went to ${unitName}.`);
    if (res.converted && res.converted.length) {
        parts.push('Subdomains replaced by their registered domain: '
            + res.converted.map(c => `${c.from} → ${c.to}`).join(', ') + '.');
    }
    if (res.rejected.length) parts.push(`Not a domain name: ${res.rejected.join(', ')}.`);
    if (res.decisions) parts.push(`Decision set for ${res.decisions} domain(s).`);
    if (res.contacts) parts.push(`Contact linked to ${res.contacts} domain(s).`);
    if (res.contacts_created && res.contacts_created.length) parts.push(`New contacts: ${res.contacts_created.join(', ')}.`);
    if (res.threat_intel) parts.push(`Threat intelligence set for ${res.threat_intel} domain(s).`);
    if (res.not_understood && res.not_understood.length) parts.push(`Not understood, left as it was: ${res.not_understood.join('; ')}.`);
    if (res.added.length) parts.push('New domains are looked up within a few minutes.');
    $('pfImportResult').textContent = parts.join(' ');
}

async function pfBulk(action, value) {
    if (!pf.selected.size) { toast('Select domains first.'); return; }
    const body = { action, ids: [...pf.selected] };
    if (value !== undefined) body.value = value;
    if (action === 'move') body.group_id = $('pfMoveTarget').value;
    if (action === 'remove' && !confirm(`Remove ${pf.selected.size} domain(s) from the portfolio?`)) return;
    try {
        const res = await pfPost('/api/portfolio/domains', body);
        toast(`${res.count} domain(s) ${action === 'move' ? 'moved' : action === 'remove' ? 'removed' : 'changed'}.`);
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
        history.replaceState(null, '', value.length > 1 ? `?unit=${value.slice(1)}` : location.pathname);
        pfRenderChrome(); pfRender();
    });
    const params = new URLSearchParams(location.search);
    const wanted = params.get('unit') || params.get('group');
    if (wanted) pf.initialGroup = `g${wanted}`;
    // "+ Domains" on a unit: the add form, open, with that unit chosen.
    if (wanted) pf.importUnit = wanted;
    if (params.get('add') && $('pfImportFold')) {
        $('pfImportFold').open = true;
        setTimeout(() => {
            $('pfImportFold').scrollIntoView({ behavior: 'smooth', block: 'start' });
            $('pfImportInput').focus();
        }, 200);
    }
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
        $('pfLifecycleBtn').addEventListener('click', () => pfBulk('lifecycle', $('pfLifecycleValue').value));
        $('pfIntelBtn').addEventListener('click', () => pfBulk('threat_intel', $('pfIntelValue').value === 'true'));
        $('pfContactValue').addEventListener('change', () => contactToggleNew($('pfContactValue')));
        $('pfContactBtn').addEventListener('click', async () => {
            if (!pf.selected.size) { toast('Select domains first.'); return; }
            try { pfBulk('contact', await contactResolve($('pfContactValue'))); } catch (err) { toast(err.message); }
        });
        // Threat intelligence on or off, one domain at a time.
        $('pfGroups').addEventListener('click', async e => {
            const toggle = e.target.closest('.pf-intel');
            if (!toggle) return;
            const id = toggle.closest('tr[data-id]').dataset.id;
            const on = toggle.getAttribute('aria-checked') !== 'true';
            toggle.setAttribute('aria-checked', String(on));
            toggle.disabled = true;
            try {
                await pfPost('/api/portfolio/domains', { action: 'threat_intel', ids: [Number(id)], value: on });
            } catch (err) { toast(err.message); }
            pfLoad();
        });
        $('pfGroups').addEventListener('click', async e => {
            const cell = e.target.closest('td');
            const row = e.target.closest('tr[data-id]');
            if (!cell || !row) return;
            const d = pf.data.domains.find(x => String(x.id) === row.dataset.id);
            if (e.target.classList.contains('pf-contact-link')) {
                pfContactEdit(cell, d);
            } else if (e.target.classList.contains('pf-contact-cancel')) {
                cell.innerHTML = pfContact(d);
            } else if (e.target.classList.contains('pf-contact-save')) {
                e.target.disabled = true;
                try {
                    const contact = await contactResolve(cell.querySelector('.pf-contact-choice'));
                    await pfPost('/api/portfolio/domains', { action: 'contact', ids: [d.id], value: contact });
                } catch (err) { toast(err.message); e.target.disabled = false; return; }
                pfLoad();
            }
        });
        $('pfGroups').addEventListener('change', e => {
            if (e.target.classList.contains('pf-contact-choice')) contactToggleNew(e.target);
        });
        $('pfGroups').addEventListener('keydown', e => {
            if (e.key === 'Enter' && e.target.closest('.contact-new')) {
                e.target.closest('td').querySelector('.pf-contact-save').click();
            }
        });
        contactBookLoad().then(() => { if (pf.data) pfRenderChrome(); });
        $('pfMonitorBtn').addEventListener('click', async () => {
            if (!pf.selected.size) { toast('Select domains first.'); return; }
            const schedule = $('pfMonitorSchedule');
            if (!confirm(`Create a security monitor for ${pf.selected.size} domain(s), `
                + `${schedule.selectedOptions[0].textContent.toLowerCase()}? Domains already monitored, on any of their hosts, are skipped; `
                + 'the first scans are spread over that interval.')) return;
            try {
                const res = await pfPost('/api/portfolio/monitor', {
                    ids: [...pf.selected], schedule_minutes: Number(schedule.value) });
                toast(`${res.created.length} monitor(s) created, ${res.already_monitored} already monitored.`);
                pf.selected.clear();
            } catch (err) { toast(err.message); }
            pfLoad();
        });
        $('pfImportBtn').addEventListener('click', async () => {
            const text = $('pfImportInput').value;
            const sheet = pf.sheet;
            if (!text.trim() && !sheet) { toast('Paste domains or choose a file first.'); return; }
            // An existing unit goes by its id, a new one by the path typed.
            const choice = $('pfImportUnit').value;
            const newPath = $('pfImportGroup').value.trim();
            if (choice === 'new' && !newPath) { toast('Give the new unit a name first.'); $('pfImportGroup').focus(); return; }
            const target = choice === 'new' ? { unit: newPath } : { unit_id: choice };
            const known = (pf.data.groups || []).find(g => String(g.id) === choice);
            const unitName = choice === 'new' ? newPath.split('>').map(s => s.trim()).join(' › ') : (known ? known.path : '');
            try {
                let res;
                if (sheet) {
                    // A workbook is read on the server; the browser cannot.
                    const form = new FormData();
                    form.append('file', sheet);
                    Object.entries(target).forEach(([k, v]) => form.append(k, v));
                    res = await requestJson('/api/portfolio/import', { method: 'POST', body: form });
                } else {
                    res = await pfPost('/api/portfolio/import', { text, ...target });
                }
                pfShowImport(res, unitName);
                if (choice === 'new') {
                    // The unit exists now; keep it chosen for the next paste.
                    $('pfImportGroup').value = '';
                    pf.importNewPath = newPath;
                }
                $('pfImportInput').value = '';
                pf.sheet = null;
                $('pfImportFile').value = '';
                $('pfImportInput').disabled = false;
            } catch (err) { toast(err.message); }
            await pfLoad();
            if (pf.importNewPath) {
                const want = pf.importNewPath.split('>').map(s => s.trim().toLowerCase()).join(' › ');
                const made = pf.data.groups.find(g => g.path.toLowerCase() === want);
                if (made) { $('pfImportUnit').value = String(made.id); $('pfImportNewField').classList.add('hidden'); }
                pf.importNewPath = null;
            }
        });
        $('pfImportUnit').addEventListener('change', () => {
            const isNew = $('pfImportUnit').value === 'new';
            $('pfImportNewField').classList.toggle('hidden', !isNew);
            if (isNew) $('pfImportGroup').focus();
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
