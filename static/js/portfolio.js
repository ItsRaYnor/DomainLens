// Monitoring -> Domain portfolio. Uses $, esc, requestJson and toast from
// lookup.js, which this page loads first.

const PF_PHASE_CLASS = {
    registered: 'status-pass', quarantine: 'status-fail', pending_delete: 'status-fail',
    not_registered: 'status-fail', redemption: 'status-warn', not_in_dns: 'status-warn',
};
const PF_FLAG_TEXT = {
    attention: 'Quarantine / deleted', expiring: 'Expiring ≤ 30 days',
    move: 'To move', intel: 'In use, no threat intel', claimable: 'Free to request',
    unmeasured: 'Registration not measured', use_unmeasured: 'Use not measured', wanted: 'Wanted',
    dns_dead: 'Name servers do not answer',
};
const PF_LIFECYCLE_CLASS = { keep: '', review: 'status-warn', cancel: 'muted', claim: '' };
const PF_SCHEDULES = [[1440, 'daily'], [10080, 'weekly'], [360, 'every 6 hours']];
const PF_NOT_HELD = ['cancel', 'claim'];
const pf = { data: null, selected: new Set(), canEdit: false };

function pfWhen(iso) {
    const d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

function pfScheduleText(minutes) {
    const known = PF_SCHEDULES.find(([m]) => m === minutes);
    return known ? known[1] : minutes ? `every ${minutes} min` : '';
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
    if (d.transfer === 'unmeasured') return '<span class="muted">Registrar not known yet</span>';
    return '';
}

// Mail and web, each measured yes or no, or not measured: never "no" for
// unknown. Two small labels instead of a sentence per row.
function pfUse(d) {
    if (d.dns_state === 'no_answer' && !d.uses_mail && !d.uses_web) {
        return '<span class="muted" title="The name servers do not answer, so use cannot be measured">Use not measurable</span>';
    }
    if (!d.uses_mail && !d.uses_web) return '<span class="muted">Use not measured yet</span>';
    const chip = (v, label, icon) => `<span class="pf-use pf-use-${v === 'yes' ? 'yes' : v === 'no' ? 'no' : 'na'}" `
        + `title="${esc(label)}: ${v === 'yes' ? 'in use' : v === 'no' ? 'not in use' : 'not measured'}">${icon} ${esc(label)}</span>`;
    return chip(d.uses_mail, 'Mail', '✉') + chip(d.uses_web, 'Web', '🌐');
}

function pfIntelState(d) {
    const s = d.threat_intel_state;
    if (s === 'enrolled') return '<span class="status-pass">Enrolled</span>';
    if (s === 'missing') return '<span class="status-warn" title="In use: it belongs with the threat intelligence service">Not enrolled</span>';
    if (s === 'not_needed') return '<span class="muted">Not needed</span>';
    return '';
}

// Use and threat intelligence in one cell: whether the domain is in use
// decides whether it belongs with the threat intelligence service.
function pfIntel(d) {
    const use = PF_NOT_HELD.includes(d.lifecycle) ? '' : `<div class="pf-use-row">${pfUse(d)}</div>`;
    if (!pf.canEdit) return use + pfIntelState(d);
    return use + '<div class="pf-intel-cell">'
        + `<button type="button" class="switch pf-intel" role="switch" aria-checked="${d.threat_intel}" `
        + `aria-label="Threat intelligence for ${esc(d.domain)}" `
        + `title="${d.threat_intel ? 'Remove from threat intelligence' : 'Add to threat intelligence'}"></button>`
        + `<span>${pfIntelState(d)}</span></div>`;
}

// The decision, changed on the row itself.
function pfLifecycle(d) {
    const claimable = d.flags.includes('claimable') ? '<div class="status-pass">Free: can be requested now</div>' : '';
    if (!pf.canEdit) return `<span class="${PF_LIFECYCLE_CLASS[d.lifecycle] || ''}">${esc(d.lifecycle_text)}</span>` + claimable;
    return `<select class="pf-decision" aria-label="Decision for ${esc(d.domain)}">`
        + (pf.data.lifecycles || []).map(l => `<option value="${esc(l.value)}"${l.value === d.lifecycle ? ' selected' : ''}>${esc(l.text)}</option>`).join('')
        + '</select>' + claimable;
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

// Security monitoring of one domain: on, paused or off, switched here.
function pfShield(d) {
    const m = d.monitor || { state: d.monitored ? 'on' : 'off' };
    const text = m.state === 'on' ? `Monitored ${pfScheduleText(m.schedule_minutes)}`.trim()
        : m.state === 'paused' ? 'Monitoring paused' : 'Not monitored';
    const body = `<span class="pf-shield-icon" aria-hidden="true">🛡</span><span>${esc(text)}</span>`;
    if (!pf.canEdit || PF_NOT_HELD.includes(d.lifecycle) && m.state === 'off') {
        return m.state === 'off' ? '' : `<span class="pf-shield pf-shield-${m.state}">${body}</span>`;
    }
    return `<button type="button" class="pf-shield pf-shield-${m.state}" `
        + `title="${m.state === 'on' ? 'Pause security monitoring' : 'Monitor security'}">${body}</button>`;
}

function pfRow(d) {
    // The lookup time is in the tooltip; "Check now" is in the row's menu.
    const looked = d.last_checked_at ? `Looked up ${pfWhen(d.last_checked_at)}` : '';
    const phase = `<span class="pf-phase ${PF_PHASE_CLASS[d.phase] || ''}" title="${esc(looked)}">${esc(d.phase_text)}</span>`
        + (d.released_from ? `<div class="muted">Released from ${esc(pfWhen(d.released_from))}</div>` : '')
        + (d.stale ? `<div class="muted" title="${esc(d.last_error)}">Last lookup failed; showing the answer from ${esc(pfWhen(d.last_ok_at))}</div>` : '')
        + (d.phase === 'unmeasured' && d.last_error ? `<div class="muted">${esc(d.last_error)}</div>` : '')
        + (d.dns_state === 'no_answer'
            ? '<div class="status-fail" title="The name servers the registry delegates this domain to do not answer for it: it resolves nowhere.">Name servers do not answer</div>' : '');
    const registrar = d.registrar ? esc(d.registrar) + (d.reseller ? ` <span class="muted">via ${esc(d.reseller)}</span>` : '') : '<span class="muted">Registrar unknown</span>';
    const transfer = pfTransfer(d);
    const check = pf.canEdit
        ? `<td><input type="checkbox" class="pf-select" value="${d.id}"${pf.selected.has(String(d.id)) ? ' checked' : ''} aria-label="Select ${esc(d.domain)}"></td>` : '';
    const menu = pf.canEdit
        ? `<td class="pf-row-actions"><button type="button" class="btn-ghost-sm pf-row-menu" aria-haspopup="menu" aria-label="Actions for ${esc(d.domain)}">⋯</button></td>` : '';
    return `<tr data-id="${d.id}">${check}<td><a href="/tools/whois?domain=${encodeURIComponent(d.domain)}"><code>${esc(d.domain).replace(/([.-])/g, '$1<wbr>')}</code></a>`
        + (d.note ? `<div class="muted">${esc(d.note)}</div>` : '')
        + `<div>${pfShield(d)}</div></td>`
        + `<td>${registrar}<div>${pfExpiry(d)}</div>${transfer ? `<div>${transfer}</div>` : ''}</td>`
        + `<td>${phase}</td>`
        + `<td>${pfIntel(d)}</td>`
        + `<td>${pfLifecycle(d)}</td>`
        + `<td>${pfContact(d)}</td>${menu}</tr>`;
}

function pfCounts(c) {
    return Object.keys(PF_FLAG_TEXT).filter(f => c[f])
        .map(f => `<span class="${['unmeasured', 'use_unmeasured', 'wanted'].includes(f) ? 'muted' : 'pf-count-warn'}">${c[f]} ${esc(PF_FLAG_TEXT[f].toLowerCase())}</span>`)
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

// A unit's security monitoring in one line, with one menu to change it: all
// of its domains (and the units below it), and the ones added later.
function pfUnitBar(group) {
    const below = pfDescendants(pf.data.groups, group.id);
    const held = pf.data.domains.filter(d => below.has(d.group_id) && !PF_NOT_HELD.includes(d.lifecycle));
    if (!held.length && !group.monitor_effective) return '';
    const on = held.filter(d => d.monitor && d.monitor.state === 'on').length;
    const scope = below.size > 1 ? ' in this unit and the units below it' : '';
    const auto = group.monitor_effective
        ? `New domains are monitored too (${pfScheduleText(group.monitor_effective)}${group.monitor_inherited ? ', set on a unit above' : ''})`
        : 'New domains are not monitored automatically';
    const button = pf.canEdit
        ? `<button type="button" class="btn-ghost-sm pf-unit-monitor" data-group="${group.id}" aria-haspopup="menu">Monitoring ▾</button>` : '';
    return `<div class="pf-unit-bar"><span>🛡 ${esc(`Security monitoring: ${on} of ${held.length} domains${scope}`)}</span>`
        + `<span class="muted">${esc(auto)}</span>${button}</div>`;
}

function pfRender() {
    const data = pf.data;
    if (!data) return;
    const groupFilter = $('pfGroupFilter').value;
    // A unit shows with the units below it: a company's view covers its parts.
    const inScope = groupFilter === '' ? null
        : groupFilter === 'g' ? new Set([''])
        : new Set([...pfDescendants(data.groups, Number(groupFilter.slice(1)))].map(String));
    const byId = Object.fromEntries(data.groups.map(g => [String(g.id), g]));
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
        const bar = s.key ? pfUnitBar(byId[s.key]) : '';
        // An empty unit that only holds other units is a heading, not a gap.
        if (!all.length && data.groups.some(g => String(g.parent_id) === s.key)) {
            return `<div class="pf-unit-heading" style="margin-left:${s.depth * 1.25}rem"><h4>${esc(s.name)}</h4>${bar}</div>`;
        }
        const head = pf.canEdit
            ? '<th><label class="nowrap"><input type="checkbox" class="pf-select-all" aria-label="Select all in this unit">'
              + ' <span class="stack-only">Select all</span></label></th>' : '';
        const table = shown.length
            ? `<div class="users-table-wrap"><table class="data-table portfolio-table stack-table">`
              + `<tr>${head}<th>Domain</th><th>Registration</th><th>Status</th>`
              + `<th>Use · threat intel</th><th>Decision</th><th>Contact</th>${pf.canEdit ? '<th></th>' : ''}</tr>`
              + shown.map(pfRow).join('') + '</table></div>'
            : `<p class="muted">${all.length ? 'No domains in this unit match the filter.' : 'No domains in this unit yet.'}</p>`;
        const counts = pfCounts(summaries[s.key] || {});
        return `<details class="monitor-fold discovered-zone" open data-group="${esc(s.key)}" style="margin-left:${s.depth * 1.25}rem">`
            + `<summary><h4>${esc(s.name)}</h4><span class="muted">${all.length} domain${all.length === 1 ? '' : 's'}`
            + (s.expected ? ` &middot; expected at ${esc(s.expected)}${s.inherited ? ' (inherited)' : ''}` : '') + '</span>'
            + (counts ? ` &middot; ${counts}` : '') + `</summary>${bar}${table}</details>`;
    }).join('');
    // Domains without a unit stand out, with one way to place them.
    const loose = data.groups.length ? data.domains.filter(d => !d.group_id).length : 0;
    const notice = loose && pf.canEdit && !inScope
        ? `<div class="pf-notice"><span>${esc(`${loose} domain(s) are not in a unit yet.`)}</span>`
          + '<button type="button" class="btn-ghost-sm primary" id="pfAssignLoose" aria-haspopup="menu">Assign to a unit…</button></div>'
        : '';
    $('pfGroups').innerHTML = notice + (html || (data.domains.length
        ? '<p class="muted">No domains match the filter.</p>'
        : '<p class="muted">No domains in the portfolio yet. Add them below.</p>'));
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
        + tile('Wanted (request or claim)', t.wanted, 'wanted', '')
        + tile('Name servers do not answer', t.dns_dead, 'dns_dead', 'tile-bad')
        + tile('Use not measured', t.use_unmeasured, 'use_unmeasured', '')
        + tile('Registration not measured', t.unmeasured, 'unmeasured', '');

    const current = pf.initialGroup || $('pfGroupFilter').value;
    pf.initialGroup = null;
    $('pfGroupFilter').innerHTML = '<option value="">All units</option>'
        + data.groups.map(g => `<option value="g${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('')
        + '<option value="g">Not in a unit</option>';
    $('pfGroupFilter').value = current;
    if ($('pfImportUnit')) {
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

// The action bar shows only with a selection: without one it was five
// lists and buttons between the filters and the domains.
function pfUpdateSelected() {
    const bar = $('pfBulkBar');
    if (!bar) return;
    bar.classList.toggle('hidden', !pf.selected.size);
    $('pfSelected').textContent = `${pf.selected.size} selected`;
}

async function pfPost(url, body, method) {
    return requestJson(url, {
        method: method || 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
    });
}

// ===== Menus =====
// One menu at a time, under the button that opened it. An item is applied
// at once: no second "Set" button.

function pfCloseMenu() {
    const open = document.querySelector('.pf-menu');
    if (open) open.remove();
    pf.menuAnchor = null;
}

// A menu stays under the button that opened it. That button can sit in the
// action bar, which stays at the top while the page scrolls: placed once,
// the menu was left floating over the domains. It follows the button, and
// closes when the button leaves the screen.
function pfPlaceMenu() {
    const menu = document.querySelector('.pf-menu');
    const anchor = pf.menuAnchor;
    if (!menu || !anchor) return;
    const r = anchor.getBoundingClientRect();
    if (!document.body.contains(anchor) || r.bottom < 0 || r.top > window.innerHeight) { pfCloseMenu(); return; }
    const left = Math.max(8, Math.min(r.left, document.documentElement.clientWidth - menu.offsetWidth - 8));
    menu.style.left = `${window.scrollX + left}px`;
    menu.style.top = `${window.scrollY + r.bottom + 4}px`;
}

function pfOpenMenu(anchor, items, onPick, extra) {
    pfCloseMenu();
    const menu = document.createElement('div');
    menu.className = 'pf-menu';
    menu.setAttribute('role', 'menu');
    const filterable = items.length > 8;
    menu.innerHTML = (filterable ? '<input type="search" class="pf-menu-filter" placeholder="Find…" aria-label="Find">' : '')
        + items.map((it, i) => it.sep ? '<hr>'
            : `<button type="button" role="menuitem" class="pf-menu-item${it.danger ? ' danger' : ''}" data-i="${i}"${it.title ? ` title="${esc(it.title)}"` : ''}>${esc(it.label)}</button>`).join('')
        + (extra || '');
    document.body.appendChild(menu);
    pf.menuAnchor = anchor;
    pfPlaceMenu();
    menu.addEventListener('click', e => {
        const item = e.target.closest('.pf-menu-item');
        if (!item) return;
        pfCloseMenu();
        onPick(items[Number(item.dataset.i)].value);
    });
    const filter = menu.querySelector('.pf-menu-filter');
    if (filter) {
        filter.addEventListener('input', () => {
            const q = filter.value.trim().toLowerCase();
            menu.querySelectorAll('.pf-menu-item').forEach(b => b.classList.toggle('hidden', q && !b.textContent.toLowerCase().includes(q)));
        });
        filter.focus();
    } else {
        const first = menu.querySelector('.pf-menu-item, select');
        if (first) first.focus();
    }
    return menu;
}

function pfUnitItems() {
    return pf.data.groups.map(g => ({ label: g.path, value: String(g.id) }))
        .concat([{ sep: true }, { label: 'Not in a unit', value: '' }]);
}

function pfMonitorItems() {
    return PF_SCHEDULES.map(([m, text]) => ({ label: `Monitor security, ${text}`, value: m }))
        .concat([{ sep: true }, { label: 'Pause monitoring', value: 0 }]);
}

// ===== Applying, with undo =====

function pfShowUndo(message, undo) {
    let box = $('pfUndo');
    if (!box) {
        box = document.createElement('div');
        box.id = 'pfUndo';
        box.className = 'pf-undo';
        box.setAttribute('role', 'status');
        document.body.appendChild(box);
    }
    box.innerHTML = `<span>${esc(message)}</span>` + (undo ? '<button type="button" class="btn-ghost-sm">Undo</button>' : '');
    box.classList.remove('hidden');
    clearTimeout(pf.undoTimer);
    pf.undoTimer = setTimeout(() => box.classList.add('hidden'), 9000);
    if (undo) {
        box.querySelector('button').addEventListener('click', async () => {
            box.classList.add('hidden');
            try { await undo(); toast('Undone.'); } catch (err) { toast(err.message); }
            pfLoad();
        });
    }
}

// What a domain had before an action, to put back on undo.
function pfBefore(action, d) {
    if (action === 'move') return d.group_id ? String(d.group_id) : '';
    if (action === 'lifecycle') return d.lifecycle;
    if (action === 'threat_intel') return !!d.threat_intel;
    if (action === 'contact') return d.contact && !d.contact_inherited ? d.contact.id : null;
    if (action === 'monitor') return d.monitor && d.monitor.state === 'on' ? (d.monitor.schedule_minutes || 1440) : 0;
    return null;
}

function pfBody(action, ids, value) {
    const body = { action, ids: ids.map(Number) };
    if (action === 'move') body.unit_id = value; else body.value = value;
    return body;
}

const PF_DONE = {
    move: 'moved', lifecycle: 'given a new decision', threat_intel: 'changed in threat intelligence',
    contact: 'given a contact', monitor: 'changed in monitoring', remove: 'removed',
};

async function pfApply(action, ids, value) {
    ids = ids.map(String);
    if (!ids.length) { toast('Select domains first.'); return; }
    if (action === 'remove' && !confirm(`Remove ${ids.length} domain(s) from the portfolio? Their registration history goes with them.`)) return;
    const domains = pf.data.domains.filter(d => ids.includes(String(d.id)));
    const before = new Map();
    domains.forEach(d => {
        const key = JSON.stringify(pfBefore(action, d));
        before.set(key, (before.get(key) || []).concat(d.id));
    });
    try {
        const res = await pfPost('/api/portfolio/domains', pfBody(action, ids, value));
        const extra = action === 'move' && res.monitored ? `, ${res.monitored} now monitored by their unit` : '';
        const undo = action === 'remove' ? null : async () => {
            for (const [key, group] of before) await pfPost('/api/portfolio/domains', pfBody(action, group, JSON.parse(key)));
        };
        const what = action === 'monitor' ? (value ? `now monitored ${pfScheduleText(Number(value))}` : 'no longer monitored (paused)')
            : action === 'threat_intel' ? (value ? 'added to threat intelligence' : 'removed from threat intelligence')
            : PF_DONE[action] || 'changed';
        pfShowUndo(`${ids.length} domain(s) ${what}${extra}.`, undo);
        if (action === 'remove') ids.forEach(id => pf.selected.delete(id));
    } catch (err) { toast(err.message); }
    pfLoad();
}

async function pfCheckNow(id) {
    try { await pfPost(`/api/portfolio/domains/${id}/check`); toast('Looked up again.'); } catch (err) { toast(err.message); }
    pfLoad();
}

async function pfUnitMonitoring(groupId, minutes) {
    const group = pf.data.groups.find(g => g.id === groupId);
    if (!minutes && !confirm(`Stop security monitoring for ${group ? group.path : 'this unit'}? Its monitors are paused; their history stays.`)) return;
    try {
        const res = await pfPost(`/api/portfolio/groups/${groupId}/monitoring`, { schedule_minutes: minutes });
        toast(minutes
            ? `${res.created + res.enabled} domain(s) now monitored ${pfScheduleText(minutes)}; new domains in this unit follow.`
            : `${res.paused} monitor(s) paused.`);
    } catch (err) { toast(err.message); }
    pfLoad();
}

function pfContactMenu(anchor, ids) {
    const panel = '<div class="pf-menu-panel"><span class="contact-pick">'
        + `<select class="pf-menu-contact" aria-label="Contact">${contactOptions("The unit's contact")}</select>`
        + contactNewFields('menu') + '</span>'
        + '<button type="button" class="btn-ghost-sm primary pf-menu-contact-apply">Apply</button></div>';
    const menu = pfOpenMenu(anchor, [], () => {}, panel);
    const select = menu.querySelector('.pf-menu-contact');
    select.addEventListener('change', () => contactToggleNew(select));
    select.focus();
    menu.querySelector('.pf-menu-contact-apply').addEventListener('click', async () => {
        try {
            const contact = await contactResolve(select);
            pfCloseMenu();
            pfApply('contact', ids, contact);
        } catch (err) { toast(err.message); }
    });
}

// The action bar's menus, for the selection.
function pfBulkMenu(button) {
    const ids = [...pf.selected];
    const kind = button.dataset.menu;
    if (kind === 'move') pfOpenMenu(button, pfUnitItems(), v => pfApply('move', ids, v));
    else if (kind === 'monitor') pfOpenMenu(button, pfMonitorItems(), v => pfApply('monitor', ids, v));
    else if (kind === 'decision') pfOpenMenu(button, (pf.data.lifecycles || []).map(l => ({ label: l.text, value: l.value })), v => pfApply('lifecycle', ids, v));
    else if (kind === 'intel') pfOpenMenu(button, [{ label: 'Add to threat intelligence', value: true }, { label: 'Remove from threat intelligence', value: false }], v => pfApply('threat_intel', ids, v));
    else if (kind === 'contact') pfContactMenu(button, ids);
    else if (kind === 'more') {
        pfOpenMenu(button, [{ label: 'Look up again now', value: 'check' }, { sep: true },
            { label: 'Remove from portfolio…', value: 'remove', danger: true }], async v => {
            if (v === 'remove') pfApply('remove', ids);
            else { for (const id of ids) await pfPost(`/api/portfolio/domains/${id}/check`).catch(() => {}); toast('Looked up again.'); pfLoad(); }
        });
    }
}

// One domain's menu: the same actions without selecting it first.
function pfRowMenu(button) {
    const id = button.closest('tr[data-id]').dataset.id;
    const d = pf.data.domains.find(x => String(x.id) === id);
    const on = d.monitor && d.monitor.state === 'on';
    pfOpenMenu(button, [
        { label: 'Move to unit…', value: 'move' },
        { label: on ? 'Pause monitoring' : 'Monitor security, daily', value: 'monitor' },
        { label: 'Look up again now', value: 'check' },
        { sep: true },
        { label: 'Remove from portfolio…', value: 'remove', danger: true },
    ], v => {
        if (v === 'move') pfOpenMenu(button, pfUnitItems(), unit => pfApply('move', [id], unit));
        else if (v === 'monitor') pfApply('monitor', [id], on ? 0 : 1440);
        else if (v === 'check') pfCheckNow(id);
        else if (v === 'remove') pfApply('remove', [id]);
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
    if (res.monitored && res.monitored.length) parts.push(`Security monitoring started for ${res.monitored.length} domain(s), as their unit asks.`);
    if (res.not_understood && res.not_understood.length) parts.push(`Not understood, left as it was: ${res.not_understood.join('; ')}.`);
    if (res.added.length) parts.push('New domains are looked up within a few minutes.');
    $('pfImportResult').textContent = parts.join(' ');
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
    // ?flag=wanted (the former Wanted domains page) and the like: open filtered.
    const flag = params.get('flag');
    if (flag && [...$('pfFlagFilter').options].some(o => o.value === flag)) $('pfFlagFilter').value = flag;
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
    // A click outside an open menu closes it; Escape too.
    document.addEventListener('click', e => {
        if (!e.target.closest('.pf-menu') && !e.target.closest('[aria-haspopup="menu"]')) pfCloseMenu();
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') pfCloseMenu(); });
    window.addEventListener('scroll', pfPlaceMenu, { passive: true });
    window.addEventListener('resize', pfPlaceMenu);
    if (pf.canEdit) {
        $('pfBulkBar').addEventListener('click', e => {
            const button = e.target.closest('[data-menu]');
            if (button) pfBulkMenu(button);
            if (e.target.id === 'pfClearSel') { pf.selected.clear(); pfRender(); }
        });
        $('pfGroups').addEventListener('click', async e => {
            const rowMenu = e.target.closest('.pf-row-menu');
            if (rowMenu) { pfRowMenu(rowMenu); return; }
            const unitMenu = e.target.closest('.pf-unit-monitor');
            if (unitMenu) {
                e.preventDefault();
                const groupId = Number(unitMenu.dataset.group);
                const group = pf.data.groups.find(g => g.id === groupId);
                const items = PF_SCHEDULES.map(([m, text]) => ({ label: `Monitor all domains, ${text}`, value: m }));
                if (group && (group.monitor_minutes || pf.data.domains.some(d => pfDescendants(pf.data.groups, groupId).has(d.group_id) && d.monitor && d.monitor.state === 'on'))) {
                    items.push({ sep: true }, { label: 'Stop monitoring this unit', value: 0, danger: true });
                }
                pfOpenMenu(unitMenu, items, v => pfUnitMonitoring(groupId, v));
                return;
            }
            if (e.target.id === 'pfAssignLoose') {
                pf.data.domains.filter(d => !d.group_id).forEach(d => pf.selected.add(String(d.id)));
                pfRender();
                pfOpenMenu($('pfAssignLoose') || e.target, pfUnitItems().filter(i => i.sep || i.value !== ''),
                    v => pfApply('move', pf.data.domains.filter(d => !d.group_id).map(d => d.id), v));
                return;
            }
            const shield = e.target.closest('button.pf-shield');
            if (shield) {
                const id = shield.closest('tr[data-id]').dataset.id;
                const d = pf.data.domains.find(x => String(x.id) === id);
                pfApply('monitor', [id], d.monitor && d.monitor.state === 'on' ? 0 : 1440);
                return;
            }
            // Threat intelligence on or off, one domain at a time.
            const toggle = e.target.closest('.pf-intel');
            if (toggle) {
                const id = toggle.closest('tr[data-id]').dataset.id;
                const on = toggle.getAttribute('aria-checked') !== 'true';
                toggle.setAttribute('aria-checked', String(on));
                toggle.disabled = true;
                pfApply('threat_intel', [id], on);
                return;
            }
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
                    await pfApply('contact', [d.id], contact);
                } catch (err) { toast(err.message); e.target.disabled = false; }
            }
        });
        $('pfGroups').addEventListener('change', e => {
            if (e.target.classList.contains('pf-contact-choice')) contactToggleNew(e.target);
            if (e.target.classList.contains('pf-decision')) {
                pfApply('lifecycle', [e.target.closest('tr[data-id]').dataset.id], e.target.value);
            }
        });
        $('pfGroups').addEventListener('keydown', e => {
            if (e.key === 'Enter' && e.target.closest('.contact-new')) {
                e.target.closest('td').querySelector('.pf-contact-save').click();
            }
        });
        contactBookLoad();
        $('pfImportBtn').addEventListener('click', async () => {
            const text = $('pfImportInput').value;
            const sheet = pf.sheet;
            if (!text.trim() && !sheet) { toast('Paste domains or choose a file first.'); return; }
            // An existing unit goes by its id, a new one by the path typed.
            const choice = $('pfImportUnit').value;
            const newPath = $('pfImportGroup').value.trim();
            if (choice === 'new' && !newPath) { toast('Give the new unit a name first.'); $('pfImportGroup').focus(); return; }
            const target = choice === 'new' ? { unit: newPath } : { unit_id: choice };
            target.lifecycle = $('pfImportLifecycle').value;
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
