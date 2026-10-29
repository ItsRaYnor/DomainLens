// Monitoring -> Monitor events: every event of every monitor, to filter on
// severity, kind, monitor, unit and period, each change with its "what
// changed?". It was a hundred cards under the monitors, the "no changes"
// ones in between. Uses lookup.js, logview.js and compare_view.js.

const EV_KEYS = ['q', 'unit', 'monitor_id', 'from', 'to'];
const EV_SETS = ['type', 'severity'];
const EV_PAGE = 100;
const EV_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
// Opening the page shows what happened, not every scan that found nothing:
// "No change" is one click away.
const EV_DEFAULT_TYPES = ['scan_changed', 'known_cve_new', 'baseline_created', 'scan_failed', 'dns_unanswered'];
const EV_TYPE_ORDER = ['scan_changed', 'known_cve_new', 'scan_failed', 'dns_unanswered', 'baseline_created', 'scan_unchanged'];
const ev = { state: null, rows: [], canEdit: false, drawPeriod: null, monitorsLoaded: false };

function evRow(e) {
    const prev = e.details && e.details.previous_scan_id;
    const canCompare = e.event_type === 'scan_changed' && prev && e.scan_id;
    // A change whose comparison is known to show nothing: an event of the
    // earlier way of detecting changes. Said here rather than after a click.
    const note = e.explained === 'no'
        ? '<span class="lv-sub lv-note">The comparison shows no difference: recorded by the earlier way of detecting changes, which also counted values that differ on every scan.</span>'
        : '';
    const links = [
        canCompare ? `<button type="button" class="lv-toggle" data-compare="${esc(String(prev))}:${esc(String(e.scan_id))}" aria-expanded="false">What changed?</button>` : '',
        e.scan_id ? `<a href="/report/${esc(String(e.scan_id))}">Report</a>` : '<span class="muted">Report deleted</span>',
    ].filter(Boolean).join('<br>');
    return `<tr data-id="${esc(String(e.id))}">
        ${ev.canEdit ? `<td><input type="checkbox" class="ev-select" value="${esc(String(e.id))}" aria-label="Select this event"></td>` : ''}
        <td class="nowrap">${esc(lvWhen(e.created_at))}</td>
        <td><span class="rec-badge sev-${esc(e.severity)}">${esc((e.severity || 'info').toUpperCase())}</span></td>
        <td><button type="button" class="lv-toggle" data-filter-monitor="${esc(String(e.monitor_id))}" title="Only this monitor"><code>${esc(e.monitor_target || e.monitor_name || '')}</code></button>
            ${e.monitor_name && e.monitor_name !== e.monitor_target ? `<span class="lv-sub">${esc(e.monitor_name)}</span>` : ''}</td>
        <td>${e.unit ? `<span>${esc(e.unit)}</span>` : '<span class="muted">—</span>'}</td>
        <td><span class="lv-sub">${esc(e.type_text || e.event_type || '')}</span><span>${esc(e.summary || '')}</span>${note}
            ${e.servicenow_number ? `<span class="lv-sub">ServiceNow ${esc(e.servicenow_number)}</span>` : ''}</td>
        <td class="nowrap">${links}</td>
    </tr>`;
}

async function evLoad(append) {
    const s = ev.state;
    const qs = lvQuery(s, EV_KEYS, EV_SETS);
    if (!append) {
        lvWrite(qs);
    }
    qs.set('limit', EV_PAGE);
    qs.set('offset', append ? ev.rows.length : 0);
    let data;
    try {
        data = await requestJson('/api/monitor-events?' + qs);
    } catch (err) {
        $('evCount').textContent = err.message;
        return;
    }
    ev.rows = append ? ev.rows.concat(data.events) : data.events;
    // A fixed order, most telling first: the server's object comes sorted by name.
    const types = EV_TYPE_ORDER.concat(Object.keys(data.types).filter(t => !EV_TYPE_ORDER.includes(t)))
        .filter(t => data.types[t] || s.type.has(t) || EV_DEFAULT_TYPES.includes(t))
        .map(t => ({ value: t, label: data.type_text[t] || t, count: data.types[t] }));
    lvChips($('evTypes'), types, s.type, () => evLoad(false));
    lvChips($('evSeverities'), EV_SEVERITIES.map(v => ({
        value: v, label: v, count: data.severities[v], cls: `sev-${v}` })), s.severity, () => evLoad(false));
    if (!ev.monitorsLoaded) {
        ev.monitorsLoaded = true;
        $('evMonitor').innerHTML = '<option value="">All monitors</option>' + data.monitors
            .slice().sort((a, b) => String(a.target).localeCompare(String(b.target)))
            .map(m => `<option value="${m.id}">${esc(m.target)}${m.name && m.name !== m.target ? ` (${esc(m.name)})` : ''}</option>`).join('');
    }
    $('evSearch').value = s.q;
    $('evFrom').value = s.from;
    $('evTo').value = s.to;
    $('evMonitor').value = s.monitor_id;
    if ($('evUnit').options.length > 1) $('evUnit').value = s.unit;
    ev.drawPeriod();
    $('evCount').textContent = data.total === 1 ? '1 event' : `${data.total} events`;
    const cols = ev.canEdit ? 7 : 6;
    $('evRows').innerHTML = ev.rows.length ? ev.rows.map(evRow).join('')
        : `<tr><td colspan="${cols}" class="lv-empty">${esc(evEmptyText())}</td></tr>`;
    $('evMore').classList.toggle('hidden', ev.rows.length >= data.total);
    evSyncSelection();
}

function evEmptyText() {
    const s = ev.state;
    const filtered = s.q || s.unit || s.monitor_id || s.from || s.to || s.severity.size || s.type.size;
    return filtered ? 'No event matches these filters.' : 'No monitor events yet.';
}

async function evCompare(btn) {
    const tr = btn.closest('tr');
    const open = tr.nextElementSibling && tr.nextElementSibling.classList.contains('lv-detail-row');
    if (open) {
        tr.nextElementSibling.remove();
        btn.setAttribute('aria-expanded', 'false');
        return;
    }
    btn.setAttribute('aria-expanded', 'true');
    const [a, b] = btn.dataset.compare.split(':');
    const detail = document.createElement('tr');
    detail.className = 'lv-detail-row';
    detail.innerHTML = `<td colspan="${tr.children.length}"><p class="muted">Comparing…</p></td>`;
    tr.after(detail);
    try {
        const data = await requestJson(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
        detail.firstElementChild.innerHTML = renderCompareHtml(data);
    } catch (err) {
        detail.firstElementChild.innerHTML = `<p class="status status-fail">${esc(err.message)}</p>`;
    }
}

function evSelected() {
    return [...document.querySelectorAll('#evRows .ev-select:checked')].map(cb => Number(cb.value));
}

function evSyncSelection() {
    if (!$('evTools')) return;
    const n = evSelected().length;
    $('evTools').classList.toggle('hidden', !n);
    $('evSelCount').textContent = n === 1 ? '1 selected' : `${n} selected`;
}

// An event raised in error -- an outage of the scanner read as a change of
// the domain -- can be removed, so it stops counting and alarming.
async function evDelete() {
    const ids = evSelected();
    if (!ids.length) return;
    if (!confirm(`Delete ${ids.length} event(s)? They are removed from the history; the reports they point to stay.`)) return;
    try {
        const data = await requestJson('/api/monitor-events/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }),
        });
        toast(`${data.deleted} event(s) deleted.`);
        evLoad(false);
    } catch (err) { toast(err.message); }
}

function initEvents() {
    if (!$('evRows')) return;
    try { ev.canEdit = JSON.parse($('evCanEdit').textContent); } catch (e) { ev.canEdit = false; }
    ev.state = lvRead(EV_KEYS, EV_SETS);
    if (!ev.state.typeGiven) EV_DEFAULT_TYPES.forEach(t => ev.state.type.add(t));
    ev.drawPeriod = lvPeriod($('evPeriod'), ev.state, () => evLoad(false));
    let typing;
    $('evSearch').addEventListener('input', () => {
        clearTimeout(typing);
        typing = setTimeout(() => { ev.state.q = $('evSearch').value.trim(); evLoad(false); }, 250);
    });
    $('evMonitor').addEventListener('change', () => { ev.state.monitor_id = $('evMonitor').value; evLoad(false); });
    $('evUnit').addEventListener('change', () => { ev.state.unit = $('evUnit').value; evLoad(false); });
    $('evFrom').addEventListener('change', () => { ev.state.from = $('evFrom').value; evLoad(false); });
    $('evTo').addEventListener('change', () => { ev.state.to = $('evTo').value; evLoad(false); });
    $('evMore').addEventListener('click', () => evLoad(true));
    $('evReset').addEventListener('click', () => {
        EV_KEYS.forEach(k => { ev.state[k] = ''; });
        ev.state.severity.clear();
        ev.state.type = new Set(EV_DEFAULT_TYPES);
        evLoad(false);
    });
    $('evRows').addEventListener('click', e => {
        const cmp = e.target.closest('[data-compare]');
        const mon = e.target.closest('[data-filter-monitor]');
        if (cmp) evCompare(cmp);
        if (mon) { ev.state.monitor_id = mon.dataset.filterMonitor; evLoad(false); }
    });
    $('evRows').addEventListener('change', e => { if (e.target.classList.contains('ev-select')) evSyncSelection(); });
    if ($('evDelete')) $('evDelete').addEventListener('click', evDelete);
    lvUnits($('evUnit'), ev.state.unit);
    evLoad(false);
}

document.addEventListener('DOMContentLoaded', initEvents);
