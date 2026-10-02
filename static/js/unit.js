// Monitoring -> Organisation -> one unit. Uses $, esc, requestJson and toast
// from lookup.js.

const UNIT_RATING_CLASS = r => 'history-grade mini g-' + String(r || 'na').toLowerCase();
const UNIT_SEV_COLOR = {
    critical: 'var(--sev-critical-badge)', high: 'var(--sev-high-badge)',
    medium: 'var(--sev-medium-badge)', low: 'var(--text-faint)',
};

function unitRating(p) {
    return p
        ? `<a href="/report/${p.scan_id}" class="unit-rating"><span class="${UNIT_RATING_CLASS(p.rating)}">${esc(p.rating)}</span></a>`
          + ` <span class="muted">${p.counts.critical} crit · ${p.counts.high} high</span>`
        : '<span class="muted">Not scanned</span>';
}

function unitWhen(iso) {
    const d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

function unitKpis(d) {
    const k = d.kpis, reg = (d.totals && d.totals.registration) || {}, sec = (d.totals && d.totals.security) || {};
    const kpi = (value, label, sub, cls) => `<div class="mgmt-kpi ${cls || ''}"><div class="value">${value}</div>`
        + `<div class="label">${esc(label)}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>`;
    const known = (reg.total || 0) - (reg.unmeasured || 0);
    $('unitKpis').innerHTML =
        kpi(k.in_order_pct === null ? '&mdash;' : `${k.in_order_pct}%`, 'In order (rating A or B)',
            `${k.in_order} of ${k.domains} scanned in 90 days`,
            k.in_order_pct === null ? '' : k.in_order_pct >= 80 ? 'good' : k.in_order_pct >= 50 ? 'warn' : 'bad')
        + kpi(k.critical, 'Open critical findings', '', k.critical ? 'bad' : 'good')
        + kpi(k.high, 'Open high findings', '', k.high ? 'warn' : 'good')
        + kpi(sec.monitors || 0, 'Monitors', `${sec.monitors_enabled || 0} running`)
        + kpi(reg.total || 0, 'Domains', reg.unmeasured ? `${reg.unmeasured} not looked up yet` : '')
        + (known
            ? kpi(reg.attention || 0, 'Registrations at risk', 'Quarantine, deleted or lost', reg.attention ? 'bad' : 'good')
              + kpi(reg.expiring || 0, 'Expiring within 30 days', '', reg.expiring ? 'warn' : 'good')
              + kpi(reg.move || 0, 'To move', 'At another registrar than expected', reg.move ? 'warn' : '')
            : '');
}

function unitRender(d) {
    $('unitTrail').innerHTML = '<a href="/monitoring/organisation">Organisation</a>'
        + d.ancestors.map(a => ` › <a href="/monitoring/organisation/${a.id}">${esc(a.name)}</a>`).join('')
        + ` › <span>${esc(d.unit.name)}</span>`;
    $('unitSub').textContent = (d.unit.effective_registrar
        ? `Registrar: ${d.unit.effective_registrar}${d.unit.registrar_inherited ? ' (inherited)' : ''} · ` : '')
        + 'Figures include the units below it.';
    $('unitSchedulerOff').classList.toggle('hidden', d.scheduler_enabled !== false);
    unitKpis(d);

    $('unitChildrenCard').classList.toggle('hidden', !d.children.length);
    $('unitChildren').innerHTML = d.children.length
        ? '<tr><th>Unit</th><th>Domains</th><th>In order</th><th>Critical / high</th><th>Monitors</th><th>At risk / expiring</th></tr>'
          + d.children.map(u => {
              const s = u.security, r = u.registration || {};
              return `<tr><td><a href="/monitoring/organisation/${u.id}">${esc(u.name)}</a></td><td>${r.total || 0}</td>`
                  + `<td>${s.scanned ? `${s.ratings.A + s.ratings.B} of ${s.scanned}` : '<span class="muted">&mdash;</span>'}</td>`
                  + `<td>${s.critical} / ${s.high}</td><td>${s.monitors}</td><td>${r.attention || 0} / ${r.expiring || 0}</td></tr>`;
          }).join('')
        : '';

    $('unitDomains').innerHTML = d.domains.length
        ? '<tr><th>Domain</th><th>Security</th><th>Registration</th><th>Expires</th><th>Registrar</th></tr>'
          + d.domains.map(x => {
              const phaseCls = x.flags.includes('attention') ? 'pf-count-bad' : x.phase === 'unmeasured' ? 'muted' : '';
              const expires = x.expiry_state === 'not_published' ? '<span class="muted">Not published</span>'
                  : x.expires ? `${esc(x.expires)}${x.days_left !== null ? ` (${x.days_left} d)` : ''}` : '<span class="muted">&mdash;</span>';
              return `<tr><td><a href="/tools/whois?domain=${encodeURIComponent(x.domain)}"><code>${esc(x.domain)}</code></a>`
                  + (x.group && x.group_id !== d.unit.id ? `<div class="muted">${esc(x.group.split(' › ').slice(-1)[0])}</div>` : '') + '</td>'
                  + `<td class="nowrap">${unitRating(x.posture)}${x.monitored ? '' : '<div class="muted">No monitor</div>'}</td>`
                  + `<td><span class="${phaseCls}">${esc(x.phase_text)}</span>`
                  + (x.transfer === 'move' ? '<div class="pf-count-warn">To move</div>' : '') + '</td>'
                  + `<td class="nowrap">${expires}</td><td>${esc(x.registrar || '')}</td></tr>`;
          }).join('')
        : '<tr><td class="muted">No domains in this unit yet. Add them in the domain portfolio, or from a scan result.</td></tr>';

    $('unitMonitors').innerHTML = d.monitors.length
        ? '<tr><th>Host</th><th>Rating</th><th>Last change</th></tr>' + d.monitors.map(m =>
            `<tr><td>${esc(m.target)}${m.enabled ? '' : ' <span class="muted">(paused)</span>'}</td>`
            + `<td class="nowrap">${unitRating(m.posture)}</td>`
            + `<td>${m.last_event ? `<span class="sev-text sev-${esc(m.last_event.severity)}">${esc(m.last_event.severity)}</span> ${esc(m.last_event.summary)}` : '<span class="muted">No changes yet</span>'}</td></tr>`).join('')
        : '<tr><td class="muted">No monitors yet. Use "Monitor security of all domains" above.</td></tr>';

    const max = Math.max(1, ...d.top_findings.map(f => f.domains));
    $('unitRisks').innerHTML = d.top_findings.length
        ? d.top_findings.map(f => `<div class="mgmt-bar-row" title="${esc(f.examples.join(', '))}"><span>${esc(f.title)}</span>`
            + `<div class="mgmt-bar"><span style="width:${100 * f.domains / max}%;background:${UNIT_SEV_COLOR[f.severity]}"></span></div>`
            + `<span class="mgmt-bar-value">${f.domains}</span></div>`).join('')
        : '<p class="muted">No open findings of medium severity or worse.</p>';

    $('unitEvents').innerHTML = d.events.length
        ? d.events.map(e => `<li><span><span class="muted">${esc(unitWhen(e.at))}</span> `
            + `<span class="chip-kind">${e.kind === 'security' ? 'Security' : 'Registration'}</span> ${esc(e.detail)}</span></li>`).join('')
        : '<li class="muted">No changes yet.</li>';
}

async function unitLoad() {
    const id = $('main').dataset.unitId;
    try { unitRender(await requestJson('/api/organisation/' + id)); } catch (err) { toast(err.message); }
}

function initUnit() {
    if (!$('unitKpis')) return;
    const btn = $('unitMonitorBtn');
    if (btn) {
        btn.addEventListener('click', async () => {
            const schedule = $('unitMonitorSchedule');
            if (!confirm(`Create a security monitor, ${schedule.selectedOptions[0].textContent.toLowerCase()}, `
                + 'for every domain of this unit and the units below it that has none? '
                + 'The first scans are spread over that interval.')) return;
            btn.disabled = true;
            try {
                const res = await requestJson('/api/portfolio/monitor', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ group_id: Number($('main').dataset.unitId), schedule_minutes: Number(schedule.value) }),
                });
                toast(`${res.created.length} monitor(s) created, ${res.already_monitored} already monitored.`);
            } catch (err) { toast(err.message); }
            btn.disabled = false;
            unitLoad();
        });
    }
    unitLoad();
}

document.addEventListener('DOMContentLoaded', initUnit);
