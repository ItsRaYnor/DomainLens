let currentDays = 30;

function $(id) { return document.getElementById(id); }

// Same contract as the helper in app.js: bind only when the node is there,
// so a template change cannot silently kill the bindings that follow it.
function on(id, event, handler) {
    const el = $(id);
    if (el) el.addEventListener(event, handler);
    return el;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function maxOf(values, fallback = 1) {
    const nums = values.filter(v => typeof v === 'number' && !Number.isNaN(v));
    return Math.max(fallback, ...(nums.length ? nums : [fallback]));
}

// Chart geometry. Left padding is wider than the rest to leave room for the
// y-axis labels; bottom padding leaves room for the date labels.
const CHART = { width: 560, height: 200, padL: 42, padR: 12, padT: 14, padB: 26 };

function plotArea() {
    return {
        x0: CHART.padL,
        x1: CHART.width - CHART.padR,
        y0: CHART.padT,
        y1: CHART.height - CHART.padB,
        w: CHART.width - CHART.padL - CHART.padR,
        h: CHART.height - CHART.padT - CHART.padB,
    };
}

function shortDay(day) {
    // "2026-08-12" -> "12/8"
    const parts = String(day || '').split('-');
    if (parts.length !== 3) return String(day || '');
    return `${Number(parts[2])}/${Number(parts[1])}`;
}

function axisLayer(points, max, valueFmt) {
    const a = plotArea();
    const ticks = [0, 0.5, 1];
    let svg = '';
    ticks.forEach(frac => {
        const y = a.y1 - frac * a.h;
        const label = valueFmt(max * frac);
        svg += `<line x1="${a.x0}" y1="${y}" x2="${a.x1}" y2="${y}" stroke="currentColor" stroke-opacity="0.12" stroke-width="1"></line>`;
        svg += `<text x="${a.x0 - 6}" y="${y + 3.5}" text-anchor="end" font-size="9" fill="currentColor" fill-opacity="0.55">${escapeHtml(label)}</text>`;
    });
    // Date labels: first, middle and last only — more would overlap.
    if (points.length) {
        const idxs = points.length > 2 ? [0, Math.floor(points.length / 2), points.length - 1] : [0, points.length - 1];
        const stepX = points.length > 1 ? a.w / (points.length - 1) : 0;
        [...new Set(idxs)].forEach(i => {
            const x = a.x0 + i * stepX;
            const anchor = i === 0 ? 'start' : (i === points.length - 1 ? 'end' : 'middle');
            svg += `<text x="${x}" y="${CHART.height - 8}" text-anchor="${anchor}" font-size="9" fill="currentColor" fill-opacity="0.55">${escapeHtml(shortDay(points[i].day))}</text>`;
        });
    }
    return svg;
}

// One transparent full-height rect per data point carrying a <title>, so the
// browser shows a native tooltip with the exact values for that day. Charts
// used to be unlabelled shapes with no way to read a number off them, which
// made them useless as report evidence.
function hoverLayer(points, tooltipFor) {
    const a = plotArea();
    const slot = points.length ? a.w / points.length : a.w;
    return points.map((p, i) => {
        const x = a.x0 + i * slot;
        // data-day makes a point clickable: the chart click handler opens the
        // scans drill-down for that day, where each scan links to its report.
        return `<rect class="chart-point" data-day="${escapeHtml(String(p.day || ''))}" x="${x}" y="${a.y0}" width="${slot}" height="${a.h}" fill="transparent"><title>${escapeHtml(tooltipFor(p))}</title></rect>`;
    }).join('');
}

function emptyState(el, msg) {
    el.innerHTML = `<div class="chart-empty">${escapeHtml(msg)}</div>`;
}

function svgWrap(inner) {
    return `<svg viewBox="0 0 ${CHART.width} ${CHART.height}" preserveAspectRatio="xMidYMid meet" role="img">${inner}</svg>`;
}

/**
 * Multi-series line chart.
 * series: [{ key, color, label }]
 */
function lineChart(el, points, series, opts = {}) {
    const fmt = opts.format || (v => String(Math.round(v * 10) / 10));
    const allValues = [];
    series.forEach(s => points.forEach(p => {
        const v = p[s.key];
        if (v != null && !Number.isNaN(Number(v))) allValues.push(Number(v));
    }));
    if (!allValues.length) {
        emptyState(el, opts.emptyMsg || 'No data in this range yet');
        return;
    }
    const a = plotArea();
    const max = opts.max || maxOf(allValues, 1);
    const stepX = points.length > 1 ? a.w / (points.length - 1) : 0;

    let body = axisLayer(points, max, fmt);

    series.forEach((s, si) => {
        const coords = [];
        points.forEach((p, i) => {
            const raw = p[s.key];
            if (raw == null || Number.isNaN(Number(raw))) return;
            const x = a.x0 + i * stepX;
            const y = a.y1 - (Number(raw) / max) * a.h;
            coords.push({ x, y });
        });
        if (!coords.length) return;
        const pts = coords.map(c => `${c.x},${c.y}`).join(' ');
        // Only the first series gets a filled area, so overlapping fills
        // don't muddy a two-line comparison chart.
        if (si === 0 && series.length === 1) {
            const gid = `g-${opts.id || s.key}`;
            body += `<defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="${s.color}" stop-opacity="0.32"/>
                <stop offset="100%" stop-color="${s.color}" stop-opacity="0"/>
            </linearGradient></defs>`;
            body += `<polygon fill="url(#${gid})" points="${coords[0].x},${a.y1} ${pts} ${coords[coords.length - 1].x},${a.y1}"></polygon>`;
        }
        body += `<polyline fill="none" stroke="${s.color}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round" points="${pts}"></polyline>`;
        // Dots make single-point and sparse series visible at all.
        if (coords.length <= 45) {
            body += coords.map(c => `<circle cx="${c.x}" cy="${c.y}" r="2.2" fill="${s.color}"></circle>`).join('');
        }
    });

    body += hoverLayer(points, p => {
        const vals = series.map(s => {
            const v = p[s.key];
            return `${s.label}: ${v == null ? 'no data' : fmt(Number(v))}`;
        }).join('\n');
        return `${p.day}\n${vals}`;
    });

    const legend = series.length > 1
        ? `<div class="chart-legend">${series.map(s =>
            `<span><i style="background:${s.color}"></i>${escapeHtml(s.label)}</span>`).join('')}</div>`
        : '';
    el.innerHTML = svgWrap(body) + legend;
}

function barChart(el, points, color, yKey, opts = {}) {
    const fmt = opts.format || (v => String(Math.round(v)));
    const values = points.map(p => Number(p[yKey] || 0));
    if (!values.some(v => v > 0)) {
        emptyState(el, opts.emptyMsg || 'No data in this range yet');
        return;
    }
    const a = plotArea();
    const max = maxOf(values, 1);
    const slot = a.w / Math.max(points.length, 1);
    const barW = Math.max(1.5, slot - 2);

    let body = axisLayer(points, max, fmt);
    body += points.map((p, i) => {
        const v = values[i];
        if (!v) return '';
        const h = (v / max) * a.h;
        const x = a.x0 + i * slot;
        return `<rect x="${x}" y="${a.y1 - h}" width="${barW}" height="${h}" rx="2" fill="${color}" opacity="0.85"></rect>`;
    }).join('');
    body += hoverLayer(points, p => `${p.day}\n${opts.label || yKey}: ${fmt(Number(p[yKey] || 0))}`);
    el.innerHTML = svgWrap(body);
}

function stackedEventsChart(el, series, events) {
    const keys = ['critical', 'high', 'medium', 'low', 'info'];
    const colors = {
        critical: '#b91c1c',
        high: '#f87171',
        medium: '#fbbf24',
        low: '#fde68a',
        info: '#5b8def',
    };
    const totals = series.map(p => {
        const day = events[p.day] || {};
        return keys.reduce((sum, k) => sum + (day[k] || 0), 0);
    });
    if (!totals.some(v => v > 0)) {
        emptyState(el, 'No monitor events in this range');
        return;
    }
    const a = plotArea();
    const max = maxOf(totals, 1);
    const slot = a.w / Math.max(series.length, 1);
    const barW = Math.max(1.5, slot - 2);

    let body = axisLayer(series, max, v => String(Math.round(v)));
    series.forEach((p, i) => {
        const day = events[p.day] || {};
        let y = a.y1;
        const x = a.x0 + i * slot;
        keys.forEach(k => {
            const v = day[k] || 0;
            if (!v) return;
            const h = (v / max) * a.h;
            y -= h;
            body += `<rect x="${x}" y="${y}" width="${barW}" height="${h}" fill="${colors[k]}"></rect>`;
        });
    });
    body += hoverLayer(series, p => {
        const day = events[p.day] || {};
        const parts = keys.filter(k => day[k]).map(k => `${k}: ${day[k]}`);
        return `${p.day}\n${parts.length ? parts.join('\n') : 'no events'}`;
    });

    const legend = `<div class="chart-legend">${keys.map(k =>
        `<span><i style="background:${colors[k]}"></i>${k}</span>`).join('')}</div>`;
    el.innerHTML = svgWrap(body) + legend;
}

function renderKpis(overview) {
    const items = [
        { label: 'Scans', value: overview.scans, drill: 'scans',
          hint: 'Scans recorded in this period' },
        { label: 'Domains', value: overview.domains, drill: 'domains',
          hint: 'Distinct domains scanned' },
        { label: 'Avg issues', value: overview.avg_issues, drill: 'issues',
          hint: 'Average over the latest scan of each domain' },
        { label: 'TLS score', value: overview.avg_grade_score, drill: 'tls',
          hint: 'Average over the latest scan of each domain' },
        { label: 'Header score', value: overview.avg_header_score, drill: 'headers',
          hint: 'Average over the latest scan of each domain' },
        { label: 'Blacklist hits', value: overview.blacklist_hits, drill: 'blacklist',
          hint: 'Domains currently on a DNS blocklist' },
        { label: 'SN incidents', value: overview.servicenow_incidents,
          hint: 'Monitor events linked to a ServiceNow incident' },
    ];
    $('kpiGrid').innerHTML = items.map(item => {
        const clickable = item.drill ? ' kpi-clickable' : '';
        const attrs = item.drill
            ? ` role="button" tabindex="0" data-drill="${escapeHtml(item.drill)}"` : '';
        return `
        <div class="kpi${clickable}"${attrs} title="${escapeHtml(item.hint)}">
            <div class="label">${escapeHtml(item.label)}</div>
            <div class="value">${escapeHtml(String(item.value ?? 0))}</div>
        </div>`;
    }).join('');
}

// ===== Drill-downs =====

const DRILL = {
    scans: {
        title: 'Scans in this period',
        note: 'Every scan recorded in the selected period, newest first. Removing a scan also removes it from the figures above.',
    },
    domains: {
        title: 'Domains',
        note: 'The most recent scan of each domain — this is what the averages above are based on.',
    },
    issues: {
        title: 'Issues: what moved in this period',
        note: 'First scan against last, per domain, biggest deterioration first. A count '
            + 'on its own cannot tell a domain that sat at 20 issues all month from one '
            + 'that went from 2 to 20. A domain scanned once has no change to report.',
    },
    tls: { title: 'Domains by TLS score', note: 'Latest scan per domain, lowest TLS score first.' },
    headers: { title: 'Domains by header score', note: 'Latest scan per domain, lowest header score first.' },
    blacklist: {
        title: 'Blacklisted domains',
        note: 'A blacklist (DNSBL) hit means the domain or its IP appears on a spam/abuse blocklist, '
            + 'which can cause outgoing mail to be rejected. Shown from the latest scan of each domain, '
            + 'so a domain that has since been rescanned clean no longer appears here.',
    },
};

let currentDrill = null;
let currentDrillDay = null;

function drillQuery() {
    const domain = $('domainFilter').value.trim().toLowerCase();
    const qs = new URLSearchParams({ days: String(currentDays) });
    if (domain) qs.set('domain', domain);
    return qs;
}

function fmtDate(value) {
    const s = String(value || '');
    return s.length >= 16 ? s.slice(0, 16).replace('T', ' ') : s;
}

function gradeCell(grade, score) {
    if (grade == null && score == null) return '<span class="muted">-</span>';
    const g = grade ? escapeHtml(String(grade)) : '?';
    return `${g}${score != null ? ' (' + escapeHtml(String(score)) + ')' : ''}`;
}

async function renderScansDrill(body, day) {
    const resp = await fetch('/api/history?limit=200&' + drillQuery().toString());
    const data = await resp.json();
    let scans = data.scans || [];
    if (day) {
        // Clicked a chart point: narrow to that day so the graph and the list
        // line up. Day is a local calendar date derived from created_at.
        scans = scans.filter(s => localDay(s.created_at) === day);
    }
    if (!scans.length) {
        body.innerHTML = `<div class="chart-empty">No scans ${day ? 'on ' + escapeHtml(day) : 'in this period'}</div>`;
        return;
    }
    body.innerHTML = `${day ? `<p class="drill-note">Scans on ${escapeHtml(day)}</p>` : ''}<div class="table-scroll"><table class="data-table drill-table">
        <thead><tr><th>When</th><th>Domain</th><th>Grade</th><th>Issues</th><th></th></tr></thead>
        <tbody>${scans.map(s => `
            <tr data-scan-id="${escapeHtml(String(s.id))}">
                <td>${escapeHtml(fmtDate(s.created_at))}</td>
                <td><a href="/report/${escapeHtml(String(s.id))}">${escapeHtml(s.domain)}</a></td>
                <td>${gradeCell(s.grade, s.score)}</td>
                <td>${escapeHtml(String(s.issues_count ?? 0))}</td>
                <td><button type="button" class="btn-ghost scan-delete" data-scan-id="${escapeHtml(String(s.id))}">Delete</button></td>
            </tr>`).join('')}
        </tbody></table></div>`;
}

// A rising issues line answers "how many" but not "where", and a domain
// sitting at 20 issues all month looks identical to one that went from 2 to
// 20. This drill-down shows the move, and links through to the field-level
// comparison that names what actually changed.
function deltaCell(row) {
    if (row.single_scan || row.delta === null || row.delta === undefined) {
        // Not zero: one scan means the change was never observed, and "0"
        // would read as "we looked and it held steady".
        return '<span class="muted" title="Only one scan in this period, so there is '
             + 'nothing to compare it against">not measured</span>';
    }
    if (row.delta > 0) return `<span class="status status-fail">+${escapeHtml(String(row.delta))}</span>`;
    if (row.delta < 0) return `<span class="status status-pass">${escapeHtml(String(row.delta))}</span>`;
    return '<span class="muted">0</span>';
}

function compareLink(row) {
    if (row.single_scan) return '<span class="muted">—</span>';
    const day = v => String(v || '').slice(0, 10);
    // Each period is a single day wide -- the day each scan actually ran --
    // so the comparison lands on exactly the two scans shown in this row.
    const qs = new URLSearchParams({
        domain: row.domain,
        a_from: day(row.first_created_at), a_to: day(row.first_created_at),
        b_from: day(row.last_created_at), b_to: day(row.last_created_at),
    });
    return `<a href="/reports/compare?${qs.toString()}">what changed</a>`;
}

async function renderDeltaDrill(body) {
    const resp = await fetch('/api/reporting/deltas?' + drillQuery().toString());
    const data = await resp.json();
    const rows = data.domains || [];
    if (!rows.length) {
        body.innerHTML = '<div class="chart-empty">No domain metrics in this period</div>';
        return;
    }
    const moved = rows.filter(r => r.delta !== null && r.delta !== 0).length;
    const unmeasured = rows.filter(r => r.single_scan).length;
    let note = `${moved} domain(s) moved.`;
    if (unmeasured) {
        note += ` ${unmeasured} scanned only once in this period, so their change `
             +  'could not be measured.';
    }
    body.innerHTML = `<p class="ct-desc">${escapeHtml(note)}</p>
        <div class="table-scroll"><table class="data-table drill-table">
        <thead><tr><th>Domain</th><th>Issues at start</th><th>Issues now</th><th>Change</th>
        <th>Grade</th><th>Scans</th><th></th></tr></thead>
        <tbody>${rows.map(r => `
            <tr>
                <td><a href="/report/${escapeHtml(String(r.last_scan_id))}">${escapeHtml(r.domain)}</a></td>
                <td>${r.single_scan ? '<span class="muted">—</span>' : escapeHtml(String(r.first_issues ?? 0))}</td>
                <td>${escapeHtml(String(r.last_issues ?? 0))}</td>
                <td>${deltaCell(r)}</td>
                <td>${escapeHtml(String(r.first_grade || '?'))} &rarr; ${escapeHtml(String(r.last_grade || '?'))}</td>
                <td>${escapeHtml(String(r.scans ?? 0))}</td>
                <td>${compareLink(r)}</td>
            </tr>`).join('')}
        </tbody></table></div>`;
}

async function renderDomainsDrill(body, kind) {
    const resp = await fetch('/api/reporting/domains?' + drillQuery().toString());
    const data = await resp.json();
    let rows = data.domains || [];
    if (kind === 'blacklist') rows = rows.filter(r => r.blacklist_listed);
    if (kind === 'tls') rows = rows.slice().sort((a, b) => (a.grade_score ?? 999) - (b.grade_score ?? 999));
    if (kind === 'headers') rows = rows.slice().sort((a, b) => (a.header_score ?? 999) - (b.header_score ?? 999));

    if (!rows.length) {
        body.innerHTML = `<div class="chart-empty">${kind === 'blacklist'
            ? 'No domain is currently on a blocklist' : 'No domain metrics in this period'}</div>`;
        return;
    }
    body.innerHTML = `<div class="table-scroll"><table class="data-table drill-table">
        <thead><tr><th>Domain</th><th>Last scan</th><th>Issues</th><th>TLS</th><th>Headers</th><th>Blacklist</th><th>Scans</th></tr></thead>
        <tbody>${rows.map(r => `
            <tr>
                <td><a href="/report/${escapeHtml(String(r.scan_id))}">${escapeHtml(r.domain)}</a></td>
                <td>${escapeHtml(fmtDate(r.created_at))}</td>
                <td>${escapeHtml(String(r.issues_count ?? 0))}</td>
                <td>${gradeCell(r.grade, r.grade_score)}</td>
                <td>${r.header_score != null ? escapeHtml(String(r.header_score)) : '<span class="muted">-</span>'}</td>
                <td>${r.blacklist_listed
                    ? '<span class="status status-fail">listed</span>'
                    : '<span class="status status-pass">clean</span>'}</td>
                <td>${escapeHtml(String(r.scans ?? 0))}</td>
            </tr>`).join('')}
        </tbody></table></div>`;
}

// The chart series keys each day as created_at[:10] (UTC date prefix), so the
// client must derive a point's day the same way to line a click up with a row.
function localDay(createdAt) { return String(createdAt || '').slice(0, 10); }

async function openDrill(kind, day) {
    const meta = DRILL[kind];
    if (!meta) return;
    currentDrill = kind;
    currentDrillDay = kind === 'scans' ? (day || null) : null;
    const panel = $('drilldown');
    const body = $('drilldownBody');
    panel.classList.remove('hidden');
    $('drilldownTitle').textContent = meta.title;
    $('drilldownNote').textContent = meta.note;
    body.innerHTML = '<div class="chart-empty">Loading…</div>';
    try {
        if (kind === 'scans') await renderScansDrill(body, currentDrillDay);
        else if (kind === 'issues') await renderDeltaDrill(body);
        else await renderDomainsDrill(body, kind);
    } catch (err) {
        body.innerHTML = `<p class="status status-warn">${escapeHtml(err.message || 'Could not load')}</p>`;
    }
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeDrill() {
    currentDrill = null;
    currentDrillDay = null;
    $('drilldown').classList.add('hidden');
}

async function deleteScan(scanId) {
    if (!confirm('Delete this scan? It will also disappear from the figures above.')) return;
    const resp = await fetch('/api/history/' + encodeURIComponent(scanId), { method: 'DELETE' });
    if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        alert(data.error || 'Could not delete the scan');
        return;
    }
    // The KPIs are derived from these rows, so refresh both.
    await loadTrends();
    if (currentDrill) await openDrill(currentDrill, currentDrillDay);
}

function renderTopDomains(rows) {
    if (!rows.length) {
        $('topDomains').innerHTML = '<div class="chart-empty">No domain metrics yet</div>';
        return;
    }
    $('topDomains').innerHTML = rows.map(row => `
        <div class="domain-row">
            <strong>${escapeHtml(row.domain)}</strong>
            <span class="muted">${escapeHtml(String(row.scans))} scans</span>
            <span>${escapeHtml(Number(row.avg_issues || 0).toFixed(1))} avg issues</span>
        </div>
    `).join('');
}

// Make the report's scope unambiguous: a filtered dashboard used to look
// identical to an unfiltered one apart from the text in the filter box.
function renderScope(domain, days, overview) {
    const el = $('scopeLabel');
    if (!el) return;
    const scope = domain ? `Domain: ${domain}` : 'All domains';
    const scanned = Number(overview.scans || 0);
    // The timestamp is what proves a refresh actually happened when the
    // figures themselves have not moved.
    const at = new Date().toLocaleTimeString();
    el.textContent = `${scope} · last ${days} days · ${scanned} scan${scanned === 1 ? '' : 's'} · updated ${at}`;
    el.classList.toggle('scoped', !!domain);
}

async function loadTrends() {
    const domain = $('domainFilter').value.trim().toLowerCase();
    const qs = new URLSearchParams({ days: String(currentDays) });
    if (domain) qs.set('domain', domain);
    const [overviewResp, trendsResp, snResp] = await Promise.all([
        fetch('/api/reporting/overview?' + qs.toString()),
        fetch('/api/reporting/trends?' + qs.toString()),
        fetch('/api/integrations/servicenow'),
    ]);
    const overview = await overviewResp.json();
    const trends = await trendsResp.json();
    const sn = await snResp.json();

    if (!overviewResp.ok || !trendsResp.ok) {
        const msg = overview.error || trends.error || 'Failed to load reporting data';
        ['issuesChart', 'scoreChart', 'volumeChart', 'eventsChart'].forEach(id => emptyState($(id), msg));
        return;
    }

    renderKpis(overview);
    renderScope(domain, currentDays, overview);
    renderTopDomains(overview.top_domains || []);

    const series = trends.series || [];
    lineChart($('issuesChart'), series,
        [{ key: 'avg_issues', color: '#f87171', label: 'Avg issues' }],
        { id: 'issues', emptyMsg: 'No scans in this range yet' });
    // Both scores share a 0-100 scale, so they belong on one axis — the card
    // is titled "TLS / header scores" but only ever plotted the TLS one.
    lineChart($('scoreChart'), series, [
        { key: 'avg_grade_score', color: '#34d399', label: 'TLS score' },
        { key: 'avg_header_score', color: '#5b8def', label: 'Header score' },
    ], { id: 'scores', max: 100, emptyMsg: 'No scored scans in this range yet' });
    barChart($('volumeChart'), series, '#5b8def', 'scans', { label: 'Scans' });
    stackedEventsChart($('eventsChart'), series, trends.events || {});

    $('snStatus').textContent = sn.enabled
        ? `ServiceNow connected · notify >= ${sn.min_severity}`
        : (sn.configured ? 'ServiceNow configured but disabled' : 'ServiceNow not configured');
}

// Reload the open drill-down whenever the period or domain filter changes,
// so it can never show a different slice than the tiles above it.
async function reload() {
    // Without feedback a refresh that returns identical numbers is
    // indistinguishable from a button that does nothing.
    const btn = $('refreshBtn');
    const original = btn ? btn.textContent : null;
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Refreshing…';
    }
    try {
        await loadTrends();
        if (currentDrill) await openDrill(currentDrill, currentDrillDay);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = original;
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.range-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentDays = Number(btn.dataset.days);
            reload();
        });
    });
    // Guarded, like the lookups below: one missing node used to throw here
    // and take every later binding -- the drill-downs, the close button --
    // and the loadTrends() call at the end of this listener down with it,
    // leaving a page that looked empty rather than broken.
    on('refreshBtn', 'click', reload);
    on('domainFilter', 'keydown', e => {
        if (e.key === 'Enter') reload();
    });
    const clear = $('clearFilterBtn');
    if (clear) {
        clear.addEventListener('click', () => {
            $('domainFilter').value = '';
            reload();
        });
    }

    on('kpiGrid', 'click', e => {
        const tile = e.target.closest('[data-drill]');
        if (tile) openDrill(tile.getAttribute('data-drill'));
    });
    on('kpiGrid', 'keydown', e => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const tile = e.target.closest('[data-drill]');
        if (tile) { e.preventDefault(); openDrill(tile.getAttribute('data-drill')); }
    });

    // Clicking a chart point opens the scans for that day, each linking to its
    // report — so a spike in the graph leads straight to the scans behind it.
    ['issuesChart', 'scoreChart', 'volumeChart', 'eventsChart'].forEach(id => {
        const el = $(id);
        if (!el) return;
        el.addEventListener('click', e => {
            const pt = e.target.closest('.chart-point');
            const day = pt && pt.getAttribute('data-day');
            if (day) openDrill('scans', day);
        });
    });

    on('drilldownClose', 'click', closeDrill);
    on('drilldownBody', 'click', e => {
        const btn = e.target.closest('.scan-delete');
        if (btn) deleteScan(btn.getAttribute('data-scan-id'));
    });

    loadTrends();
});
