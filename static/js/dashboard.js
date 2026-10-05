// Reports -> Dashboard. Charts are plain SVG built here: no chart library,
// so nothing extra to load, and the page prints exactly as it shows.
// Uses $, esc, requestJson and toast from lookup.js.

const MG_RATING_COLOR = {
    A: 'var(--grade-a)', B: 'var(--grade-b)', C: 'var(--grade-c)', D: 'var(--grade-d)', F: 'var(--grade-f)',
    'A+': 'var(--grade-a)', 'A-': 'var(--grade-a)',
};
const MG_SEV_COLOR = {
    critical: 'var(--sev-critical-badge)', high: 'var(--sev-high-badge)',
    medium: 'var(--sev-medium-badge)', low: 'var(--text-faint)',
};
const mg = { days: 90, group: '' };

function mgPct(part, whole) { return whole ? Math.round(100 * part / whole) : 0; }

function mgRatingBadge(r) {
    return `<span class="mgmt-rating" style="background:${MG_RATING_COLOR[r]}" title="Rating ${r}">${r}</span>`;
}

function mgDonut(counts, size) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const r = size / 2 - 14, c = 2 * Math.PI * r;
    let offset = 0;
    const arcs = Object.entries(counts).filter(([, n]) => n).map(([k, n]) => {
        const len = c * n / total;
        const arc = `<circle r="${r}" cx="${size / 2}" cy="${size / 2}" fill="none" stroke="${MG_RATING_COLOR[k]}"`
            + ` stroke-width="22" stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-offset}"`
            + ` transform="rotate(-90 ${size / 2} ${size / 2})"><title>${k}: ${n}</title></circle>`;
        offset += len;
        return arc;
    }).join('');
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Ratings">`
        + `<circle r="${r}" cx="${size / 2}" cy="${size / 2}" fill="none" stroke="var(--bg-subtle)" stroke-width="22"/>`
        + arcs
        + `<text x="50%" y="48%" text-anchor="middle" style="font-size:26px;font-weight:700;fill:var(--text)">${total}</text>`
        + `<text x="50%" y="62%" text-anchor="middle">domains</text></svg>`;
}

function mgLine(series, key) {
    const w = 520, h = 190, pad = { l: 40, r: 12, t: 12, b: 26 };
    if (!series.length) return '<p class="muted">No scans in this period.</p>';
    const max = Math.max(1, ...series.map(p => p[key]));
    const x = i => pad.l + (series.length === 1 ? 0 : i * (w - pad.l - pad.r) / (series.length - 1));
    const y = v => pad.t + (h - pad.t - pad.b) * (1 - v / max);
    const pts = series.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
    const area = `${x(0)},${h - pad.b} ${pts} ${x(series.length - 1)},${h - pad.b}`;
    const grid = [0, 0.5, 1].map(f => {
        const v = Math.round(max * f);
        return `<line x1="${pad.l}" x2="${w - pad.r}" y1="${y(v)}" y2="${y(v)}" stroke="var(--border)"/>`
            + `<text x="${pad.l - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
    }).join('');
    const labels = series.map((p, i) => (i === 0 || i === series.length - 1 || i % Math.ceil(series.length / 4) === 0)
        ? `<text x="${x(i)}" y="${h - 6}" text-anchor="middle">${esc(p.at.slice(5))}</text>` : '').join('');
    const dots = series.map((p, i) => `<circle cx="${x(i)}" cy="${y(p[key])}" r="3" fill="var(--accent)">`
        + `<title>${esc(p.at)}: ${p[key]} open findings on ${p.domains} domains</title></circle>`).join('');
    return `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-label="Open findings over time">${grid}`
        + `<polygon points="${area}" fill="var(--accent-glow)"/>`
        + `<polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2"/>${dots}${labels}</svg>`;
}

function mgBarRow(label, segments, value, title) {
    const total = segments.reduce((a, s) => a + s.n, 0);
    const bar = segments.filter(s => s.n).map(s =>
        `<span style="width:${100 * s.n / (total || 1)}%;background:${s.color}" title="${esc(s.label)}: ${s.n}"></span>`).join('');
    return `<div class="mgmt-bar-row"${title ? ` title="${esc(title)}"` : ''}><span>${esc(label)}</span>`
        + `<div class="mgmt-bar">${bar}</div><span class="mgmt-bar-value">${value}</span></div>`;
}

function mgKpis(d) {
    const k = d.kpis;
    const kpi = (value, label, sub, cls) => `<div class="mgmt-kpi ${cls || ''}"><div class="value">${value}</div>`
        + `<div class="label">${esc(label)}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;
    const trend = k.compared
        ? `${k.improved} better, ${k.worsened} worse than ${d.days} days ago` : 'No earlier scan to compare with';
    let html = kpi(k.domains, 'Domains assessed', k.not_rescanned ? `${k.not_rescanned} not scanned again in this period` : '')
        + kpi(k.in_order_pct === null ? '&mdash;' : `${k.in_order_pct}%`, 'In order (rating A or B)',
            `${k.in_order} of ${k.domains}`, k.in_order_pct === null ? '' : k.in_order_pct >= 80 ? 'good' : k.in_order_pct >= 50 ? 'warn' : 'bad')
        + kpi(k.critical, 'Open critical findings', '', k.critical ? 'bad' : 'good')
        + kpi(k.high, 'Open high findings', '', k.high ? 'warn' : 'good')
        + kpi(k.improved - k.worsened >= 0 ? `+${k.improved - k.worsened}` : k.improved - k.worsened,
            'Net change in ratings', trend, k.worsened > k.improved ? 'bad' : k.improved ? 'good' : '')
        + kpi(k.accepted, 'Accepted risks', 'Decided, with an owner and an end date');
    if (d.portfolio) {
        // A registration nobody has looked up yet is not "fine": with every
        // domain unmeasured the tile says so instead of a green zero.
        const t = d.portfolio.total;
        const known = t.total - t.unmeasured;
        const note = t.unmeasured ? `${t.unmeasured} of ${t.total} not looked up yet` : '';
        html += known
            ? kpi(t.attention, 'Registrations at risk', note || 'In quarantine, being deleted or lost',
                t.attention ? 'bad' : t.unmeasured ? '' : 'good')
              + kpi(t.expiring, 'Expiring within 30 days', note, t.expiring ? 'warn' : t.unmeasured ? '' : 'good')
            : kpi('&mdash;', 'Registrations', `${t.total} in the portfolio, none looked up yet`);
    }
    $('mgKpis').innerHTML = html;
}

function mgRender(d) {
    const when = new Date(d.generated_at).toLocaleString([], { dateStyle: 'long', timeStyle: 'short' });
    $('mgScope').textContent = `${d.group ? `${d.group} (and the units below it)` : 'All domains'} · last ${d.days} days · as of ${when}`;
    mgKpis(d);

    $('mgRatingChart').innerHTML = d.kpis.domains ? mgDonut(d.ratings, 190) : '<p class="muted">No domains were scanned in this period.</p>';
    $('mgRatingLegend').innerHTML = Object.entries(d.ratings).map(([r, n]) =>
        `<li><span class="mgmt-swatch" style="background:${MG_RATING_COLOR[r]}"></span>`
        + `<span><strong>${r}</strong> &middot; ${n} (${mgPct(n, d.kpis.domains)}%) <span class="muted">${esc((d.band_text || d.rating_text)[r])}</span></span></li>`).join('');
    // Before the first scan there is nothing to count; a zero there would
    // read as a clean start.
    $('mgTrendChart').innerHTML = mgLine(d.trend.filter(p => p.domains), 'open_findings');

    $('mgControls').innerHTML = d.controls.map(c => mgBarRow(c.label, [
        { n: c.pass, color: 'var(--green)', label: 'In place' },
        { n: c.fail, color: 'var(--red)', label: 'Missing' },
        { n: c.unmeasured, color: 'var(--border-hover)', label: 'Could not be measured' },
    ], c.pass_rate === null ? '&mdash;' : `${c.pass_rate}%`,
    `${c.pass} in place, ${c.fail} missing, ${c.unmeasured} not measured`)).join('')
        + '<p class="muted mgmt-legend-line"><span class="mgmt-swatch" style="background:var(--green)"></span> in place &nbsp; '
        + '<span class="mgmt-swatch" style="background:var(--red)"></span> missing &nbsp; '
        + '<span class="mgmt-swatch" style="background:var(--border-hover)"></span> not measured</p>';

    const maxDomains = Math.max(1, ...d.top_findings.map(f => f.domains));
    $('mgTopFindings').innerHTML = d.top_findings.length
        ? d.top_findings.map(f => mgBarRow(f.title, [
            { n: f.domains, color: MG_SEV_COLOR[f.severity], label: f.severity },
            { n: maxDomains - f.domains, color: 'transparent', label: '' },
        ], f.domains, `${f.severity}: ${f.examples.join(', ')}${f.domains > f.examples.length ? ', …' : ''}`)).join('')
        : '<p class="muted">No open findings of medium severity or worse.</p>';

    const cats = Object.entries(d.by_category);
    $('mgCategories').innerHTML = cats.length
        ? cats.map(([cat, c]) => mgBarRow(cat, ['critical', 'high', 'medium', 'low'].map(s =>
            ({ n: c[s], color: MG_SEV_COLOR[s], label: s })), c.critical + c.high + c.medium + c.low)).join('')
          + '<p class="muted">' + ['critical', 'high', 'medium', 'low'].map(s =>
            `<span class="mgmt-swatch" style="background:${MG_SEV_COLOR[s]}"></span> ${s}`).join(' &nbsp; ') + '</p>'
        : '<p class="muted">No open findings.</p>';

    $('mgAttention').innerHTML = d.attention.length
        ? '<ul class="mgmt-list">' + d.attention.map(a => `<li><span>${mgRatingBadge(a.rating)} `
            + `<a href="/report/${a.scan_id}">${esc(a.domain)}</a></span><span class="muted">`
            + `${a.counts.critical} critical, ${a.counts.high} high</span></li>`).join('') + '</ul>'
        : '<p class="muted">No domain is rated C or worse.</p>';

    const moverList = (items, word) => items.length
        ? '<ul class="mgmt-list">' + items.map(m => `<li><span><a href="/report/${m.scan_id}">${esc(m.domain)}</a></span>`
            + `<span>${mgRatingBadge(m.previous_rating)} &rarr; ${mgRatingBadge(m.rating)}</span></li>`).join('') + '</ul>'
        : `<p class="muted">No domain ${word}.</p>`;
    $('mgMovers').innerHTML = `<h4>Better</h4>${moverList(d.improved, 'improved')}<h4>Worse</h4>${moverList(d.worsened, 'got worse')}`
        + (d.not_rescanned.length ? `<p class="muted">Not scanned in this period, so not included: ${d.not_rescanned.map(esc).join(', ')}</p>` : '');

    const p = d.portfolio;
    $('mgPortfolioCard').classList.toggle('hidden', !p);
    if (p) {
        $('mgPortfolio').innerHTML = (p.groups.length
            ? `<div class="users-table-wrap"><table class="data-table mgmt-table"><tr><th>Unit</th><th>Domains</th>`
              + `<th>At risk</th><th>Expiring ≤ 30 d</th><th>To move</th><th>Not measured</th></tr>`
              + p.groups.map(g => `<tr><td>${esc(g.name)}</td><td>${g.total}</td><td>${g.attention}</td>`
                + `<td>${g.expiring}</td><td>${g.move}</td><td>${g.unmeasured}</td></tr>`).join('') + '</table></div>' : '')
            + (p.attention.length ? '<h4>At risk</h4><ul class="mgmt-list">' + p.attention.map(a =>
                `<li><span>${esc(a.domain)}</span><span class="status-fail">${esc(a.phase_text)}</span></li>`).join('') + '</ul>' : '')
            + (p.expiring.length ? '<h4>Expiring soon</h4><ul class="mgmt-list">' + p.expiring.map(e =>
                `<li><span>${esc(e.domain)}</span><span>${esc(e.expires)} (${e.days_left} d)</span></li>`).join('') + '</ul>' : '')
            + '<p class="muted"><a class="no-print" href="/monitoring/domains">Open the domain portfolio</a></p>';
    }

    $('mgMethod').innerHTML = [
        'Each domain is judged on its latest scan in the period; a domain not scanned in the period is left out and listed under "Change in the period".',
        'Ratings: ' + Object.entries(d.rating_text).map(([r, t]) => `${r} — ${t.toLowerCase()}`).join('; ') + '.',
        'Accepted risks are not counted as open findings: they are decisions with an owner and an end date.',
        'A control that could not be measured (for example because a firewall blocked the check) is shown separately and counts neither as in place nor as missing.',
        '"Better" and "worse" compare each domain with its last scan before the period began.',
    ].map(t => `<li>${esc(t)}</li>`).join('');
}

async function mgLoad() {
    const qs = new URLSearchParams({ days: mg.days });
    if (mg.group) qs.set('unit', mg.group);
    try {
        mgRender(await requestJson('/api/reporting/dashboard?' + qs));
    } catch (err) { toast(err.message); $('mgScope').textContent = err.message; }
}

async function mgLoadGroups() {
    try {
        const data = await requestJson('/api/portfolio');
        $('mgGroup').innerHTML = '<option value="">All domains</option>'
            + data.groups.map(g => `<option value="${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('');
        $('mgGroup').classList.toggle('hidden', !data.groups.length);
    } catch (e) { $('mgGroup').classList.add('hidden'); }
}

function initDashboard() {
    if (!$('mgKpis')) return;
    const params = new URLSearchParams(location.search);
    mg.days = Number(params.get('days')) || 90;
    mg.group = params.get('unit') || params.get('group') || '';
    document.querySelectorAll('#mgRange .range-btn').forEach(btn => {
        btn.classList.toggle('active', Number(btn.dataset.days) === mg.days);
        btn.addEventListener('click', () => {
            mg.days = Number(btn.dataset.days);
            document.querySelectorAll('#mgRange .range-btn').forEach(b => b.classList.toggle('active', b === btn));
            mgSync();
        });
    });
    $('mgGroup').addEventListener('change', () => { mg.group = $('mgGroup').value; mgSync(); });
    $('mgPrint').addEventListener('click', () => window.print());
    mgLoadGroups().then(() => { $('mgGroup').value = mg.group; });
    mgLoad();
}

// The address carries the view, so a link to "Sales, last year" opens it.
function mgSync() {
    const qs = new URLSearchParams({ days: mg.days });
    if (mg.group) qs.set('unit', mg.group);
    history.replaceState(null, '', '?' + qs);
    mgLoad();
}

document.addEventListener('DOMContentLoaded', initDashboard);
