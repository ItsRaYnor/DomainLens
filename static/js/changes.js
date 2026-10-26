// Monitoring -> Domain changes: every change of the portfolio's domains, to
// filter on what changed, when, in which unit and by whom. It was a column
// of fifteen sentences at the bottom of the portfolio, with no way to find
// "every registrar change last month" or "who switched threat intel off".
// Uses lookup.js and logview.js.

const CH_KEYS = ['q', 'unit', 'from', 'to'];
const CH_SETS = ['kind', 'source'];
const CH_PAGE = 100;
const CH_KIND_ORDER = ['registrar', 'reseller', 'nameservers', 'phase', 'expiry', 'dns',
    'decision', 'threat_intel', 'contact', 'unit', 'added', 'removed'];
const ch = { state: null, offset: 0, rows: [], kindText: {}, sourceText: {}, drawPeriod: null };

function chSeverity(sev) {
    return sev && sev !== 'info'
        ? `<span class="rec-badge sev-${esc(sev)}">${esc(sev.toUpperCase())}</span> ` : '';
}

function chRow(e) {
    const change = lvChange(e.before, e.after);
    // The sentence when it says more than before and after: "expires in 7
    // days", or an older row whose values could not be read back.
    const sentence = !change || ['expiry', 'dns', 'added', 'removed', 'phase'].includes(e.kind)
        ? `<span class="${change ? 'lv-sub' : ''}">${esc(e.detail || '')}</span>` : '';
    const by = e.source === 'registry'
        ? `<span>${esc(e.source_text)}</span>`
        : `<span>${esc(e.source_text)}</span>${e.actor ? `<span class="lv-sub">${esc(e.actor)}</span>` : ''}`;
    return `<tr>
        <td class="nowrap">${esc(lvWhen(e.at))}</td>
        <td><button type="button" class="lv-toggle" data-filter-q="${esc(e.domain)}" title="Only this domain"><code>${esc(e.domain)}</code></button>
            <a class="lv-sub" href="/monitoring/domains?q=${encodeURIComponent(e.domain)}">In the portfolio</a></td>
        <td>${e.unit ? `<button type="button" class="lv-toggle" data-filter-unit="${esc(String(e.unit_id))}" title="Only this unit">${esc(e.unit)}</button>` : '<span class="muted">—</span>'}</td>
        <td>${chSeverity(e.severity)}<span>${esc(e.kind_text)}</span></td>
        <td>${change}${sentence}</td>
        <td>${by}</td>
    </tr>`;
}

function chFilters() {
    const s = ch.state;
    $('chSearch').value = s.q;
    $('chFrom').value = s.from;
    $('chTo').value = s.to;
    if ($('chUnit').options.length > 1) $('chUnit').value = s.unit;
    if (ch.drawPeriod) ch.drawPeriod();
}

async function chLoad(append) {
    const s = ch.state;
    const qs = lvQuery(s, CH_KEYS, CH_SETS);
    if (!append) {
        ch.offset = 0;
        lvWrite(qs);
        $('chCsv').href = '/api/portfolio/changes.csv' + (qs.toString() ? `?${qs}` : '');
    }
    qs.set('limit', CH_PAGE);
    qs.set('offset', ch.offset);
    let data;
    try {
        data = await requestJson('/api/portfolio/changes?' + qs);
    } catch (err) {
        $('chCount').textContent = err.message;
        return;
    }
    ch.kindText = data.kind_text;
    ch.sourceText = data.source_text;
    ch.rows = append ? ch.rows.concat(data.events) : data.events;
    ch.offset = ch.rows.length;
    const kinds = CH_KIND_ORDER.filter(k => data.kinds[k] || s.kind.has(k))
        .map(k => ({ value: k, label: ch.kindText[k] || k, count: data.kinds[k] }));
    lvChips($('chKinds'), kinds, s.kind, () => chLoad(false));
    lvChips($('chSources'), Object.keys(ch.sourceText).map(k => ({
        value: k, label: ch.sourceText[k], count: data.sources[k] })), s.source, () => chLoad(false));
    chFilters();
    $('chCount').textContent = data.total === 1 ? '1 change' : `${data.total} changes`;
    $('chRows').innerHTML = ch.rows.length ? ch.rows.map(chRow).join('')
        : `<tr><td colspan="6" class="lv-empty">${esc(chEmptyText())}</td></tr>`;
    $('chMore').classList.toggle('hidden', ch.rows.length >= data.total);
}

function chEmptyText() {
    const s = ch.state;
    const filtered = s.q || s.unit || s.from || s.to || s.kind.size || s.source.size;
    return filtered ? 'No change matches these filters.'
        : 'No changes yet. The first lookup of a domain is its baseline, not a change.';
}

function initChanges() {
    if (!$('chRows')) return;
    ch.state = lvRead(CH_KEYS, CH_SETS);
    ch.drawPeriod = lvPeriod($('chPeriod'), ch.state, () => chLoad(false));
    let typing;
    $('chSearch').addEventListener('input', () => {
        clearTimeout(typing);
        typing = setTimeout(() => { ch.state.q = $('chSearch').value.trim(); chLoad(false); }, 250);
    });
    $('chUnit').addEventListener('change', () => { ch.state.unit = $('chUnit').value; chLoad(false); });
    $('chFrom').addEventListener('change', () => { ch.state.from = $('chFrom').value; chLoad(false); });
    $('chTo').addEventListener('change', () => { ch.state.to = $('chTo').value; chLoad(false); });
    $('chMore').addEventListener('click', () => chLoad(true));
    $('chReset').addEventListener('click', () => {
        CH_KEYS.forEach(k => { ch.state[k] = ''; });
        CH_SETS.forEach(k => ch.state[k].clear());
        chLoad(false);
    });
    // A domain or unit in the list filters on it: one click instead of typing.
    $('chRows').addEventListener('click', e => {
        const q = e.target.closest('[data-filter-q]');
        const unit = e.target.closest('[data-filter-unit]');
        if (q) { ch.state.q = q.dataset.filterQ; chLoad(false); }
        if (unit) { ch.state.unit = unit.dataset.filterUnit; chLoad(false); }
    });
    lvUnits($('chUnit'), ch.state.unit);
    chLoad(false);
}

document.addEventListener('DOMContentLoaded', initChanges);
