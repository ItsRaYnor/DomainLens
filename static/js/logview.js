// Shared by the two lists of what happened -- Monitoring -> Monitor events and
// Monitoring -> Domain changes: filters that live in the address (so a
// filtered list can be bookmarked and sent), chips that toggle and say how
// many each would show, a period, and loading more. Uses $ and esc from
// lookup.js.

const LV_PERIODS = [
    { days: 7, label: '7 days' }, { days: 30, label: '30 days' }, { days: 90, label: '90 days' },
    { days: 365, label: '1 year' }, { days: 0, label: 'All' },
];

function lvDaysAgo(n) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - n);
    return d.toISOString().slice(0, 10);
}

// Local time, the way the rest of the app shows a moment.
function lvWhen(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? String(iso)
        : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

// State <-> address. Sets are written as comma lists; empty values are left out.
function lvRead(keys, sets) {
    const params = new URLSearchParams(location.search);
    const state = {};
    keys.forEach(k => { state[k] = params.get(k) || ''; });
    sets.forEach(k => {
        state[k] = new Set((params.get(k) || '').split(',').map(v => v.trim()).filter(Boolean));
        state[k + 'Given'] = params.has(k);
    });
    return state;
}

function lvQuery(state, keys, sets) {
    const qs = new URLSearchParams();
    keys.forEach(k => { if (state[k]) qs.set(k, state[k]); });
    sets.forEach(k => { if (state[k] && state[k].size) qs.set(k, [...state[k]].join(',')); });
    return qs;
}

function lvWrite(qs) {
    const text = qs.toString();
    history.replaceState(null, '', text ? `?${text}` : location.pathname);
}

// Chips: one button per value, pressed when chosen. None chosen means all.
// Each says how many it would show with the other filters as they are.
function lvChips(el, items, selected, onChange) {
    el.innerHTML = items.map(item => {
        const on = selected.has(item.value);
        const n = item.count ?? 0;
        return `<button type="button" class="lv-chip${n || on ? '' : ' is-empty'}${item.cls ? ' ' + item.cls : ''}"`
            + ` data-value="${esc(item.value)}" aria-pressed="${on}"><span>${esc(item.label)}</span>`
            + ` <span class="lv-n">${esc(String(n))}</span></button>`;
    }).join('');
    el.onclick = e => {
        const btn = e.target.closest('.lv-chip');
        if (!btn) return;
        const value = btn.dataset.value;
        if (selected.has(value)) selected.delete(value); else selected.add(value);
        onChange();
    };
}

// Period buttons fill in the dates; the date fields stay for any other range.
function lvPeriod(el, state, onChange) {
    const active = () => LV_PERIODS.find(p => (p.days ? state.from === lvDaysAgo(p.days) && !state.to
        : !state.from && !state.to));
    const draw = () => {
        const current = active();
        el.innerHTML = LV_PERIODS.map(p => `<button type="button" data-days="${p.days}"`
            + ` class="${current === p ? 'active' : ''}">${esc(p.label)}</button>`).join('');
    };
    el.onclick = e => {
        const btn = e.target.closest('button[data-days]');
        if (!btn) return;
        const days = Number(btn.dataset.days);
        state.from = days ? lvDaysAgo(days) : '';
        state.to = '';
        onChange();
    };
    draw();
    return draw;
}

// Before -> after, each its own element so the page's translation finds it.
function lvChange(before, after) {
    if (before == null && after == null) return '';
    const b = before == null || before === '' ? '<span class="muted">none</span>' : `<span class="lv-before">${esc(before)}</span>`;
    const a = after == null || after === '' ? '<span class="muted">none</span>' : `<span class="lv-after">${esc(after)}</span>`;
    return `<span class="lv-change">${b}<span class="lv-arrow">→</span>${a}</span>`;
}

async function lvUnits(select, chosen) {
    try {
        const data = await requestJson('/api/portfolio');
        select.innerHTML = '<option value="">All units</option>'
            + data.groups.map(g => `<option value="${g.id}" title="${esc(g.path)}">${esc(g.path)}</option>`).join('');
        select.value = chosen || '';
        select.classList.toggle('hidden', !data.groups.length);
    } catch (e) { select.classList.add('hidden'); }
}
