// The old-vs-new view of two saved scans (/api/compare): the history's
// compare, a monitor event's "what changed?" and the events page share it,
// so the three never judge a change differently.

function cvEsc(value) {
    return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function compareValueText(row) {
    const fmt = v => {
        if (v === null || v === undefined) return '—';
        if (typeof v === 'boolean') return v ? 'yes' : 'no';
        if (Array.isArray(v)) return v.length ? v.join(', ') : 'none';
        if (v && typeof v === 'object') {
            return Object.entries(v).filter(([, n]) => n).map(([k, n]) => `${k}:${n}`).join(' ') || 'none';
        }
        return String(v);
    };
    return { old: fmt(row.old), now: fmt(row.new) };
}

// Reusable old-vs-new table used by both the history compare and a monitor
// event's "what changed" panel. `data` is the /api/compare payload.
function renderCompareHtml(data) {
    const rows = (data.diff && data.diff.dimensions) || [];
    const order = { worse: 0, better: 1, changed: 2, unmeasured: 3, unchanged: 4 };
    const shown = rows.slice().sort((p, q) => (order[p.status] ?? 9) - (order[q.status] ?? 9));
    const badge = s => `<span class="cmp-badge cmp-${cvEsc(s)}">${cvEsc(s)}</span>`;
    const head = `
        <div class="cmp-head">
            <a href="${cvEsc(data.a.report_url)}" target="_blank" rel="noopener">A · ${cvEsc(data.a.domain || '')} (${cvEsc(data.a.grade || 'N/A')})</a>
            <span>→</span>
            <a href="${cvEsc(data.b.report_url)}" target="_blank" rel="noopener">B · ${cvEsc(data.b.domain || '')} (${cvEsc(data.b.grade || 'N/A')})</a>
        </div>`;
    const row = r => {
        const v = compareValueText(r);
        return `<tr class="cmp-row cmp-${cvEsc(r.status)}">
            <td>${cvEsc(r.label)}</td>
            <td class="nowrap">${badge(r.status)}</td>
            <td class="mono">${cvEsc(v.old)} → ${cvEsc(v.now)}</td>
        </tr>`;
    };
    // What moved first; the rows that did not move stay folded away. They
    // used to fill the panel, so a change listed nothing but "unchanged".
    const moved = shown.filter(r => ['worse', 'better', 'changed'].includes(r.status));
    const still = shown.filter(r => !['worse', 'better', 'changed'].includes(r.status));
    const findings = data.findings || { new: [], resolved: [] };
    const findingList = (title, list, cls) => list.length
        ? `<h4 class="cmp-subhead">${cvEsc(title)}</h4><ul class="cmp-findings">`
          + list.map(f => `<li><span class="rec-badge sev-${cvEsc(f.severity)}">${cvEsc((f.severity || '').toUpperCase())}</span> `
              + `<span class="${cls}">${cvEsc(f.title)}</span></li>`).join('') + '</ul>'
        : '';
    const shownLabels = new Set(moved.map(r => r.label.toLowerCase()));
    const fields = (data.fields || []).filter(f => !shownLabels.has(String(f.label).toLowerCase()));
    const fieldRows = fields.map(f => `<tr class="cmp-row cmp-${cvEsc(f.direction)}"><td>${cvEsc(f.label)}</td>`
        + `<td class="nowrap">${badge(f.direction)}</td>`
        + `<td class="mono">${cvEsc(f.before === null || f.before === undefined ? 'none' : String(f.before))} → `
        + `${cvEsc(f.after === null || f.after === undefined ? 'none' : String(f.after))}</td></tr>`).join('');
    // The record a monitor watches is compared apart from the fields: a change
    // of it raises an event, and without it here such an event read as
    // "nothing moved".
    const rec = data.record;
    const recordRow = rec
        ? `<tr class="cmp-row cmp-changed"><td>${cvEsc(`${rec.type || 'DNS'} record (watched)`)}</td>`
          + `<td class="nowrap">${badge('changed')}</td>`
          + `<td class="mono">${cvEsc((rec.before || []).join(', ') || rec.rcode_before || 'none')} → `
          + `${cvEsc((rec.after || []).join(', ') || rec.rcode_after || 'none')}</td></tr>`
        : '';
    const nothing = !rec && !moved.length && !fields.length && !findings.new.length && !findings.resolved.length;
    return head
        + (nothing ? '<p class="ct-desc">Nothing that is compared moved between these two scans. An event like this '
            + 'came from the earlier way of detecting changes, which also counted values that differ on every scan; '
            + 'such differences no longer raise an event.</p>' : '')
        + findingList('New findings', findings.new, '')
        + findingList('Resolved findings', findings.resolved, 'muted')
        + (recordRow || moved.length || fieldRows
            ? `<div class="table-scroll"><table class="data-table cmp-table stack-table"><tr><th>What</th><th>Change</th><th>Before → after</th></tr>`
              + recordRow + moved.map(row).join('') + fieldRows + '</table></div>' : '')
        + (still.length
            ? `<details class="cmp-still"><summary>${cvEsc(`Unchanged or not measured (${still.length})`)}</summary>`
              + `<div class="table-scroll"><table class="data-table cmp-table"><tbody>${still.map(row).join('')}</tbody></table></div></details>`
            : '');
}
