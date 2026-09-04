// Reports -> Compare: what changed for one domain between two periods.
(function () {
    function $(id) { return document.getElementById(id); }

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value === null || value === undefined ? '' : String(value);
        return div.innerHTML;
    }

    // Same contract as the other pages: an HTTP status is not a network
    // error, and a server that has not been restarted since a route was
    // added returns a perfectly healthy 404.
    async function requestJson(url) {
        let resp;
        try {
            resp = await fetch(url);
        } catch (e) {
            throw new Error('Could not reach the server. Is DomainLens still running?');
        }
        const body = await resp.text();
        let data = null;
        try {
            data = body ? JSON.parse(body) : null;
        } catch (e) {
            if (resp.status === 404) {
                throw new Error('This endpoint is not available (HTTP 404). If you just '
                    + 'updated DomainLens, restart it: routes are registered at startup.');
            }
            throw new Error(`The server returned HTTP ${resp.status} instead of JSON.`);
        }
        if (!resp.ok && !(data && data.error)) {
            throw new Error(`The server returned HTTP ${resp.status}.`);
        }
        return data;
    }

    let lastResult = null;

    // A value that is absent reads differently from one that is empty, so it
    // is named rather than rendered as a blank cell.
    function showValue(value) {
        if (value === null || value === undefined || value === '') return '<em>none</em>';
        if (value === true) return 'yes';
        if (value === false) return 'no';
        return esc(value);
    }

    function render() {
        const out = $('cmpResult');
        const data = lastResult;
        if (!data) { out.innerHTML = ''; return; }

        if (data.error) {
            out.innerHTML = `<p class="status status-warn">${esc(data.error)}</p>`;
            return;
        }

        const onlyWorse = $('cmpOnlyWorse').checked;
        const section = $('cmpSectionFilter').value;
        const rows = (data.changes || []).filter(c =>
            (!onlyWorse || c.direction === 'worse') && (!section || c.section === section));

        const s = data.summary || {};
        let html = '';
        if (!data.changed) {
            html += '<p class="status status-pass">Nothing tracked changed between these '
                 + 'two scans.</p>';
        } else {
            const verdict = s.worse ? 'status-fail' : s.better ? 'status-pass' : 'status-warn';
            html += `<p class="status ${verdict}">${esc(s.total)} change(s): `
                 + `${esc(s.worse)} worse, ${esc(s.better)} better, `
                 + `${esc(s.neutral)} without a verdict.</p>`;
        }

        // Naming both scans is what makes the comparison checkable: "period A"
        // means nothing without the date it resolved to.
        const a = data.a || {}, b = data.b || {};
        html += `<p class="ct-desc">Comparing the last scan in each period: `
             + `<strong>${esc((a.created_at || '').slice(0, 10))}</strong> `
             + `(scan ${esc(a.scan_id)}) against `
             + `<strong>${esc((b.created_at || '').slice(0, 10))}</strong> `
             + `(scan ${esc(b.scan_id)}).</p>`;

        if (rows.length) {
            html += '<table class="data-table compare-table"><thead><tr>'
                 + '<th>What</th><th>Was</th><th>Now</th><th>Direction</th>'
                 + '</tr></thead><tbody>'
                + rows.map(c => {
                    const cls = c.direction === 'worse' ? 'status-fail'
                              : c.direction === 'better' ? 'status-pass' : 'status-warn';
                    const arrow = c.direction === 'worse' ? 'worse'
                                : c.direction === 'better' ? 'better' : 'changed';
                    return `<tr><td>${esc(c.label)}</td>`
                        + `<td class="mono">${showValue(c.before)}</td>`
                        + `<td class="mono">${showValue(c.after)}</td>`
                        + `<td><span class="status ${cls}">${esc(arrow)}</span></td></tr>`;
                }).join('')
                + '</tbody></table>';
        } else if (data.changed) {
            html += '<p class="ct-desc">No changes match the current filter.</p>';
        }

        // Never folded into "nothing changed": a check that did not run in one
        // of the two scans has no before-and-after to report, and saying it
        // held steady would be a claim nobody measured.
        if ((data.unmeasured || []).length) {
            html += '<p class="status status-warn">Could not be compared</p><ul class="finding-list">'
                + data.unmeasured.map(u =>
                    `<li>${esc(u.label)} &mdash; ${esc(u.reason)}</li>`).join('')
                + '</ul>';
        }
        out.innerHTML = html;
    }

    async function runCompare() {
        const out = $('cmpResult');
        const domain = ($('cmpDomain').value || '').trim().toLowerCase();
        const params = {
            domain,
            a_from: $('cmpAFrom').value, a_to: $('cmpATo').value,
            b_from: $('cmpBFrom').value, b_to: $('cmpBTo').value,
        };
        const missing = Object.entries(params).filter(([, v]) => !v).map(([k]) => k);
        if (missing.length) {
            out.innerHTML = '<p class="status status-warn">Fill in a domain and both '
                          + 'periods first.</p>';
            return;
        }
        out.innerHTML = '<p class="history-empty">Comparing…</p>';
        try {
            lastResult = await requestJson('/api/reporting/compare?'
                + new URLSearchParams(params).toString());
        } catch (e) {
            out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
            return;
        }
        render();
    }

    // One row per scanned domain rather than one per scan, so a domain
    // scanned fifty times appears once. Two sources because they answer
    // slightly different questions: scan_metrics covers what the drill-downs
    // report on, the history covers anything scanned before metrics existed.
    // First and last scan date per domain, so picking one can land the
    // periods where its data actually is.
    let domainSpans = {};

    function applySpan(domain) {
        const span = domainSpans[domain];
        if (!span || !span.first || !span.last || span.first === span.last) return false;
        $('cmpAFrom').value = span.first;
        $('cmpATo').value = span.first;
        $('cmpBFrom').value = span.last;
        $('cmpBTo').value = span.last;
        return true;
    }

    async function fillDomains(preferred) {
        const select = $('cmpDomain');
        const found = new Set();
        try {
            const metrics = await requestJson('/api/reporting/domains?days=365');
            (metrics.domains || []).forEach(d => d.domain && found.add(d.domain));
        } catch (e) { /* fall through to the history below */ }
        try {
            const deltas = await requestJson('/api/reporting/deltas?days=365');
            (deltas.domains || []).forEach(d => {
                found.add(d.domain);
                domainSpans[d.domain] = {
                    first: String(d.first_created_at || '').slice(0, 10),
                    last: String(d.last_created_at || '').slice(0, 10),
                };
            });
        } catch (e) { /* the date boxes keep their defaults */ }
        try {
            const history = await requestJson('/api/history?limit=200');
            (history.scans || []).forEach(s => s.domain && found.add(s.domain));
        } catch (e) { /* whatever the first source gave is still usable */ }

        // A domain arriving in the URL that is not in either list would
        // otherwise silently reset the selection to the placeholder.
        if (preferred) found.add(preferred);

        const domains = [...found].sort();
        if (!domains.length) {
            select.innerHTML = '<option value="">No scanned domains yet</option>';
            select.disabled = true;
            return;
        }
        select.disabled = false;
        select.innerHTML = '<option value="">Choose a domain…</option>'
            + domains.map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
        if (preferred) select.value = preferred;
    }

    function isoDaysAgo(days) {
        const d = new Date();
        d.setDate(d.getDate() - days);
        return d.toISOString().slice(0, 10);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        try {
            await DomainLensI18n.init(DomainLensI18n.pageLocale());
        } catch (e) {
            console.error('i18n init failed; continuing without translations', e);
        }
        if (!$('cmpRunBtn')) return;

        // Something usable on arrival beats four empty date boxes: last month
        // against this one is the comparison people come here to make.
        $('cmpBTo').value = isoDaysAgo(0);
        $('cmpBFrom').value = isoDaysAgo(30);
        $('cmpATo').value = isoDaysAgo(31);
        $('cmpAFrom').value = isoDaysAgo(60);

        // Arriving from the trends drill-down: it has already decided which
        // two scans are interesting, so run the comparison rather than
        // making the reader re-enter what they just clicked.
        const params = new URLSearchParams(location.search);
        const prefilled = ['domain', 'a_from', 'a_to', 'b_from', 'b_to']
            .filter(k => params.get(k));
        const ids = { a_from: 'cmpAFrom', a_to: 'cmpATo',
                      b_from: 'cmpBFrom', b_to: 'cmpBTo' };
        prefilled.filter(k => ids[k]).forEach(k => { $(ids[k]).value = params.get(k); });

        try {
            const fields = await requestJson('/api/reporting/compare/fields');
            const sections = [...new Set((fields.fields || []).map(f => f.section))].sort();
            $('cmpSectionFilter').innerHTML = '<option value="">All areas</option>'
                + sections.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
        } catch (e) { /* the filter is a convenience; the page works without it */ }

        await fillDomains(params.get('domain'));

        $('cmpRunBtn').addEventListener('click', runCompare);
        if (prefilled.length === 5) runCompare();
        $('cmpDomain').addEventListener('change', () => {
            const domain = $('cmpDomain').value;
            if (!domain) return;
            // Default periods that sit where no scan happened produce "nothing
            // to compare" for a domain that has plenty -- correct, and useless.
            // Bracketing its own first and last scan always has something in it.
            if (!applySpan(domain)) {
                $('cmpResult').innerHTML = '<p class="status status-warn">'
                    + esc(domain) + ' has only one scan, so there is nothing to '
                    + 'compare yet. Scan it again and come back.</p>';
                return;
            }
            runCompare();
        });
        // Filters re-render what is already loaded rather than re-querying:
        // the comparison has not changed, only which rows are shown.
        $('cmpOnlyWorse').addEventListener('change', render);
        $('cmpSectionFilter').addEventListener('change', render);
    });
})();
