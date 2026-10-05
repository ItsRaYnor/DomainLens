/* Registration data, shared by the scan's WHOIS tab and Tools -> WHOIS.
 *
 * RDAP first: it is the same structured record for every registry. The
 * port-43 text parse follows as a fallback and for the fields only it has.
 * A withheld holder or contact is said to be withheld -- with the registry's
 * own lookup to check -- never left blank, which would read as "none".
 */
(function (global) {
    'use strict';

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function row(label, html) {
        return html ? `<tr><th>${esc(label)}</th><td>${html}</td></tr>` : '';
    }

    function party(p, lookup) {
        if (!p) return '';
        if (p.withheld) {
            // Not public over RDAP. SIDN does show contacts on its own site,
            // behind bot protection this tool does not get around.
            const where = lookup
                ? ` &mdash; <a href="${esc(lookup.url)}" target="_blank" rel="noopener noreferrer">see ${esc(lookup.name)}</a>`
                : '';
            return `<span class="muted">Not published over RDAP</span>${where}`;
        }
        const lines = [esc(p.name)];
        if (p.address) lines.push(`<span class="muted">${esc(p.address)}</span>`);
        if (p.email) lines.push(esc(p.email));
        if (p.abuse_email) lines.push(`<span class="muted">Abuse: ${esc(p.abuse_email)}</span>`);
        return lines.join('<br>');
    }

    function when(iso) {
        const d = new Date(iso);
        return isNaN(d) ? iso : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
    }

    // Quarantine and deletion first: for someone after the domain, that is
    // the line that matters.
    function lifecycleBlock(r) {
        const lc = r.lifecycle || {};
        if (!lc.phase || lc.phase === 'registered') return '';
        let html = `<p class="status status-warn">${esc(lc.text || '')}</p>`;
        if (lc.released_from) {
            const from = new Date(lc.released_from);
            const until = new Date(from.getTime() + (lc.release_window_minutes || 0) * 60000);
            html += `<p class="ct-desc">Released for registration between <strong>${esc(when(lc.released_from))}</strong>`
                + (lc.release_window_minutes ? ` and <strong>${esc(until.toLocaleTimeString([], { timeStyle: 'short' }))}</strong> (your time), at a random moment` : '')
                + (lc.since ? `; deleted on ${esc(lc.since)}` : '') + '.</p>';
        }
        return html;
    }

    function rdapTable(r) {
        const lookup = r.registry_lookup;
        const abuse = r.registrar && r.registrar.abuse_email
            ? esc(r.registrar.abuse_email)
            : '<span class="muted">Not published by the registry; see the registrar\'s website</span>';
        const dnssec = r.dnssec === true ? 'Yes' : r.dnssec === false ? 'No' : '';
        const rows = [
            row('Domain', esc(r.domain)),
            row('Status', (r.status_text || r.status || []).map(esc).join('<br>')),
            row('Holder', party(r.registrant, lookup)),
            row('Administrative contact', party(r.administrative, lookup)),
            row('Registrar', party(r.registrar)),
            row('Reseller', party(r.reseller)),
            row('Abuse contact', abuse),
            row('Technical contact', party(r.technical, lookup)),
            row('DNSSEC', esc(dnssec)),
            row('Name servers', (r.nameservers || []).map(esc).join('<br>')),
            row('Registered', esc(r.registered || '')),
            row('Last changed', esc(r.updated || '')),
            row('Expires', esc(r.expires || '')),
        ].join('');
        const kind = r.source === 'whois' ? 'WHOIS (port 43)' : 'RDAP';
        const source = r.server ? `${kind} &middot; ${esc(r.server.replace(/^https?:\/\//, '').replace(/\/$/, ''))}` : kind;
        return lifecycleBlock(r) + `<table class="data-table">${rows}</table><p class="ct-desc">Source: ${source}</p>`;
    }

    const TEXT_LABELS = {
        domain_name: 'Domain', registrar: 'Registrar', whois_server: 'WHOIS server',
        creation_date: 'Created', expiration_date: 'Expires', updated_date: 'Updated',
        name_servers: 'Name servers', status: 'Status', emails: 'Contact',
        dnssec: 'DNSSEC', org: 'Organization', country: 'Country',
        registrar_abuse_contact_email: 'Registrar abuse', reseller: 'Reseller',
    };

    function textTable(d) {
        let rows = '';
        for (const [key, label] of Object.entries(TEXT_LABELS)) {
            const val = d && d[key];
            if (val === undefined || val === null || val === '') continue;
            rows += row(label, Array.isArray(val) ? val.map(esc).join('<br>') : esc(val));
        }
        return rows ? `<table class="data-table">${rows}</table>` : '';
    }

    function render(result) {
        if (!result) return '';
        const r = result.rdap;
        const text = textTable(result.data);
        if (r && r.success) {
            return rdapTable(r) + (text
                ? `<details class="whois-raw"><summary>WHOIS (port 43)</summary>${text}</details>`
                : '');
        }
        let note = '';
        if (r && r.registered === false) {
            note = `<p class="status status-warn">${esc(r.error)}</p>`;
        } else if (r && r.error) {
            // Could not be measured over RDAP: said as such, not as a finding.
            note = `<p class="ct-desc">RDAP: ${esc(r.error)}.</p>`;
        }
        if (text) return note + text;
        if (!result.success) {
            return note + `<p class="status status-warn">${esc(result.error || 'Registration data could not be retrieved')}</p>`;
        }
        return note;
    }

    global.DomainLensWhois = { render };
})(window);
