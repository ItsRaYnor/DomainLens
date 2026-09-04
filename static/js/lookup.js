// Lookup pages: IP address, DNS record, impersonation dossier, remediation.
// One file, because each page uses a small slice of it and a separate bundle
// per page would be three more requests for a few hundred lines.

function $(id) { return document.getElementById(id); }

function esc(value) {
    const div = document.createElement('div');
    div.textContent = value === null || value === undefined ? '' : String(value);
    return div.innerHTML;
}

// Every fetch on these pages used to end in a bare "Network error", which
// is the one thing it usually is not: a 404 from a server that has not been
// restarted since a route was added, or a 500, both arrive as a perfectly
// healthy response carrying HTML. Saying "network" sends someone to check
// their connection instead of their server.
async function requestJson(url, options) {
    let resp;
    try {
        resp = await fetch(url, options);
    } catch (e) {
        throw new Error('Could not reach the server. Is DomainLens still running?');
    }
    const body = await resp.text();
    let data = null;
    try {
        data = body ? JSON.parse(body) : null;
    } catch (e) {
        if (resp.status === 404) {
            throw new Error(`This endpoint is not available (HTTP 404). If you just `
                + `updated DomainLens, restart it: routes are registered at startup.`);
        }
        throw new Error(`The server returned HTTP ${resp.status} instead of JSON.`);
    }
    if (!resp.ok || (data && data.error)) {
        throw new Error((data && data.error) || `The server returned HTTP ${resp.status}.`);
    }
    return data;
}

function toast(message) {
    const el = $('errorToast');
    if (!el) return;
    el.textContent = message;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
}

function rows(pairs) {
    // Only rows with a value: an empty cell reads as "we looked and found
    // nothing", which is a different claim from "this field does not apply".
    const body = pairs
        .filter(([, value]) => value !== null && value !== undefined && value !== '')
        .map(([label, value]) => `<tr><th>${esc(label)}</th><td>${esc(value)}</td></tr>`)
        .join('');
    return body ? `<table class="data-table"><tbody>${body}</tbody></table>` : '';
}

function card(title, inner, extraClass) {
    if (!inner) return '';
    return `<section class="card ${extraClass || ''}">
        <h3>${esc(title)}</h3>${inner}</section>`;
}

// ===== IP address =====

async function ipLookup() {
    const out = $('ipResult');
    const value = $('ipInput').value.trim();
    if (!value) { out.innerHTML = ''; return; }
    out.innerHTML = '<p class="history-empty">Looking up…</p>';

    let data;
    try {
        data = await requestJson('/api/ip/' + encodeURIComponent(value));
    } catch (e) {
        out.innerHTML = `<section class="card"><p class="status status-fail">${esc(e.message)}</p></section>`;
        return;
    }

    if (data.not_applicable) {
        // A correct address that no registry has an answer for is not a
        // failure, and must not be rendered as one.
        out.innerHTML = `<section class="card"><p class="status status-warn">${esc(data.not_applicable)}</p></section>`;
        return;
    }

    const rdap = data.rdap || {};
    const geo = (data.geo || {}).geo || {};
    const bl = data.blacklist || {};
    let html = '';

    // The abuse contact leads: it is the one field that decides where a
    // notice goes, and burying it in the registry table is why people give up
    // and mail the hosting company's sales address instead.
    if (data.abuse_contact) {
        html += `<section class="card highlight-card">
            <h3>Abuse contact</h3>
            <p class="abuse-address"><a href="mailto:${esc(data.abuse_contact)}">${esc(data.abuse_contact)}</a></p>
            <p class="ct-desc">Registered for ${esc(rdap.range || rdap.name || 'this range')}. This is the party that can act on the content hosted here.</p>
        </section>`;
    } else if (rdap.success) {
        html += `<section class="card"><h3>Abuse contact</h3>
            <p class="status status-warn">The registry record names no abuse address. The parent range may still have one.</p></section>`;
    }

    html += card('Registry', rows([
        ['Range', rdap.range],
        ['Network name', rdap.name],
        ['Type', rdap.type],
        ['Country', rdap.country],
        ['Handle', rdap.handle],
        ['Holder', (rdap.registrant || {}).name],
        ['Registered', (rdap.events || {}).registration],
        ['Last changed', (rdap.events || {}).lastchanged || (rdap.events || {})['last changed']],
    ]) || (rdap.error ? `<p class="status status-warn">${esc(rdap.error)}</p>` : ''));

    html += card('Network', rows([
        ['ASN', geo.asn],
        ['Operator', geo.asname || geo.org],
        ['ISP', geo.isp],
        ['Location', [geo.city, geo.region, geo.country].filter(Boolean).join(', ')],
        ['Hosting/datacentre', geo.hosting === undefined ? '' : (geo.hosting ? 'yes' : 'no')],
        ['Proxy/VPN', geo.proxy === undefined ? '' : (geo.proxy ? 'yes' : 'no')],
    ]));

    const ptr = (data.reverse_dns || {}).names || [];
    html += card('Reverse DNS', ptr.length
        ? `<table class="data-table"><tbody>${ptr.map(n => `<tr><td class="mono">${esc(n)}</td></tr>`).join('')}</tbody></table>`
        : '<p class="ct-desc">No PTR record.</p>');

    const listed = bl.listed || [];
    html += card('Reputation', listed.length
        ? `<p class="status status-fail">Listed on ${listed.length} blocklist(s)</p>
           <table class="data-table"><tbody>${listed.map(z => `<tr><td class="mono">${esc(z)}</td></tr>`).join('')}</tbody></table>`
        : `<p class="status status-pass">Not listed on ${(bl.clean || []).length} checked blocklist(s)</p>`);

    out.innerHTML = html;
}

// ===== Impersonation dossier =====

let lastDossier = null;

function similarityText(sim) {
    if (!sim) return '';
    const parts = [];
    if (sim.tld_swap_only) parts.push('Same name under a different top-level domain.');
    else if (sim.edit_distance === 1) parts.push('Differs from your domain by one character.');
    else if (sim.edit_distance <= 3) parts.push(`Differs from your domain by ${sim.edit_distance} characters.`);
    if (sim.contains_protected) parts.push('Contains your domain name as part of a longer name.');
    parts.push(`Edit distance ${sim.edit_distance}, similarity ${Math.round(sim.similarity * 100)}%.`);
    return parts.join(' ');
}

async function buildDossier() {
    const out = $('impResult');
    const domain = $('impDomain').value.trim();
    const protectedDomain = $('impProtected').value.trim();
    if (!domain) { out.innerHTML = ''; return; }
    out.innerHTML = '<p class="history-empty">Collecting…</p>';

    let data;
    try {
        data = await requestJson('/api/evidence', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, protected_domain: protectedDomain }),
        });
    } catch (e) {
        out.innerHTML = `<section class="card"><p class="status status-fail">${esc(e.message)}</p></section>`;
        return;
    }

    lastDossier = data;
    const where = data.where_to_report || {};
    const reg = where.registrar || {};
    const net = where.hosting_network || {};
    let html = '';

    // Two routes, side by side and labelled with what each can actually do.
    // A notice to the wrong one is forwarded at best.
    html += `<section class="card highlight-card">
        <h3>Where to report</h3>
        <div class="report-routes">
            <div class="route">
                <span class="route-label">Registrar</span>
                <p class="route-name">${esc(reg.name || 'unknown')}</p>
                ${reg.abuse_email
                    ? `<p class="abuse-address"><a href="mailto:${esc(reg.abuse_email)}">${esc(reg.abuse_email)}</a></p>`
                    : '<p class="status status-warn">No abuse address published</p>'}
                <p class="ct-desc">Can ${esc(reg.can || '')}</p>
            </div>
            <div class="route">
                <span class="route-label">Hosting network</span>
                <p class="route-name">${esc(net.name || 'unknown')}</p>
                ${net.abuse_email
                    ? `<p class="abuse-address"><a href="mailto:${esc(net.abuse_email)}">${esc(net.abuse_email)}</a></p>`
                    : '<p class="status status-warn">No abuse address published</p>'}
                <p class="ct-desc">Can ${esc(net.can || '')}</p>
            </div>
        </div>
    </section>`;

    if (data.similarity) {
        html += card('Similarity', `<p>${esc(similarityText(data.similarity))}</p>
            <p class="ct-desc">DomainLens measures and describes the resemblance. Whether that amounts to infringement is a question about your mark and their use of it, and stays yours to assert.</p>`);
    }

    const reg2 = data.registration || {};
    html += card('Registration', rows([
        ['Created', reg2.created],
        ['Updated', reg2.updated],
        ['Expires', reg2.expires],
        ['Registrant organisation', reg2.registrant_org],
        ['Registrant country', reg2.registrant_country],
        ['Name servers', (reg2.name_servers || []).join(', ')],
        ['Status', Array.isArray(reg2.status) ? reg2.status.join(', ') : reg2.status],
    ]));

    const addr = data.address || {};
    html += card('Address', rows([
        ['IP', addr.ip],
        ['Reverse DNS', (addr.reverse_dns || []).join(', ')],
        ['Blocklisted on', (addr.blacklisted_on || []).join(', ')],
    ]));

    if (data.body) {
        html += card('Page fingerprint', rows([
            ['SHA-256', data.body.sha256],
            ['Bytes', data.body.length],
        ]));
    }

    if ((data.gaps || []).length) {
        // Stated rather than left as blanks: a missing abuse address is the
        // one thing that stops a notice being sent at all.
        html += `<section class="card"><h3>What is missing</h3><ul class="gap-list">
            ${data.gaps.map(g => `<li>${esc(g)}</li>`).join('')}</ul></section>`;
    }

    html += `<section class="card">
        <p class="ct-desc">Observed at ${esc(data.generated_at)} by DomainLens ${esc((data.tool || {}).version || '')}.</p>
        <button type="button" class="btn-primary-lite" id="impDownload">Download as JSON</button>
    </section>`;

    out.innerHTML = html;
    const download = $('impDownload');
    if (download) download.addEventListener('click', downloadDossier);
}

function downloadDossier() {
    if (!lastDossier) return;
    const blob = new Blob([JSON.stringify(lastDossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dossier-${lastDossier.subject.domain}-${lastDossier.generated_at.slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// ===== DNS record (same behaviour as the panel it replaces) =====

function formatCacheAge(seconds) {
    const n = Number(seconds) || 0;
    if (n < 3600) return `${Math.max(1, Math.round(n / 60))} min`;
    const hours = n / 3600;
    return hours < 24 ? `${Math.round(hours)} h` : `${Math.round(hours / 24)} d`;
}

let dnsResolverOptions = [];
let dnsCustomResolvers = [];

async function initDnsLookupPage() {
    const typeEl = $('dnsLookupType');
    if (!typeEl) return;
    try {
        const data = await (await fetch('/api/dns/options')).json();
        typeEl.innerHTML = (data.types || []).map(t => `<option>${esc(t)}</option>`).join('');
        dnsResolverOptions = data.resolvers || [];
        dnsCustomResolvers = data.custom_resolvers || [];
        $('dnsLookupResolver').innerHTML = dnsResolverOptions.map(r => `<option>${esc(r)}</option>`).join('');
        typeEl.value = 'TXT';
    } catch (e) { return; }
    $('dnsLookupBtn').addEventListener('click', dnsLookup);
    $('dnsLookupName').addEventListener('keydown', e => { if (e.key === 'Enter') dnsLookup(); });

    // Propagation: the same resolver list, as checkboxes. Everything except
    // the system resolver is ticked by default -- "system" is whatever this
    // container was handed, which says nothing about the public internet.
    const box = $('dnsPropResolvers');
    if (box) {
        box.innerHTML = (dnsResolverOptions || []).map((r, i) => `<label class="prop-resolver">
            <input type="checkbox" value="${esc(r)}"${r === 'system' ? '' : ' checked'}>
            <span>${esc(r)}</span></label>`).join('');
        // Say plainly whether any own resolvers are configured. Buried in a
        // sentence about port 53, the link read as a footnote and people
        // looked for an address box on this page instead.
        const hint = $('dnsPropCustomHint');
        if (hint) {
            hint.innerHTML = dnsCustomResolvers.length
                ? `Your own resolvers: <strong>${esc(dnsCustomResolvers.join(', '))}</strong>. `
                  + `<a href="/admin/settings#scan">Edit the list</a>.`
                : `<strong>Want to check your own DNS server?</strong> Add it under `
                  + `<a href="/admin/settings#scan">Settings &rarr; Scan &rarr; Custom resolvers</a>, `
                  + `one <code>Label = 1.2.3.4</code> per line &mdash; it then appears as a checkbox here. `
                  + `Addresses live in settings rather than in this box so an unauthenticated `
                  + `page cannot be used to aim UDP/53 at any host this server can reach.`;
        }
        const propBtn = $('dnsPropBtn');
        if (propBtn) propBtn.addEventListener('click', dnsPropagation);
    }
}

// Rendered next to every answer so you can see what came back, not just the
// values: which server replied, the flags it set, and the authority section
// that explains a delegation you did not expect.
function dnsDetailHtml(data) {
    const d = data.detail;
    if (!d) return '';
    const rows = [];
    ['answer', 'authority', 'additional'].forEach(section => {
        (d[section] || []).forEach(r => {
            // An RRSIG is a few hundred characters of base64. Left whole it
            // wraps into a cell taller than the screen and buries the records
            // the table exists to show. Marked with an ellipsis rather than
            // silently cut, and the whole value stays in the title.
            const full = String(r.value === null || r.value === undefined ? '' : r.value);
            const shown = full.length > 120 ? full.slice(0, 120) + '…' : full;
            const title = full.length > 120 ? ` title="${esc(full)}"` : '';
            rows.push(`<tr><td class="mono">${esc(section)}</td><td class="mono">${esc(r.name)}</td>`
                + `<td class="mono">${esc(r.ttl)}</td><td class="mono">${esc(r.type)}</td>`
                + `<td class="mono dns-detail-value"${title}>${esc(shown)}</td></tr>`);
        });
    });
    if (!rows.length) return '';
    const flags = (d.flags || []).join(' ');
    return `<details class="dns-detail"><summary>Query detail</summary>
        <p class="http-meta"><span>${esc(d.rcode)}${flags ? ' · flags: ' + esc(flags) : ''}`
        + `${data.answered_by ? ' · answered by ' + esc(data.answered_by) : ''}</span></p>
        <div class="dns-detail-table-wrap"><table class="data-table"><thead><tr><th>Section</th><th>Name</th><th>TTL</th><th>Type</th><th>Value</th></tr></thead>
        <tbody>${rows.join('')}</tbody></table></div></details>`;
}

async function dnsPropagation() {
    const out = $('dnsPropResult');
    const name = $('dnsLookupName').value.trim();
    if (!name) { out.innerHTML = '<p class="status status-warn">Enter a name above first.</p>'; return; }
    const chosen = Array.from($('dnsPropResolvers').querySelectorAll('input:checked')).map(c => c.value);
    if (!chosen.length) { out.innerHTML = '<p class="status status-warn">Tick at least one resolver.</p>'; return; }

    out.innerHTML = '<p class="history-empty">Asking ' + esc(chosen.length) + ' resolvers…</p>';
    let data;
    try {
        const params = new URLSearchParams({ name, type: $('dnsLookupType').value });
        chosen.forEach(r => params.append('resolver', r));
        data = await requestJson('/api/dns/propagation?' + params.toString());
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    }

    // Three verdicts, three sentences. "unknown" is never dressed up as a
    // pass: too few resolvers answered to have compared anything.
    const verdicts = {
        propagated: ['status-pass', `All ${data.answered} resolvers that answered agree.`],
        inconsistent: ['status-fail', `Resolvers disagree — the change is still rolling out.`],
        unknown: ['status-warn', `Not enough resolvers answered (${data.answered}) to compare.`],
    };
    const [cls, text] = verdicts[data.verdict] || ['status-warn', 'No verdict'];
    let html = `<p class="status ${cls}">${esc(text)}</p>`;
    if ((data.unreachable || []).length) {
        html += `<p class="ct-desc">Could not be measured: ${esc(data.unreachable.join(', '))}.`
            + ` This is our reach, not their records.</p>`;
    }
    if (data.verdict === 'inconsistent') {
        html += '<table class="data-table"><thead><tr><th>Answer</th><th>Seen by</th></tr></thead><tbody>'
            + data.groups.map(g => `<tr><td class="mono" style="word-break:break-all">`
                + `${esc((g.records || []).join(', ') || g.rcode || '—')}</td>`
                + `<td>${esc((g.resolvers || []).join(', '))}</td></tr>`).join('')
            + '</tbody></table>';
    }
    html += (data.results || []).map(r => {
        const head = r.error
            ? `<span class="status status-warn">unreachable</span> ${esc(r.error)}`
            : `<span class="mono">${esc((r.records || []).join(', ') || r.rcode || '—')}</span>`
              + (r.ttl !== null && r.ttl !== undefined ? ` · TTL ${esc(r.ttl)}s` : '')
              + (r.elapsed_ms !== null && r.elapsed_ms !== undefined ? ` · ${esc(r.elapsed_ms)} ms` : '');
        return `<div class="prop-row"><strong>${esc(r.resolver)}</strong><div>${head}</div>`
            + dnsDetailHtml(r) + '</div>';
    }).join('');
    out.innerHTML = html;
}

async function dnsLookup() {
    const out = $('dnsLookupResult');
    const name = $('dnsLookupName').value.trim();
    if (!name) { out.innerHTML = ''; return; }
    out.innerHTML = '<p class="history-empty">Looking up…</p>';
    let data;
    try {
        const params = new URLSearchParams({
            name, type: $('dnsLookupType').value, resolver: $('dnsLookupResolver').value,
        });
        data = await requestJson('/api/dns/query?' + params.toString());
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    }

    let html = '';
    if (!data.records.length) {
        const detail = data.rcode === 'NXDOMAIN'
            ? `${esc(data.name)} does not exist`
            : `${esc(data.name)} exists but has no ${esc(data.type)} record`;
        html += `<p class="status status-warn">${detail} (${esc(data.rcode)})</p>`;
    } else {
        html += '<table class="data-table"><tbody>'
            + data.records.map(r => `<tr><td class="mono" style="word-break:break-all">${esc(r)}</td></tr>`).join('')
            + '</tbody></table>';
    }
    const meta = [];
    if (data.ttl !== null && data.ttl !== undefined) meta.push(`TTL ${esc(data.ttl)}s`);
    meta.push(`${esc(data.elapsed_ms)} ms`);
    if (data.resolver === 'authoritative') {
        meta.push(`authoritative for ${esc(data.authoritative_zone || '?')}`);
    } else if (data.authenticated) {
        meta.push('DNSSEC validated');
    }
    html += `<p class="http-meta"><span>${meta.join(' · ')}</span></p>`;
    html += dnsDetailHtml(data);
    out.innerHTML = html;
}

// ===== Remediation landing =====

async function initRemediate() {
    const btn = $('remediateBtn');
    if (!btn) return;
    const go = () => {
        const domain = $('remediateDomain').value.trim().toLowerCase();
        if (domain) window.location.href = '/remediate/domain/' + encodeURIComponent(domain);
    };
    btn.addEventListener('click', go);
    $('remediateDomain').addEventListener('keydown', e => { if (e.key === 'Enter') go(); });

    const list = $('remediateRecent');
    try {
        const data = await (await fetch('/api/history?limit=15')).json();
        const scans = data.scans || [];
        list.innerHTML = scans.length
            ? '<table class="data-table"><tbody>' + scans.map(s =>
                `<tr><td><a href="/remediate/domain/${encodeURIComponent(s.domain)}">${esc(s.domain)}</a></td>
                     <td>${esc(new Date(s.created_at).toLocaleDateString())}</td>
                     <td>${esc(s.grade || '')}</td></tr>`).join('') + '</tbody></table>'
            : '<p class="history-empty">No scans yet</p>';
    } catch (e) {
        list.innerHTML = '<p class="history-empty">Could not load recent scans</p>';
    }
}

// ===== PGP / security.txt lookup =====

function keyVerdict(key) {
    // The three states, each with the sentence an operator can act on.
    if (!key) return ['status-warn', 'No key information'];
    if (key.state === 'not_applicable') {
        return ['status-warn', 'No Encryption: field — optional in RFC 9116, so this is a '
                + 'choice, not a fault. Researchers have no way to encrypt a report.'];
    }
    if (key.state === 'unmeasured') {
        return ['status-warn', 'Could not be checked: ' + (key.reason || 'unknown')
                + '. That is our reach, not their records.'];
    }
    if (key.private_key_published) {
        return ['status-fail', 'The Encryption: URL serves a PGP PRIVATE key. Anyone who '
                + 'fetched it can decrypt reports sent to this address.'];
    }
    if (key.armored) return ['status-pass', 'Armoured PGP public key served.'];
    return ['status-fail', 'The URL does not serve a PGP public key: ' + (key.reason || '')];
}

async function pgpLookup() {
    const out = $('pgpLookupResult');
    const domain = ($('pgpLookupDomain').value || '').trim().toLowerCase();
    if (!domain) { out.innerHTML = ''; return; }
    out.innerHTML = '<p class="history-empty">Fetching security.txt…</p>';
    let data;
    try {
        data = await requestJson('/api/pgp/inspect?domain=' + encodeURIComponent(domain));
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    }

    if (!data.found) {
        // Absent is a finding in itself, and distinct from unreachable.
        const why = data.error
            ? esc(data.error)
            : `No security.txt at ${esc(data.url || domain)}`
              + (data.status ? ` (HTTP ${esc(data.status)})` : '');
        out.innerHTML = `<p class="status status-warn">${why}</p>`
            + '<p class="ct-desc">Researchers have no documented way to report a '
            + 'vulnerability to this domain.</p>';
        return;
    }

    const [cls, text] = keyVerdict(data.key);
    let html = `<p class="status status-pass">security.txt found at ${esc(data.url)}</p>`;
    html += `<p class="status ${cls}">${esc(text)}</p>`;
    if (data.key && data.key.url) {
        html += `<p class="ct-desc">Encryption: <span class="mono" style="word-break:break-all">${esc(data.key.url)}</span></p>`;
    }
    // The key was fetched during the check, so its details are already here.
    // "Armoured" only says the wrapper is right: an expired key passes that
    // and still leaves a researcher unable to encrypt anything.
    const details = data.key && data.key.key_details;
    if (details && (details.keys || []).length) {
        html += '<table class="data-table"><thead><tr><th>Fingerprint</th><th>Algorithm</th>'
             + '<th>Created</th><th>Expires</th><th>Identities</th></tr></thead><tbody>'
            + details.keys.map(k => {
                const exp = k.expires
                    ? (k.expired ? `<span class="status status-fail">${esc(k.expires)} — expired</span>`
                                 : esc(k.expires))
                    : 'never';
                return `<tr><td class="mono" style="word-break:break-all">${esc(k.fingerprint || '?')}</td>`
                    + `<td>${esc(k.algorithm)}${k.bits ? ' / ' + esc(k.bits) : ''}</td>`
                    + `<td>${esc(k.created || '?')}</td><td>${exp}</td>`
                    + `<td>${esc((k.uids || []).join(', '))}</td></tr>`;
            }).join('') + '</tbody></table>';
        if (details.keys.some(k => k.expired)) {
            html += '<p class="status status-fail">The published key has expired. A '
                 + 'researcher following this field cannot encrypt to it.</p>';
        }
    } else if (details && details.error) {
        html += `<p class="status status-warn">The key was fetched but could not be read: `
             + `${esc(details.error)}</p>`;
    }

    const fields = data.fields || {};
    const rows = Object.keys(fields).sort().map(name => {
        const values = (fields[name] || []).map(v =>
            `<div class="mono" style="word-break:break-all">${esc(v)}</div>`).join('');
        return `<tr><td>${esc(name)}</td><td>${values}</td></tr>`;
    }).join('');
    if (rows) {
        html += '<table class="data-table"><thead><tr><th>Field</th><th>Value</th></tr></thead>'
            + `<tbody>${rows}</tbody></table>`;
    }
    if (data.raw) {
        html += '<details class="dns-detail"><summary>Raw file</summary>'
            + `<pre class="mono" style="white-space:pre-wrap;word-break:break-all">${esc(data.raw)}</pre></details>`;
    }
    out.innerHTML = html;
}

function listBlock(cls, title, items) {
    if (!items || !items.length) return '';
    return `<p class="status ${cls}">${esc(title)}</p><ul class="finding-list">`
        + items.map(i => `<li>${esc(i)}</li>`).join('') + '</ul>';
}

async function validateSecurityTxt() {
    const out = $('stxtResult');
    const body = $('stxtInput').value;
    if (!body.trim()) { out.innerHTML = '<p class="status status-warn">Paste a file first.</p>'; return; }
    let data;
    try {
        data = await requestJson('/api/pgp/validate-securitytxt', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ body }),
        });
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    }
    // Errors break the file; warnings and notes do not. Kept apart so an
    // operator can tell "this is broken" from "this could say more".
    let html = data.valid
        ? '<p class="status status-pass">Valid against RFC 9116.</p>'
        : '<p class="status status-fail">Not a valid security.txt.</p>';
    html += listBlock('status-fail', 'Errors', data.errors);
    html += listBlock('status-warn', 'Warnings', data.warnings);
    html += listBlock('status-warn', 'Could say more', data.notes);
    const fields = data.fields || {};
    const rows = Object.keys(fields).sort().map(n =>
        `<tr><td>${esc(n)}</td><td class="mono" style="word-break:break-all">`
        + `${esc((fields[n] || []).join(', '))}</td></tr>`).join('');
    if (rows) {
        html += '<table class="data-table"><thead><tr><th>Field</th><th>Value</th></tr></thead>'
            + `<tbody>${rows}</tbody></table>`;
    }
    out.innerHTML = html;
}

async function validatePgpKey() {
    const out = $('pgpKeyResult');
    const key = $('pgpKeyInput').value;
    if (!key.trim()) { out.innerHTML = '<p class="status status-warn">Paste a key first.</p>'; return; }
    out.innerHTML = '<p class="history-empty">Reading the key…</p>';
    let data;
    try {
        data = await requestJson('/api/pgp/validate-key', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key }),
        });
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    }
    let html = '';
    if (data.is_private) {
        html += '<p class="status status-fail">This is a PGP <strong>private</strong> key. '
             + 'If it has been published anywhere, treat it as compromised: revoke it and '
             + 'publish only the exported public half.</p>';
    }
    html += data.valid
        ? '<p class="status status-pass">gpg read this key.</p>'
        : `<p class="status status-fail">${esc(data.error || 'gpg could not read this key')}</p>`;
    if ((data.keys || []).length) {
        html += '<table class="data-table"><thead><tr><th>Fingerprint</th><th>Algorithm</th>'
             + '<th>Created</th><th>Expires</th><th>Identities</th></tr></thead><tbody>'
            + data.keys.map(k => {
                const exp = k.expires
                    ? (k.expired ? `<span class="status status-fail">${esc(k.expires)} — expired</span>`
                                 : esc(k.expires))
                    : 'never';
                return `<tr><td class="mono" style="word-break:break-all">${esc(k.fingerprint || '?')}</td>`
                    + `<td>${esc(k.algorithm)}${k.bits ? ' / ' + esc(k.bits) : ''}</td>`
                    + `<td>${esc(k.created || '?')}</td><td>${exp}</td>`
                    + `<td>${esc((k.uids || []).join(', '))}</td></tr>`;
            }).join('')
            + '</tbody></table>';
    }
    out.innerHTML = html;
}

async function generateThrowawayKey() {
    const btn = $('genBtn');
    const out = $('genResult');
    const name = ($('genName').value || '').trim();
    const email = ($('genEmail').value || '').trim();
    const expiry = ($('genExpiry').value || '2y').trim();
    const passphrase = $('genPassphrase') ? $('genPassphrase').value : '';
    if (!name || !email) {
        out.innerHTML = '<p class="status status-warn">Enter a name and an email address.</p>';
        return;
    }
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = 'Generating…';
    out.innerHTML = '<p class="history-empty">Generating a keypair…</p>';
    let data;
    try {
        data = await requestJson('/api/pgp/generate', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, expiry, passphrase }),
        });
    } catch (e) {
        out.innerHTML = `<p class="status status-fail">${esc(e.message)}</p>`;
        return;
    } finally {
        btn.disabled = false; btn.textContent = label;
        // Cleared once used: it protects the file that was just handed over,
        // and leaving it sitting in the form serves nothing.
        const field = $('genPassphrase');
        if (field) field.value = '';
    }

    const protection = data.protected
        ? 'The private key is passphrase-protected; you will need it to use the key.'
        : 'The private key has no passphrase: anyone holding the file can use it.';
    out.innerHTML = `<div class="login-error"><strong>Save both halves now.</strong> ${esc(data.warning)}</div>
        <p class="ct-desc">${esc(protection)}</p>
        <p class="muted mono" style="word-break:break-all">${esc(data.fingerprint)}</p>
        <div class="pgp-actions">
            <button class="btn-primary-lite" id="genDownloadPriv" type="button">Download private key</button>
            <button class="btn-ghost" id="genDownloadPub" type="button">Download public key</button>
        </div>
        <label class="ct-desc">Private key</label><textarea id="genPrivBox" rows="8" readonly class="mono"></textarea>
        <label class="ct-desc">Public key</label><textarea id="genPubBox" rows="8" readonly class="mono"></textarea>`;
    // Assigned, not interpolated: armour text never becomes markup.
    $('genPrivBox').value = data.private_key;
    $('genPubBox').value = data.public_key;

    const save = (text, suffix) => {
        const blob = new Blob([text], { type: 'application/pgp-keys' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `domainlens-${(data.fingerprint || 'key').slice(-16)}-${suffix}.asc`;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    $('genDownloadPriv').addEventListener('click', () => save(data.private_key, 'private'));
    $('genDownloadPub').addEventListener('click', () => save(data.public_key, 'public'));
}

function initPgpLookupPage() {
    const btn = $('pgpLookupBtn');
    if (!btn) return;
    btn.addEventListener('click', pgpLookup);
    $('pgpLookupDomain').addEventListener('keydown', e => {
        if (e.key === 'Enter') pgpLookup();
    });
    const bind = (id, handler) => { const el = $(id); if (el) el.addEventListener('click', handler); };
    bind('stxtValidateBtn', validateSecurityTxt);
    bind('pgpKeyValidateBtn', validatePgpKey);
    bind('genBtn', generateThrowawayKey);
}

document.addEventListener('DOMContentLoaded', async () => {
    if (window.DomainLensI18n) {
        try { await DomainLensI18n.init(DomainLensI18n.pageLocale()); }
        catch (e) { console.error('i18n init failed; continuing without translations', e); }
    }
    const ipBtn = $('ipLookupBtn');
    if (ipBtn) {
        ipBtn.addEventListener('click', ipLookup);
        $('ipInput').addEventListener('keydown', e => { if (e.key === 'Enter') ipLookup(); });
        // Arriving from the scan box with an address already typed: run it
        // rather than making the reader press the button again.
        const handed = new URLSearchParams(window.location.search).get('ip');
        if (handed) {
            $('ipInput').value = handed;
            ipLookup();
        }
    }
    const impBtn = $('impBtn');
    if (impBtn) {
        impBtn.addEventListener('click', buildDossier);
        $('impProtected').addEventListener('keydown', e => { if (e.key === 'Enter') buildDossier(); });
    }
    initDnsLookupPage();
    initPgpLookupPage();
    initRemediate();
});
