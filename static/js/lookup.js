// Lookup pages: IP address, DNS record, impersonation dossier, remediation.
// One file, because each page uses a small slice of it and a separate bundle
// per page would be three more requests for a few hundred lines.

function $(id) { return document.getElementById(id); }

function esc(value) {
    const div = document.createElement('div');
    div.textContent = value === null || value === undefined ? '' : String(value);
    return div.innerHTML;
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
        const resp = await fetch('/api/ip/' + encodeURIComponent(value));
        data = await resp.json();
        if (!resp.ok || data.error) {
            out.innerHTML = `<section class="card"><p class="status status-fail">${esc(data.error || 'Lookup failed')}</p></section>`;
            return;
        }
    } catch (e) {
        out.innerHTML = `<section class="card"><p class="status status-fail">Network error</p></section>`;
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
        const resp = await fetch('/api/evidence', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, protected_domain: protectedDomain }),
        });
        data = await resp.json();
        if (!resp.ok || data.error) {
            out.innerHTML = `<section class="card"><p class="status status-fail">${esc(data.error || 'Could not build the dossier')}</p></section>`;
            return;
        }
    } catch (e) {
        out.innerHTML = `<section class="card"><p class="status status-fail">Network error</p></section>`;
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

let dnsProviderAssigned = [];

async function initDnsLookupPage() {
    const typeEl = $('dnsLookupType');
    if (!typeEl) return;
    try {
        const data = await (await fetch('/api/dns/options')).json();
        typeEl.innerHTML = (data.types || []).map(t => `<option>${esc(t)}</option>`).join('');
        $('dnsLookupResolver').innerHTML = (data.resolvers || []).map(r => `<option>${esc(r)}</option>`).join('');
        dnsProviderAssigned = data.provider_assigned || [];
        typeEl.value = 'TXT';
    } catch (e) { return; }
    $('dnsLookupBtn').addEventListener('click', dnsLookup);
    $('dnsLookupName').addEventListener('keydown', e => { if (e.key === 'Enter') dnsLookup(); });
}

function providerAssignedFor(host) {
    const h = String(host || '').replace(/\.$/, '').toLowerCase();
    return dnsProviderAssigned.find(p => h.includes(p.suffix)) || null;
}

// Follow a CNAME target and report whether it still resolves. A CNAME whose
// target is NXDOMAIN is a dangling record; when the target is a
// provider-assigned name it is stale but not claimable, which is called out
// so the reader does not mistake it for a takeover.
async function dnsDanglingNotice(target, resolver) {
    let data;
    try {
        const params = new URLSearchParams({ name: target, type: 'A', resolver });
        const resp = await fetch('/api/dns/query?' + params.toString());
        data = await resp.json();
        if (!resp.ok || data.error) return '';
    } catch (e) { return ''; }
    if (data.rcode !== 'NXDOMAIN') return '';
    const assigned = providerAssignedFor(target);
    const msg = assigned
        ? `Dangling CNAME: target <code>${esc(target)}</code> returns NXDOMAIN. It is a ${esc(assigned.provider)} name that a third party cannot re-register — a stale record to clean up, not a claimable takeover.`
        : `Dangling CNAME: target <code>${esc(target)}</code> returns NXDOMAIN. The record is stale; claimability depends on whether the provider lets the target be re-registered.`;
    return `<p class="status status-warn">${msg}</p>`;
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
        const resp = await fetch('/api/dns/query?' + params.toString());
        data = await resp.json();
        if (!resp.ok || data.error) {
            out.innerHTML = `<p class="status status-fail">${esc(data.error || 'Lookup failed')}</p>`;
            return;
        }
    } catch (e) {
        out.innerHTML = '<p class="status status-fail">Network error</p>';
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

    // Follow a CNAME to flag a dangling target (NXDOMAIN), with the
    // claimable-vs-stale nuance for provider-assigned names.
    if (data.type === 'CNAME' && data.records.length) {
        const target = String(data.records[0]).replace(/\.$/, '');
        const notice = await dnsDanglingNotice(target, $('dnsLookupResolver').value);
        if (notice) html += notice;
    }
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
    initRemediate();
});
