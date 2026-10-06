// Tools -> Mail test. Uses $, esc, requestJson, toast and rows from lookup.js.
// Everything taken from the message is shown as text: its HTML is never
// rendered and its links are never made clickable.

const MT_RESULT_TEXT = {
    pass: 'Pass', fail: 'Fail', softfail: 'Soft fail', neutral: 'Neutral', none: 'None',
    permerror: 'Broken record', temperror: 'Not measured',
};
let mtLast = null;   // { file } or { text }: sent again when another hop is chosen

function mtVerdict(label, part, sub) {
    let value = 'Not measured', cls = '';
    if (part && part.state === 'measured') {
        value = MT_RESULT_TEXT[part.result] || part.result || '—';
        cls = part.result === 'pass' ? 'good' : ['fail', 'permerror'].includes(part.result) ? 'bad' : 'warn';
    }
    return `<div class="mgmt-kpi ${cls}"><div class="value">${esc(value)}</div>`
        + `<div class="label">${esc(label)}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>`;
}

function mtDkimPart(dkim) {
    const sigs = dkim.signatures;
    if (!sigs.length) return { state: 'measured', result: 'none' };
    if (sigs.some(s => s.state === 'measured' && s.result === 'pass')) return { state: 'measured', result: 'pass' };
    if (dkim.state !== 'measured') return { state: 'unmeasured' };
    return { state: 'measured', result: 'fail' };
}

function mtTlsPart(server) {
    if (server.tls === true) return { state: 'measured', result: 'pass' };
    if (server.tls === false) return { state: 'measured', result: 'fail' };
    return { state: 'unmeasured' };
}

function mtYesNo(value) {
    return value === true ? 'Yes' : value === false ? 'No' : 'Not measured';
}

function mtFindings(findings) {
    if (!findings.length) return '<p class="muted">Nothing to remark.</p>';
    return findings.map(f => `<article class="rec sev-${esc(f.severity)}"><div class="rec-head">`
        + `<span class="rec-badge sev-${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span>`
        + `<h4>${esc(f.title)}</h4></div>`
        + (f.detail ? `<div class="rec-body"><p>${esc(f.detail)}</p></div>` : '') + '</article>').join('');
}

function mtSignatures(sigs) {
    if (!sigs.length) return '<p class="muted">No DKIM signature in this message.</p>';
    return '<div class="dns-detail-table-wrap"><table class="data-table"><tr><th>Domain</th><th>Selector</th>'
        + '<th>Algorithm</th><th>Key</th><th>Result</th></tr>'
        + sigs.map(s => `<tr><td><code>${esc(s.domain)}</code></td><td><code>${esc(s.selector)}</code></td>`
            + `<td>${esc(s.algorithm)}</td><td>${s.key_bits ? esc(`${s.key_bits} bits ${s.key_type || ''}`) : '<span class="muted">—</span>'}</td>`
            + `<td>${s.state === 'measured' ? esc(MT_RESULT_TEXT[s.result] || s.result) : 'Not measured'}`
            + (s.reason ? `<div class="muted">${esc(s.reason)}</div>` : '') + '</td></tr>').join('')
        + '</table></div>';
}

function mtHops(d) {
    if (!d.hops.length) return '<p class="muted">The message has no Received headers.</p>';
    return '<p class="ct-desc">Newest first. The marked hop is where the message entered the receiving side; '
        + 'SPF and the server checks are about the address in it. If that is the wrong one, choose another.</p>'
        + '<div class="dns-detail-table-wrap"><table class="data-table mt-hops"><tr><th>#</th><th>From</th><th>Address</th>'
        + '<th>By</th><th>With</th><th></th></tr>'
        + d.hops.map(h => {
            const current = h.index === d.border;
            const tls = h.tls_version ? ` (${h.tls_version})` : '';
            return `<tr class="${current ? 'mt-border' : ''}"><td>${h.index + 1}</td>`
                + `<td>${esc(h.helo || '')}${h.rdns && h.rdns !== h.helo ? `<div class="muted">${esc(h.rdns)}</div>` : ''}</td>`
                + `<td>${h.ip ? `<code>${esc(h.ip)}</code>` : '<span class="muted">—</span>'}</td>`
                + `<td>${esc(h.by || '')}</td><td class="nowrap">${esc((h.protocol || '') + tls)}</td>`
                + `<td class="nowrap">${current ? '<strong>Judged</strong>'
                    : h.ip && h.public ? `<button class="btn-ghost-sm" type="button" data-hop-ip="${esc(h.ip)}">Judge from this hop</button>` : ''}</td></tr>`;
        }).join('') + '</table></div>';
}

function mtRender(d) {
    const s = d.summary, spf = d.spf, dmarc = d.dmarc, server = d.server;
    const sourceNote = {
        'received-spf': 'Sending address from the receiver\'s Received-SPF header.',
        received: 'Sending address read from the Received chain.',
        chosen: 'Sending address chosen by you.',
    }[d.border_source] || '';
    const verdicts = '<div class="mgmt-kpis">'
        + mtVerdict('SPF', spf, spf.ip ? `Checked ${spf.ip} for ${spf.domain || '?'}` : 'No sending address found')
        + mtVerdict('DKIM', mtDkimPart(d.dkim), s.has_body ? '' : 'Headers only: signature not verified')
        + mtVerdict('DMARC', dmarc, dmarc.policy ? `p=${dmarc.policy}` : '')
        + mtVerdict('TLS on arrival', mtTlsPart(server), server.tls_version || '')
        + '</div>';

    const auth = rows([
        ['From', s.from], ['Subject', s.subject], ['Date', s.date],
        ['Envelope sender', s.return_path || 'None (bounce or not in the headers)'],
        ['SPF', spf.explanation],
        ['DMARC policy found at', dmarc.policy_domain ? `_dmarc.${dmarc.policy_domain}` : ''],
        ['SPF aligned with From', dmarc.state === 'measured' || dmarc.spf_aligned ? mtYesNo(dmarc.spf_aligned) : ''],
        ['DKIM aligned with From', dmarc.state === 'measured' || dmarc.dkim_aligned ? mtYesNo(dmarc.dkim_aligned) : ''],
        ['DMARC', dmarc.explanation],
    ]);
    // What the receiving system concluded itself, kept apart from what
    // DomainLens verified: a sender can write such a header too.
    const receiver = d.receiver
        ? '<section class="card"><h3>As reported by the receiving system</h3>'
          + '<p class="ct-desc">From the newest Authentication-Results header. Shown for comparison; the verdict above is worked out by DomainLens.</p>'
          + rows([
              ['Reported by', d.receiver.authserv_id],
              ['Results', Object.entries(d.receiver.methods).map(([k, v]) => `${k}=${v}`).join(' ')],
              ['ARC chain', d.arc ? `${d.arc.instances} × cv=${d.arc.cv || '?'}` : ''],
          ]) + '</section>'
        : '';
    const blocklist = server.blocklist
        ? (server.blocklist.listed.length ? `Listed on ${server.blocklist.listed.join(', ')}` : 'Not listed')
          + (server.blocklist.spamhaus ? '' : ' (Spamhaus not queried: no DQS key)')
        : (server.ip ? 'Not measured' : '');
    const serverRows = rows([
        ['Address', server.ip],
        ['Reverse DNS', server.ptr_state === 'measured' ? (server.ptr.length ? server.ptr.join(', ') : 'None') : (server.ip ? 'Not measured' : '')],
        ['Reverse DNS points back', server.ptr && server.ptr.length ? mtYesNo(server.fcrdns) : ''],
        ['HELO name', server.helo],
        ['Received by', server.by],
        ['TLS on arrival', server.tls === null ? (server.ip ? 'Not stated in the header' : '') : server.tls ? `${server.tls_version || 'Yes'}${server.cipher ? ` · ${server.cipher}` : ''}` : 'No'],
        ['Blocklists', blocklist],
    ]);
    const content = d.content;
    const links = content && content.links.length
        ? '<details><summary>' + esc(`Links (${content.links.length})`) + '</summary>'
          + '<div class="dns-detail-table-wrap"><table class="data-table"><tr><th>Goes to</th><th>Shown as</th></tr>'
          + content.links.slice(0, 100).map(l => `<tr><td><code>${esc(l.host)}</code>${l.https ? '' : ' <span class="muted">http</span>'}</td>`
              + `<td>${esc(l.text)}</td></tr>`).join('') + '</table></div></details>'
        : '';
    const attachments = content && content.attachments.length
        ? rows(content.attachments.map(a => ['Attachment', `${a.name} (${a.type})`])) : '';
    const learned = d.learned.length
        ? '<p class="ct-desc">' + d.learned.map(x => esc(`DKIM selector ${x.selector} of ${x.domain} is remembered: scans of that domain now check it.`)).join('<br>') + '</p>'
        : '';

    $('mailTestResult').innerHTML =
        `<section class="card"><h3>Verdict</h3>${verdicts}<p class="ct-desc">${esc(sourceNote)}</p>${learned}</section>`
        + `<section class="card"><h3>Findings</h3>${mtFindings(d.findings)}</section>`
        + `<section class="card"><h3>Authentication</h3>${auth}<h4>DKIM signatures</h4>${mtSignatures(d.dkim.signatures)}</section>`
        + receiver
        + `<section class="card"><h3>Sending server</h3>${serverRows || '<p class="muted">No sending address found in the headers.</p>'}</section>`
        + `<section class="card"><h3>Received chain</h3>${mtHops(d)}</section>`
        + (content ? `<section class="card"><h3>Content</h3>${rows([
              ['Plain-text part', content.has_text ? 'Yes' : 'No'], ['HTML part', content.has_html ? 'Yes' : 'No'],
              ['Bulk mail', content.bulk ? 'Yes' : 'No'],
              ['Unsubscribe', { 'one-click': 'One-click', incomplete: 'Not one-click', missing: 'Missing', not_applicable: 'Not applicable (not bulk mail)' }[content.unsubscribe]],
          ])}${attachments}${links}</section>`
          : '<section class="card"><h3>Content</h3><p class="muted">Only headers were given, so the content was not checked.</p></section>');

    $('mailTestResult').querySelectorAll('[data-hop-ip]').forEach(btn =>
        btn.addEventListener('click', () => mtRun(btn.dataset.hopIp)));
}

async function mtRun(ip) {
    if (!mtLast) return;
    const btn = $('mailTestBtn');
    btn.disabled = true;
    $('mailTestResult').innerHTML = '<p class="history-empty">Analysing…</p>';
    try {
        let options;
        if (mtLast.file) {
            const form = new FormData();
            form.append('file', mtLast.file);
            if (ip) form.append('ip', ip);
            options = { method: 'POST', body: form };
        } else {
            options = { method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message: mtLast.text, ip: ip || null }) };
        }
        mtRender(await requestJson('/api/mailtest', options));
    } catch (err) {
        $('mailTestResult').innerHTML = '';
        toast(err.message);
    }
    btn.disabled = false;
}

function initMailTest() {
    if (!$('mailTestBtn')) return;
    $('mailTestBtn').addEventListener('click', () => {
        const file = $('mailTestFile').files[0];
        const text = $('mailTestSource').value;
        if (!file && !text.trim()) { toast('Paste the message source or choose an .eml file.'); return; }
        mtLast = file ? { file } : { text };
        mtRun(null);
    });
    $('mailTestClear').addEventListener('click', () => {
        $('mailTestFile').value = '';
        $('mailTestSource').value = '';
        $('mailTestResult').innerHTML = '';
        mtLast = null;
    });
}

document.addEventListener('DOMContentLoaded', initMailTest);
