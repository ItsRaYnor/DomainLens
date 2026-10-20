// Tools -> Mail and web analysis. Uses $, esc, requestJson, toast and rows from lookup.js.
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

// Why DKIM could not be judged, under the verdict: "not measured" alone
// read as a fault, while the usual cause is a copy that is not the original.
function mtDkimWhy(dkim, s, origin) {
    if (!s.has_body) return 'Headers only: signature not verified';
    if (origin === 'msg' && mtDkimPart(dkim).state !== 'measured') {
        return dkim.signatures.some(sig => sig.receiver === 'pass')
            ? 'Outlook file: not verifiable here; the receiver verified it' : 'Outlook file: the body is not as sent';
    }
    if (mtDkimPart(dkim).state === 'measured') return '';
    if (dkim.signatures.some(sig => sig.receiver === 'pass')) return 'The receiver verified it; this copy was altered. Upload the .eml file';
    return dkim.signatures.some(sig => sig.state !== 'measured') ? 'The key could not be looked up' : '';
}

function mtIpLists(found) {
    if (!found) return '';
    return found.state === 'listed' ? `Listed on ${found.lists.map(l => l.source).join(', ')}`
        : found.state === 'not_listed' ? 'Not listed'
        : found.state === 'not_public' ? 'Not a public address'
        : 'Not checked (no list downloaded yet)';
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

// The reason a signature failed or could not be checked gets a line of its
// own under it: in a cell it squeezed the column to a letter's width.
function mtSignatures(sigs) {
    if (!sigs.length) return '<p class="muted">No DKIM signature in this message.</p>';
    return '<div class="dns-detail-table-wrap"><table class="data-table mt-table stack-table"><tr><th>Domain</th><th>Selector</th>'
        + '<th>Algorithm</th><th>Key</th><th>Result</th></tr>'
        + sigs.map(s => `<tr><td><code>${esc(s.domain)}</code></td><td><code>${esc(s.selector)}</code></td>`
            + `<td>${esc(s.algorithm)}</td><td class="nowrap">${s.key_bits ? esc(`${s.key_bits} bits ${s.key_type || ''}`) : '<span class="muted">—</span>'}</td>`
            + `<td class="nowrap">${s.state === 'measured' ? esc(MT_RESULT_TEXT[s.result] || s.result) : 'Not measured'}</td></tr>`
            + (s.reason ? `<tr class="mt-reason"><td colspan="5">${esc(s.reason)}</td></tr>` : '')).join('')
        + '</table></div>';
}

// Seconds between two Received stamps, or null when either is unreadable or
// the clocks disagree (a negative or day-long step says nothing).
function mtSeconds(older, newer) {
    const a = Date.parse(older && older.at), b = Date.parse(newer && newer.at);
    if (isNaN(a) || isNaN(b)) return null;
    const s = Math.round((b - a) / 1000);
    return s >= 0 && s < 86400 ? s : null;
}

function mtUtc(at) {
    const t = Date.parse(at);
    return isNaN(t) ? '' : new Date(t).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

// A host name may break after a dot or a colon, never inside a label.
function mtHost(name) {
    return esc(name).replace(/([.:])/g, '$1<wbr>');
}

// The Received chain oldest first, as a relay table: delay with a bar, the
// sending and receiving host, protocol and TLS, time in UTC, and the
// blocklist answer on the hop where the message was handed over.
function mtHops(d) {
    if (!d.hops.length) return '<p class="muted">The message has no Received headers.</p>';
    const hops = d.hops.slice().reverse();
    const delays = hops.map((h, i) => (i ? mtSeconds(hops[i - 1], h) : null));
    const longest = Math.max(1, ...delays.filter(x => x !== null));
    const listed = d.server.blocklist
        ? (d.server.blocklist.listed.length ? mtTag('Listed', 'bad', d.server.blocklist.listed.join(', ')) : mtTag('Not listed', 'ok'))
        : mtTag('Not measured', 'na');
    return '<p class="ct-desc">Oldest first. The marked hop is where the message entered the receiving side; '
        + 'SPF and the server checks are about the address in it. If that is the wrong one, choose another.</p>'
        + '<div class="dns-detail-table-wrap"><table class="data-table mt-table mt-hops stack-table"><tr><th>Hop</th><th>Delay</th>'
        + '<th>From</th><th>By</th><th>With</th><th>Time (UTC)</th><th>Blocklist</th></tr>'
        + hops.map((h, i) => {
            const current = h.index === d.border;
            const delay = delays[i];
            const bar = delay === null ? (i ? '<span class="muted">?</span>' : '<span class="muted">*</span>')
                : `<span class="mt-delay"><span class="mt-delay-track"><span class="mt-delay-bar" style="width:${Math.max(4, Math.round(100 * delay / longest))}%"></span></span>`
                  + `<span>${esc(mtDelay(hops[i - 1], h).replace('+', ''))}</span></span>`;
            const name = h.rdns || h.helo || '';
            const tls = h.tls_version ? ` · ${h.tls_version}` : '';
            const utc = mtUtc(h.at);
            const choose = current ? '<div class="mt-judged">Judged</div>'
                : h.ip && h.public ? `<div><button class="btn-ghost-sm" type="button" data-hop-ip="${esc(h.ip)}">Judge from this hop</button></div>` : '';
            return `<tr class="${current ? 'mt-border' : ''}"><td class="nowrap">${i + 1}</td><td class="nowrap">${bar}</td>`
                + `<td class="mt-host">${name ? `<code>${mtHost(name)}</code>` : ''}${h.ip ? `<div><code class="muted">${mtHost(h.ip)}</code></div>` : ''}`
                + `${!name && !h.ip ? '<span class="muted">—</span>' : ''}${choose}</td>`
                + `<td class="mt-host"><code>${mtHost(h.by || '')}</code></td><td class="nowrap">${esc((h.protocol || '') + tls)}</td>`
                + `<td class="nowrap"${utc ? ` title="${esc(utc)}"` : ''}>${esc(utc ? utc.slice(11, 19) : '')}</td>`
                + `<td class="nowrap">${current ? listed : ''}</td></tr>`;
        }).join('') + '</table></div>';
}

// ===== Mail flow =====
// The path of the message as a picture, oldest step first: the sender, any
// relays on its side, the server that handed it over (where SPF is judged),
// the hand-over itself (TLS, delay), the receiving server (where DMARC is
// judged) and the mailbox. Each check sits on the step it is about, so an
// analyst sees where a message failed instead of reading it from a list.

const MT_CHIP_CLASS = { pass: 'ok', fail: 'bad', softfail: 'warn', neutral: 'warn', none: 'warn', permerror: 'bad' };

function mtChip(label, part, title) {
    const measured = part && part.state === 'measured';
    const cls = measured ? (MT_CHIP_CLASS[part.result] || 'warn') : 'na';
    const value = measured ? (MT_RESULT_TEXT[part.result] || part.result) : 'Not measured';
    return `<span class="mt-chip ${cls}"${title ? ` title="${esc(title)}"` : ''}>${esc(`${label}: ${value}`)}</span>`;
}

function mtTag(text, cls, title) {
    return `<span class="mt-chip ${cls}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span>`;
}

function mtDelay(older, newer) {
    const s = mtSeconds(older, newer);
    if (s === null) return '';
    return s < 60 ? `+${s} s` : s < 3600 ? `+${Math.round(s / 60)} min` : `+${Math.round(s / 3600)} h`;
}

function mtArrow(labelHtml, cls, delay) {
    return `<div class="mt-arrow ${cls || ''}"><span class="mt-arrow-label">${labelHtml || ''}</span>`
        + '<span class="mt-arrow-line" aria-hidden="true"></span>'
        + `<span class="mt-arrow-delay">${esc(delay || '')}</span></div>`;
}

function mtNode(kind, titleHtml, lines, chips, cls) {
    return `<div class="mt-node ${cls || ''}"><div class="mt-node-kind">${esc(kind)}</div>`
        + `<div class="mt-node-title">${titleHtml}</div>`
        + lines.filter(Boolean).map(l => `<div class="mt-node-line">${l}</div>`).join('')
        + (chips.length ? `<div class="mt-chips">${chips.join('')}</div>` : '') + '</div>';
}

function mtFlow(d) {
    const s = d.summary, server = d.server, hops = d.hops, border = d.border;
    // Hops are newest first; the picture runs oldest first.
    const before = (border === null ? hops : hops.filter(h => h.index > border)).slice().reverse();
    const after = border === null ? [] : hops.filter(h => h.index < border).reverse();
    const handover = border === null ? null : hops.find(h => h.index === border);
    const parts = [];

    const signers = d.dkim.signatures.map(sig => mtChip(
        sig.aligned ? `DKIM ${sig.domain || '?'}` : `DKIM ${sig.domain || '?'} (not aligned)`, sig, sig.reason));
    parts.push(mtNode('Sender', `<code>${esc(s.from_domain || '?')}</code>`,
        [esc(s.from), s.return_path ? `<span>Envelope:</span> <code>${esc(s.return_path.split('@').pop())}</code>` : esc('No envelope sender')],
        signers.length ? signers : [mtTag('Not DKIM-signed', 'bad')]));

    // Relays on the sending side: the first two, then how many more.
    let previous = null;
    before.slice(0, 2).forEach(h => {
        parts.push(mtArrow(esc(h.protocol || ''), '', previous ? mtDelay(previous, h) : ''));
        parts.push(mtNode('Relay', `<code>${esc(h.rdns || h.helo || h.by || '—')}</code>`,
            [h.ip ? `<code>${esc(h.ip)}</code>` : ''], [], 'mt-node-small'));
        previous = h;
    });
    if (before.length > 2) {
        parts.push(mtArrow('', '', ''));
        parts.push(mtNode('Relays', esc(`${before.length - 2} more`), [], [], 'mt-node-small'));
        previous = before[before.length - 1];
    }

    if (handover) {
        const ptr = server.ptr_state !== 'measured' ? mtTag('Reverse DNS: not measured', 'na')
            : !server.ptr.length ? mtTag('No reverse DNS', 'bad')
            : server.fcrdns === false ? mtTag('Reverse DNS does not point back', 'warn', server.ptr.join(', '))
            : mtTag('Reverse DNS', 'ok', server.ptr.join(', '));
        const listed = !server.blocklist ? mtTag('Blocklists: not measured', 'na')
            : server.blocklist.listed.length ? mtTag('On a blocklist', 'bad', server.blocklist.listed.join(', '))
            : mtTag('Not listed', 'ok');
        const threat = (server.blocklist || {}).ip_lists;
        const onLists = threat && threat.state === 'listed'
            ? mtTag('On an IP threat list', 'bad', threat.lists.map(l => l.source).join(', ')) : '';
        if (before.length) parts.push(mtArrow('', '', mtDelay(previous, handover)));
        parts.push(mtNode('Sending server', `<code>${esc((server.ptr && server.ptr[0]) || server.helo || '?')}</code>`,
            [`<code>${esc(server.ip || '')}</code>`, server.helo ? `HELO <code>${esc(server.helo)}</code>` : ''],
            [mtChip('SPF', d.spf, d.spf.explanation), ptr, listed, onLists].filter(Boolean), 'mt-node-key'));
        const tls = server.tls === true ? ['ok', server.tls_version || 'TLS'] : server.tls === false ? ['bad', 'No TLS'] : ['na', 'TLS not stated'];
        parts.push(mtArrow(mtTag(tls[1], tls[0], server.cipher || ''), 'mt-arrow-key', ''));
        const said = d.receiver ? Object.entries(d.receiver.methods)
            .filter(([k]) => ['spf', 'dkim', 'dmarc'].includes(k))
            .map(([k, v]) => mtTag(`${k}=${v}`, v === 'pass' ? 'ok' : v === 'fail' ? 'bad' : 'warn', 'As reported by the receiving system'))
            : [];
        parts.push(mtNode('Receiving server', `<code>${esc(handover.by || '?')}</code>`,
            [d.receiver ? `<span>Reported by</span> <code>${esc(d.receiver.authserv_id)}</code>` : ''],
            [mtChip(d.dmarc.policy ? `DMARC p=${d.dmarc.policy}` : 'DMARC', d.dmarc, d.dmarc.explanation)].concat(said),
            'mt-node-key'));
        previous = handover;
    } else {
        parts.push(mtArrow('', 'mt-arrow-unknown', ''));
        parts.push(mtNode('Sending server', esc('Not found'),
            [esc('The headers name no address where the message was handed over.')], [mtTag('SPF: not measured', 'na')]));
    }

    const last = after.length ? after[after.length - 1] : null;
    parts.push(mtArrow('', '', last ? mtDelay(previous, last) : ''));
    const to = (s.to || '').replace(/.*</, '').replace(/>.*/, '');
    parts.push(mtNode('Mailbox', `<code>${esc(to || '?')}</code>`,
        after.length ? [esc(after.length === 1 ? 'Via 1 internal hop' : `Via ${after.length} internal hops`)] : [], []));

    return '<p class="ct-desc">Oldest step first. Each check sits on the step it is about: DKIM with the sender, SPF with the server that handed the message over, TLS on the hand-over, DMARC where it is judged. Green passed, red failed, grey could not be measured.</p>'
        + `<div class="mt-flow">${parts.join('')}</div>`;
}

// ===== Links =====

const MT_FEED_TEXT = { listed: ['On a threat list', 'bad'], host_listed: ['Host has listed links', 'warn'],
                       not_listed: ['Not listed', 'ok'], not_checked: ['Not checked', 'na'] };
const MT_VT_TEXT = { malicious: 'bad', suspicious: 'warn', no_detections: 'ok', unknown: 'na', unmeasured: 'na', not_checked: 'na' };

function mtVtText(v) {
    return v.state === 'malicious' ? `${v.malicious} of ${v.engines} engines: malicious`
        : v.state === 'suspicious' ? `${v.suspicious} of ${v.engines} engines: suspicious`
        : v.state === 'no_detections' ? `Known, no detections (${v.engines} engines)`
        : v.state === 'unknown' ? 'Not known to VirusTotal'
        : v.state === 'unmeasured' ? 'Could not be checked'
        : 'Not checked';
}

function mtLinks(content, checks) {
    if (!content || !content.links.length) return '';
    const flagged = content.links.some(l => l.lookalike || ['listed', 'host_listed'].includes(l.feed)
        || ['malicious', 'suspicious'].includes((l.virustotal || {}).state));
    const how = checks ? [
        checks.own_domains ? `Lookalikes compared with ${checks.own_domains} own domain(s)` : 'No own domains to compare lookalikes with',
        checks.feeds === 'checked' ? 'Threat lists searched on this server' : 'No threat lists configured',
        { on: 'VirusTotal asked by hash only', off: 'VirusTotal off', no_key: 'VirusTotal on, but no API key' }[checks.virustotal] || '',
    ].filter(Boolean).join(' · ') : '';
    return `<details${flagged ? ' open' : ''}><summary>${esc(`Links (${content.links.length})`)}</summary>`
        + (how ? `<p class="ct-desc">${esc(how)}</p>` : '')
        + '<div class="dns-detail-table-wrap"><table class="data-table stack-table"><tr><th>Goes to</th><th>Shown as</th>'
        + '<th>Lookalike</th><th>Threat lists</th><th>VirusTotal</th></tr>'
        + content.links.slice(0, 100).map(l => {
            const feed = MT_FEED_TEXT[l.feed || 'not_checked'] || MT_FEED_TEXT.not_checked;
            const vt = l.virustotal || { state: 'not_checked' };
            return `<tr><td><code title="${esc(l.url || '')}">${esc(l.host)}</code>${l.https ? '' : ' <span class="muted">http</span>'}</td>`
                + `<td>${l.source ? `<span class="muted">${esc(`From ${l.source}`)}</span>` : esc(l.text)}</td>`
                + `<td>${l.lookalike ? mtTag(`Looks like ${l.lookalike}`, 'bad') : '<span class="muted">—</span>'}</td>`
                + `<td>${mtTag(feed[0], feed[1])}</td>`
                + `<td>${mtTag(mtVtText(vt), MT_VT_TEXT[vt.state] || 'na', vt.error || '')}</td></tr>`;
        }).join('') + '</table></div></details>';
}

// ===== Attachments and files =====

const MT_SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];

function mtBytes(n) {
    if (n === null || n === undefined) return '';
    return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

// The worst finding in a file and everything found inside it.
function mtWorst(node) {
    let worst = MT_SEVERITY.length;
    (node.findings || []).forEach(f => { worst = Math.min(worst, MT_SEVERITY.indexOf(f[0])); });
    (node.children || []).forEach(c => { worst = Math.min(worst, mtWorst(c)); });
    return worst;
}

// What the file does, in a chip or two. Three states: read, partly read
// (encrypted, a ceiling reached), not read -- never "clean" for the last.
function mtFileState(node) {
    if (node.state === 'unmeasured') return mtTag('Not read', 'na', node.reason || '');
    const worst = mtWorst(node);
    const count = (node.findings || []).length;
    const chips = [];
    if (worst <= 1) chips.push(mtTag(count ? `${count} finding(s)` : 'Inside: findings', 'bad'));
    else if (worst <= 2) chips.push(mtTag(count ? `${count} finding(s)` : 'Inside: findings', 'warn'));
    else chips.push(mtTag('Nothing active found', 'ok'));
    if ((node.urls || []).length) chips.push(mtTag(`${node.urls.length} link(s)`, 'na'));
    if (node.state === 'partial') chips.push(mtTag('Partly read', 'na', node.reason || ''));
    return chips.join(' ');
}

// Known by its hash? Only the hash was asked, never the file.
function mtReputation(rep) {
    if (!rep) return '<span class="muted">—</span>';
    const mb = rep.malwarebazaar || {}, vt = rep.virustotal || {};
    const chips = [];
    if (mb.state === 'listed') chips.push(mtTag(`MalwareBazaar: ${mb.signature || 'known malware'}`, 'bad'));
    else if (mb.state === 'unknown') chips.push(mtTag('MalwareBazaar: not known', 'ok'));
    else if (mb.state === 'unmeasured') chips.push(mtTag('MalwareBazaar: not checked', 'na', mb.error || ''));
    if (vt.state === 'malicious') chips.push(mtTag(`VirusTotal: ${vt.malicious} of ${vt.engines} engines`, 'bad', vt.label || ''));
    else if (vt.state === 'suspicious') chips.push(mtTag(`VirusTotal: ${vt.suspicious} of ${vt.engines} suspicious`, 'warn'));
    else if (vt.state === 'no_detections') chips.push(mtTag('VirusTotal: no detections', 'ok'));
    else if (vt.state === 'unknown') chips.push(mtTag('VirusTotal: not known', 'na'));
    else if (vt.state === 'unmeasured') chips.push(mtTag('VirusTotal: not checked', 'na', vt.error || ''));
    return chips.join(' ') || '<span class="muted">—</span>';
}

// Source excerpts are shown as text, escaped, never run or linked.
function mtExcerpts(node) {
    const parts = [];
    const macros = node.macros;
    if (macros && macros.excerpt) {
        parts.push(`<details class="mt-excerpt-wrap"><summary>${esc('Macro source (excerpt)')}</summary>`
            + `<pre class="mt-excerpt">${esc(macros.excerpt)}</pre></details>`);
    }
    const js = (node.pdf || {}).js || {};
    (js.excerpts || []).forEach(text => parts.push(`<details class="mt-excerpt-wrap"><summary>${esc('JavaScript (excerpt)')}</summary>`
        + `<pre class="mt-excerpt">${esc(text)}</pre></details>`));
    return parts.join('');
}

function mtFileRows(node, depth) {
    const indent = depth ? `<span class="muted" aria-hidden="true">${'↳ '.repeat(1)}</span>` : '';
    // Searches by hash, which uploads nothing. The title says why the file
    // itself must not go there: an upload is visible to the service's users.
    const warn = 'Searches by hash; nothing is uploaded. Do not upload the file there yourself: an uploaded file can be seen and downloaded by others.';
    const hash = node.sha256
        ? `<div class="mt-hash"><code title="SHA-256 ${esc(node.sha256)}">${esc(node.sha256.slice(0, 16))}…</code> `
          + `<a href="https://www.virustotal.com/gui/file/${esc(node.sha256)}" target="_blank" rel="noopener noreferrer" title="${esc(warn)}">VirusTotal</a> · `
          + `<a href="https://bazaar.abuse.ch/sample/${esc(node.sha256)}/" target="_blank" rel="noopener noreferrer" title="${esc(warn)}">MalwareBazaar</a></div>`
        : '';
    const row = `<tr><td style="padding-left:${0.5 + depth * 1.1}rem">${indent}${esc(node.name)}${hash}${mtExcerpts(node)}</td>`
        + `<td>${esc(node.type_label || '')}<div class="muted">${esc(mtBytes(node.size))}</div></td>`
        + `<td>${mtFileState(node)}</td><td>${mtReputation(node.reputation)}</td></tr>`;
    return row + (node.children || []).map(c => mtFileRows(c, depth + 1)).join('');
}

function mtAttachments(list, checked) {
    const note = checked === 'checked' ? '' : `<p class="ct-desc">${esc('Hashes are not looked up: set an abuse.ch Auth-Key for MalwareBazaar, or switch VirusTotal on for the mail analysis.')}</p>`;
    return '<h4>Attachments</h4>'
        + `<p class="ct-desc">${esc('Read as data in a separate process with no network: nothing was opened or run. Only hashes leave this server.')}</p>`
        + note
        + `<p class="ct-desc mt-privacy">${esc('The content of a file is never sent anywhere. The VirusTotal and MalwareBazaar links search by hash; do not upload a file with customer data to them yourself, as an uploaded file can be seen and downloaded by others.')}</p>`
        + '<div class="dns-detail-table-wrap"><table class="data-table stack-table">'
        + '<tr><th>File</th><th>Type</th><th>What it does</th><th>Known as</th></tr>'
        + list.map(a => a.scan ? mtFileRows(a.scan, 0)
            : `<tr><td>${esc(a.name)}</td><td><code>${esc(a.type)}</code></td><td><span class="muted">${esc('Name and type only')}</span></td><td></td></tr>`).join('')
        + '</table></div>';
}

// A file on its own: what it does when opened, what is inside, its
// findings and its links.
function mtRenderFile(d) {
    const content = d.content || {};
    $('mailTestResult').innerHTML =
        `<section class="card"><h3>${esc(d.file.name)}</h3>${mtAttachments(content.attachments || [d.file], content.reputation)}</section>`
        + `<section class="card"><h3>Findings</h3>${mtFindings(d.findings)}</section>`
        + ((content.links || []).length ? `<section class="card">${mtLinks(content, d.link_checks)}</section>` : '');
    const links = $('mailTestResult').querySelector('details:not(.mt-excerpt-wrap)');
    if (links) links.open = true;
}

function mtRender(d) {
    if (d.kind === 'file') { mtRenderFile(d); return; }
    const s = d.summary, spf = d.spf, dmarc = d.dmarc, server = d.server;
    const sourceNote = {
        'received-spf': 'Sending address from the receiver\'s Received-SPF header.',
        received: 'Sending address read from the Received chain.',
        chosen: 'Sending address chosen by you.',
    }[d.border_source] || '';
    const verdicts = '<div class="mgmt-kpis">'
        + mtVerdict('SPF', spf, spf.ip ? `Checked ${spf.ip} for ${spf.domain || '?'}` : 'No sending address found')
        + mtVerdict('DKIM', mtDkimPart(d.dkim), mtDkimWhy(d.dkim, s, d.origin))
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
        ['IP threat lists', mtIpLists(server.blocklist && server.blocklist.ip_lists)],
    ]);
    const content = d.content;
    const links = mtLinks(content, d.link_checks);
    const attachments = content && content.attachments.length ? mtAttachments(content.attachments, content.reputation) : '';
    const learned = d.learned.length
        ? '<p class="ct-desc">' + d.learned.map(x => esc(`DKIM selector ${x.selector} of ${x.domain} is remembered: scans of that domain now check it.`)).join('<br>') + '</p>'
        : '';

    // An Outlook file: what it kept, and what that leaves out.
    const msgNote = d.msg
        ? `<p class="ct-desc">${esc(d.msg.headers
            ? 'Read from an Outlook .msg file: the received headers as Outlook kept them, the body rebuilt from it.'
            : 'Read from an Outlook .msg file without received headers (a sent item or a draft): the sending server and SPF cannot be judged.')}</p>`
        : '';
    $('mailTestResult').innerHTML =
        `<section class="card"><h3>Verdict</h3>${verdicts}<p class="ct-desc">${esc(sourceNote)}</p>${msgNote}${learned}</section>`
        + `<section class="card"><h3>Mail flow</h3>${mtFlow(d)}</section>`
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

function mtAgo(iso) {
    const t = Date.parse(iso);
    if (isNaN(t)) return '';
    const h = Math.round((Date.now() - t) / 3600000);
    return h < 1 ? 'less than an hour ago' : h === 1 ? '1 hour ago' : `${h} hours ago`;
}

// How the links of a message will be checked here, before one is analysed.
async function mtLoadChecks() {
    let c;
    try { c = await requestJson('/api/mailtest/checks'); } catch (err) { return; }
    const loaded = c.feeds.filter(f => f.entries !== null && f.entries !== undefined);
    const feeds = !c.feeds.length ? 'no threat lists configured'
        : `${c.feeds.length} threat list(s), ${loaded.reduce((n, f) => n + f.entries, 0)} links`
          + (loaded.length ? `, refreshed ${mtAgo(loaded.map(f => f.refreshed_at).sort()[0])}` : ', not downloaded yet')
          + (c.feeds.some(f => f.error) ? ' (a download failed)' : '');
    const vt = { on: 'VirusTotal by hash only', off: 'VirusTotal off', no_key: 'VirusTotal on, but no API key' }[c.virustotal] || '';
    $('mailTestChecks').textContent = `Links are checked on this server: lookalikes of ${c.own_domains} own domain(s) · ${feeds} · ${vt}. Links are never opened.`;
    const btn = $('mailTestFeedsRefresh');
    if (btn) btn.classList.toggle('hidden', !c.feeds.length);
}

function initMailTest() {
    if (!$('mailTestBtn')) return;
    mtLoadChecks();
    const refresh = $('mailTestFeedsRefresh');
    if (refresh) {
        refresh.addEventListener('click', async () => {
            refresh.disabled = true;
            try {
                await requestJson('/api/mailtest/feeds/refresh', { method: 'POST' });
                toast('Downloading the threat lists. This can take a minute.');
                setTimeout(mtLoadChecks, 15000);
            } catch (err) { toast(err.message); }
            refresh.disabled = false;
        });
    }
    $('mailTestBtn').addEventListener('click', () => {
        const file = $('mailTestFile').files[0];
        const text = $('mailTestSource').value;
        if (!file && !text.trim()) { toast('Paste the message source or choose an .eml, .msg or PDF file.'); return; }
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

// ===== Tabs: a message or file, and links on their own =====

function mtShowTab(name) {
    document.querySelectorAll('[data-mt-tab]').forEach(btn => {
        const on = btn.dataset.mtTab === name;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('[data-mt-panel]').forEach(p => p.classList.toggle('hidden', p.dataset.mtPanel !== name));
}

function initMailTabs() {
    const tabs = document.querySelectorAll('[data-mt-tab]');
    if (!tabs.length) return;
    tabs.forEach(btn => btn.addEventListener('click', () => {
        mtShowTab(btn.dataset.mtTab);
        // #links is a link to the tab, kept in the address for sharing.
        history.replaceState(null, '', btn.dataset.mtTab === 'links' ? '#links' : location.pathname + location.search);
    }));
    if (location.hash === '#links') mtShowTab('links');
}

// ===== Links on their own (url_check.py): judged, never opened =====

function lcVerdict(link) {
    const worst = link.worst;
    if (worst === 'critical' || worst === 'high') return mtTag('Dangerous signs', 'bad');
    if (worst === 'medium') return mtTag('Suspicious signs', 'warn');
    if (worst === 'low' || worst === 'info') return mtTag('Remarks only', 'na');
    return mtTag('Nothing found', 'ok', 'Nothing found is not proof that a link is safe.');
}

function lcDate(iso) {
    return iso ? String(iso).slice(0, 10) : '';
}

function lcRows(link) {
    const c = link.checks || {};
    const look = c.lookalike || {};
    const feeds = c.feeds || {};
    const vt = c.virustotal || {};
    const reg = c.registration;
    const dns = c.dns;
    const rep = c.reputation;
    const repResult = rep && rep.result;
    const repText = !rep ? '' : !repResult ? 'Not measured'
        : repResult.is_listed ? `Listed on ${(repResult.listed || []).join(', ')}`
        : ((repResult.ip_lists || {}).lists || []).length ? `On ${(repResult.ip_lists.lists || []).map(e => e.source).join(', ')}`
        : repResult.measured === 0 ? 'Not measured: no blocklist could be asked' : 'Not listed';
    // A look-alike name shown as read and as it really is.
    const domain = link.registrable && link.registrable_unicode && link.registrable_unicode !== link.registrable
        ? `${link.registrable_unicode} (${link.registrable})` : (link.registrable || link.ip || '');
    return rows([
        ['Domain', domain],
        ['Imitates your domain', !link.host ? '' : look.state === 'not_configured' ? 'No own domains to compare with'
            : look.imitates ? `Looks like ${look.imitates}` : 'No'],
        ['Threat lists', !link.host ? '' : { listed: 'On a threat list', host_listed: 'Host has listed links',
            not_listed: 'Not listed', not_configured: 'No threat lists configured' }[feeds.state] || ''],
        ['VirusTotal', !link.host ? '' : vt.state === 'off' ? 'VirusTotal off' : mtVtText(vt)],
        // The registrar in a row of its own: a name joined to the date with
        // " · " kept the whole line from being translated.
        ['Registered', !reg ? '' : reg.state === 'measured'
            ? `${lcDate(reg.registered)} (${reg.age_days} days ago)`
            : reg.state === 'not_registered' ? 'Not registered'
            : reg.state === 'no_date' ? 'Registered; the registry gives no date'
            : reg.state === 'not_applicable' ? 'This registry does not publish registration dates (no RDAP)' : 'Not measured'],
        ['Registrar', reg && reg.registrar ? reg.registrar : ''],
        ['Address', !dns ? '' : dns.state === 'measured' ? (dns.addresses || []).join(', ') || 'None'
            : dns.state === 'nxdomain' ? 'The host does not exist' : 'Not measured'],
        ['Address reputation', repText],
    ]);
}

function lcRender(d) {
    const how = [
        d.own_domains ? `Lookalikes compared with ${d.own_domains} own domain(s)` : 'No own domains to compare lookalikes with',
        d.feeds === 'checked' ? 'Threat lists searched on this server' : 'No threat lists configured',
        { on: 'VirusTotal asked by hash only', off: 'VirusTotal off', no_key: 'VirusTotal on, but no API key' }[d.virustotal] || '',
    ].filter(Boolean).join(' · ');
    $('linkCheckResult').innerHTML =
        `<p class="ct-desc">${esc(how)}</p>`
        + (d.skipped ? `<p class="ct-desc">${esc(`${d.skipped} more link(s) were not checked: up to ten at a time.`)}</p>` : '')
        + d.links.map(link => `<section class="card lc-link">`
            + `<div class="lc-head"><h3><code>${esc(link.host_unicode || link.host || link.url)}</code></h3>${lcVerdict(link)}</div>`
            + `<p class="mt-hash"><code>${esc(link.url)}</code></p>`
            + lcRows(link)
            + (link.findings.length ? `<h4>Findings</h4>${mtFindings(link.findings)}` : '')
            + '</section>').join('');
}

function initLinkCheck() {
    const btn = $('linkCheckBtn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        const text = $('linkCheckInput').value;
        if (!text.trim()) { toast('Paste one or more links.'); return; }
        btn.disabled = true;
        $('linkCheckResult').innerHTML = '<p class="history-empty">Checking…</p>';
        try {
            lcRender(await requestJson('/api/linkcheck', { method: 'POST',
                headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) }));
        } catch (err) {
            $('linkCheckResult').innerHTML = '';
            toast(err.message);
        }
        btn.disabled = false;
    });
    $('linkCheckClear').addEventListener('click', () => {
        $('linkCheckInput').value = '';
        $('linkCheckResult').innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initMailTabs();
    initMailTest();
    initLinkCheck();
});
