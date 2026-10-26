// Help: the manual (static/help/handleiding.md) as a page, with a table of
// contents. One Markdown file is the source, so the same text reads on GitHub
// and here. Only the Markdown the manual uses is understood -- headings,
// paragraphs, lists, tables, quotes, bold, italic, code and links -- and all
// text is escaped first: the file is ours, but nothing in it can add markup.

function hlEsc(value) {
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function hlSlug(text, used) {
    let slug = text.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'sectie';
    const base = slug;
    let n = 2;
    while (used.has(slug)) slug = `${base}-${n++}`;
    used.add(slug);
    return slug;
}

// Inline markup on escaped text. A link goes to a page of this app (/...),
// a place in the manual (#...) or a web address; anything else stays text.
function hlInline(text) {
    const codes = [];
    let out = hlEsc(text).replace(/`([^`]+)`/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
    out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, href) => {
            const url = href.replace(/&amp;/g, '&');
            if (!/^(\/(?!\/)|#|https?:\/\/)/.test(url)) return label;
            const external = /^https?:/.test(url) ? ' target="_blank" rel="noopener noreferrer"' : '';
            return `<a href="${hlEsc(url)}"${external}>${label}</a>`;
        });
    return out.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${codes[Number(i)]}</code>`);
}

function hlRender(markdown) {
    const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
    const html = [];
    const toc = [];
    const used = new Set();
    let i = 0;
    const isTableRow = l => /^\s*\|.*\|\s*$/.test(l);
    const cells = l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
    while (i < lines.length) {
        const line = lines[i];
        if (!line.trim()) { i++; continue; }
        const heading = line.match(/^(#{1,4})\s+(.*)$/);
        if (heading) {
            const level = heading[1].length;
            const text = heading[2].trim();
            const id = hlSlug(text, used);
            if (level === 2 || level === 3) toc.push({ level, id, text });
            html.push(`<h${level} id="${id}">${hlInline(text)}</h${level}>`);
            i++;
            continue;
        }
        if (/^---+\s*$/.test(line)) { html.push('<hr>'); i++; continue; }
        if (isTableRow(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
            const head = cells(line);
            i += 2;
            const body = [];
            while (i < lines.length && isTableRow(lines[i])) body.push(cells(lines[i++]));
            html.push('<div class="table-scroll"><table class="data-table help-table"><thead><tr>'
                + head.map(c => `<th>${hlInline(c)}</th>`).join('') + '</tr></thead><tbody>'
                + body.map(r => '<tr>' + r.map(c => `<td>${hlInline(c)}</td>`).join('') + '</tr>').join('')
                + '</tbody></table></div>');
            continue;
        }
        if (/^\s*>\s?/.test(line)) {
            const quote = [];
            while (i < lines.length && /^\s*>\s?/.test(lines[i])) quote.push(lines[i++].replace(/^\s*>\s?/, ''));
            html.push(`<aside class="help-tip">${hlInline(quote.join(' '))}</aside>`);
            continue;
        }
        const bullet = /^\s*[-*]\s+/;
        const number = /^\s*\d+[.)]\s+/;
        if (bullet.test(line) || number.test(line)) {
            const ordered = number.test(line);
            const marker = ordered ? number : bullet;
            const items = [];
            while (i < lines.length && (marker.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
                if (marker.test(lines[i])) items.push(lines[i].replace(marker, ''));
                else items[items.length - 1] += ' ' + lines[i].trim();
                i++;
            }
            const tag = ordered ? 'ol' : 'ul';
            html.push(`<${tag}>` + items.map(t => `<li>${hlInline(t)}</li>`).join('') + `</${tag}>`);
            continue;
        }
        const para = [];
        while (i < lines.length && lines[i].trim() && !/^(#{1,4})\s/.test(lines[i]) && !isTableRow(lines[i])
               && !bullet.test(lines[i]) && !number.test(lines[i]) && !/^\s*>/.test(lines[i])) {
            para.push(lines[i++].trim());
        }
        html.push(`<p>${hlInline(para.join(' '))}</p>`);
    }
    return { html: html.join('\n'), toc };
}

function hlToc(toc) {
    return '<ol class="help-toc-list">' + toc.map(t =>
        `<li class="help-toc-${t.level}"><a href="#${t.id}">${hlEsc(t.text)}</a></li>`).join('') + '</ol>';
}

async function initHelp() {
    const body = document.getElementById('helpBody');
    if (!body) return;
    try {
        const resp = await fetch(body.dataset.src);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const { html, toc } = hlRender(await resp.text());
        body.innerHTML = html;
        document.getElementById('helpToc').innerHTML = hlToc(toc);
        // Filter the contents: type a word, keep the sections that name it.
        const filter = document.getElementById('helpFilter');
        filter.addEventListener('input', () => {
            const q = filter.value.trim().toLowerCase();
            document.querySelectorAll('#helpToc li').forEach(li => {
                const id = li.querySelector('a').getAttribute('href').slice(1);
                const start = document.getElementById(id);
                let text = start.textContent;
                for (let el = start.nextElementSibling; el && !/^H[23]$/.test(el.tagName); el = el.nextElementSibling) {
                    text += ' ' + el.textContent;
                }
                li.classList.toggle('hidden', !!q && !text.toLowerCase().includes(q));
            });
        });
        if (location.hash) {
            const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
            if (target) target.scrollIntoView();
        }
    } catch (err) {
        body.innerHTML = `<p class="status status-fail">${hlEsc(`The manual could not be loaded (${err.message}).`)}</p>`;
    }
}

if (typeof module !== 'undefined') module.exports = { hlRender, hlInline };
else document.addEventListener('DOMContentLoaded', initHelp);
