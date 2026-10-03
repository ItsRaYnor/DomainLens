// Dutch for everything the browser shows, looked up by its English text.
//
// Most of the interface is written in English in the templates and in the
// scripts that build tables, toasts and findings. Rewriting each of those
// thousands of strings into key lookups would touch nearly every line, so
// the translation is applied to the page instead: a catalogue maps English
// text to Dutch (i18n/nl_ui/*.json), and this script applies it to the
// document and to everything scripts add later. Three kinds of entry:
//   text     - a text node, an attribute (placeholder, title, aria-label)
//   blocks   - an element whose text runs through inline markup (a sentence
//              with a link or <strong> in it), keyed by its plain text and
//              replaced by Dutch HTML with the same markup
//   patterns - text with numbers or names in it, as a regular expression;
//              each captured part is translated in turn where it can be
// Text the catalogue does not know stays as it is: English, never empty.
// Code, data and anything marked translate="no" is left alone.
(function () {
    const root = document.documentElement;
    if ((root.getAttribute('lang') || '').slice(0, 2).toLowerCase() !== 'nl') return;

    // Hide the page for the moment the catalogue takes to load, so it does
    // not flash English. Never longer: an unreachable catalogue shows English.
    root.classList.add('i18n-pending');
    const reveal = () => root.classList.remove('i18n-pending');
    const failSafe = setTimeout(reveal, 1500);

    const SKIP = new Set(['SCRIPT', 'STYLE', 'CODE', 'PRE', 'TEXTAREA', 'KBD', 'SAMP', 'NOSCRIPT']);
    const INLINE = new Set(['A', 'STRONG', 'EM', 'B', 'I', 'CODE', 'SPAN', 'BR', 'SMALL', 'ABBR', 'KBD', 'SUP', 'SUB']);
    const ATTRS = ['placeholder', 'title', 'aria-label', 'alt'];
    const norm = s => String(s).replace(/\s+/g, ' ').trim();

    let text = null, blocks = null, patterns = [];

    function translate(value) {
        const key = norm(value);
        if (!key || !/[A-Za-z]/.test(key)) return null;
        if (text.has(key)) return text.get(key);
        // Several sentences: sentence by sentence first, so a pattern ending
        // in "{}." cannot swallow the sentences after it.
        const split = sentences(key);
        if (split !== null) return split;
        for (const [re, rep] of patterns) {
            const m = key.match(re);
            if (m) {
                const out = rep.replace(/\$(\d)/g, (_, i) => {
                    const part = m[Number(i)] || '';
                    const inner = /[A-Za-z]{2}/.test(part) && part !== key ? translate(part) : null;
                    return inner === null ? part : inner;
                });
                // Unchanged is not translated: try the next way in.
                if (out !== key) return out;
            }
        }
        // "4 domains · 2 at risk": each part on its own.
        for (const sep of [' · ', ' — ', ' | ']) {
            if (key.includes(sep)) {
                const parts = key.split(sep).map(p => translate(p) ?? (/[a-z]{3}/.test(p) ? null : p));
                if (parts.every(p => p !== null)) return parts.join(sep);
            }
        }
        return null;
    }

    // Advice merged from two findings is two known texts in a row. Split at
    // a sentence end where the first part is known as a whole and the rest
    // can be translated in turn.
    function sentences(key) {
        if (key.length < 40) return null;
        const re = /[.!?:)`] (?=[A-Z0-9`(*])/g;
        let m;
        while ((m = re.exec(key)) !== null) {
            const cut = m.index + 1;
            const head = key.slice(0, cut), tail = key.slice(cut + 1);
            const first = whole(head);
            if (first === null) continue;
            const rest = translate(tail);
            if (rest !== null) return first + ' ' + rest;
        }
        return null;
    }

    // A text or pattern for exactly this, without splitting it further.
    function whole(key) {
        if (text.has(key)) return text.get(key);
        for (const [re, rep] of patterns) {
            const m = key.match(re);
            if (m) {
                return rep.replace(/\$(\d)/g, (_, i) => {
                    const part = m[Number(i)] || '';
                    const inner = /[A-Za-z]{2}/.test(part) && part !== key ? whole(part) : null;
                    return inner === null ? part : inner;
                });
            }
        }
        return null;
    }

    function skipped(node) {
        for (let el = node.nodeType === 1 ? node : node.parentElement; el; el = el.parentElement) {
            if (SKIP.has(el.tagName) || el.getAttribute('translate') === 'no' || el.isContentEditable) return true;
        }
        return false;
    }

    function doText(node) {
        const value = node.nodeValue;
        if (!value || !/[A-Za-z]/.test(value)) return;
        const out = translate(value);
        if (out === null || out === norm(value)) return;
        const lead = value.match(/^\s*/)[0], trail = value.match(/\s*$/)[0];
        node.nodeValue = lead + out + trail;
    }

    function doAttrs(el) {
        for (const name of ATTRS) {
            const value = el.getAttribute(name);
            if (!value) continue;
            const out = translate(value);
            if (out !== null && out !== value) el.setAttribute(name, out);
        }
        if (el.tagName === 'INPUT' && /^(button|submit|reset)$/i.test(el.type) && el.value) {
            const out = translate(el.value);
            if (out !== null && out !== el.value) el.value = out;
        }
    }

    function doBlock(el) {
        if (!el.firstElementChild || el.firstElementChild === null) return false;
        for (const child of el.children) if (!INLINE.has(child.tagName)) return false;
        const content = el.textContent;
        if (content.length > 1500) return false;
        const out = blocks.get(norm(content));
        if (out === undefined) return false;
        el.innerHTML = out;
        return true;
    }

    function walk(start) {
        if (start.nodeType === 3) { if (!skipped(start)) doText(start); return; }
        if (start.nodeType !== 1 || skipped(start)) return;
        const elements = [start, ...start.querySelectorAll('*')];
        const done = new Set();
        for (const el of elements) {
            if (SKIP.has(el.tagName) || el.getAttribute('translate') === 'no') continue;
            let inside = false;
            for (let p = el.parentElement; p && p !== start.parentElement; p = p.parentElement) {
                if (done.has(p)) { inside = true; break; }
            }
            if (inside) continue;
            doAttrs(el);
            if (doBlock(el)) done.add(el);
        }
        const walker = document.createTreeWalker(start, NodeFilter.SHOW_TEXT, {
            acceptNode: n => (skipped(n) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
        });
        const nodes = [];
        while (walker.nextNode()) nodes.push(walker.currentNode);
        nodes.forEach(doText);
    }

    function observe() {
        const queue = new Set();
        let scheduled = false;
        const flush = () => {
            scheduled = false;
            const items = [...queue];
            queue.clear();
            items.forEach(n => { if (n.isConnected) walk(n); });
        };
        new MutationObserver(records => {
            for (const r of records) {
                // The element itself, not only what was added: a sentence set
                // through innerHTML is a block only seen from its parent.
                if (r.type === 'childList') queue.add(r.target);
                else if (r.type === 'characterData') queue.add(r.target);
                else if (r.type === 'attributes') queue.add(r.target);
            }
            if (!scheduled) { scheduled = true; requestAnimationFrame(flush); }
        }).observe(document.body, { childList: true, subtree: true, characterData: true,
            attributes: true, attributeFilter: ATTRS });
    }

    function wrapDialogs() {
        for (const name of ['alert', 'confirm', 'prompt']) {
            const original = window[name].bind(window);
            window[name] = (message, ...rest) => original(translate(message) ?? message, ...rest);
        }
    }

    function start(catalogue) {
        text = new Map(Object.entries(catalogue.text || {}));
        blocks = new Map(Object.entries(catalogue.blocks || {}));
        patterns = (catalogue.patterns || []).map(([re, rep]) => [new RegExp('^' + re + '$'), rep]);
        const title = translate(document.title);
        if (title) document.title = title;
        walk(document.body);
        observe();
        wrapDialogs();
        // For finding gaps: the text on this page the catalogue does not know.
        window.DomainLensUntranslated = () => {
            const dutch = new Set([...text.values()].map(norm));
            const out = new Set();
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            while (walker.nextNode()) {
                const n = walker.currentNode;
                if (skipped(n) || !n.parentElement || n.parentElement.closest('.hidden')) continue;
                const v = norm(n.nodeValue);
                if (/[A-Za-z]{3}/.test(v) && !dutch.has(v) && translate(v) === null) out.add(v);
            }
            document.querySelectorAll('[placeholder],[title],[aria-label]').forEach(el => ATTRS.forEach(a => {
                const v = el.getAttribute(a);
                if (v && /[A-Za-z]{3}/.test(v) && translate(v) === null) out.add('@' + a + ': ' + v);
            }));
            return [...out];
        };
        clearTimeout(failSafe);
        reveal();
    }

    const src = (document.currentScript && document.currentScript.src) || '';
    const token = (src.match(/[?&]v=([^&]+)/) || [])[1] || '';
    // Fetched at once, applied when the page is parsed: this script sits near
    // the top of the body, before the content it translates.
    const parsed = document.readyState === 'loading'
        ? new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve))
        : Promise.resolve();
    fetch('/i18n/nl-ui.json?v=' + encodeURIComponent(token))
        .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
        .then(catalogue => parsed.then(() => start(catalogue)))
        .catch(() => { clearTimeout(failSafe); reveal(); });
})();
