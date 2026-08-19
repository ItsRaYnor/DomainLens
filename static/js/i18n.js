(function (global) {
    'use strict';

    const SUPPORTED = ['en', 'nl'];
    const DEFAULT_LOCALE = 'en';

    const DomainLensI18n = {
        locale: DEFAULT_LOCALE,
        strings: {},
        ready: false,

        async init(locale) {
            const loc = SUPPORTED.includes(locale) ? locale : DEFAULT_LOCALE;
            this.locale = loc;
            try {
                const resp = await fetch('/api/i18n/' + encodeURIComponent(loc) + '.json');
                if (resp.ok) {
                    this.strings = await resp.json();
                }
            } catch (e) {
                console.warn('i18n load failed', e);
            }
            this.ready = true;
            document.documentElement.lang = loc;
            this.applyDataI18n();
            return this;
        },

        t(key, vars) {
            const parts = String(key || '').split('.');
            let cur = this.strings;
            for (const p of parts) {
                if (!cur || typeof cur !== 'object' || !(p in cur)) {
                    return key;
                }
                cur = cur[p];
            }
            let text = typeof cur === 'string' ? cur : key;
            if (vars && typeof text === 'string') {
                Object.keys(vars).forEach(k => {
                    text = text.replace(new RegExp('\\{' + k + '\\}', 'g'), String(vars[k]));
                });
            }
            return text;
        },

        applyDataI18n(root) {
            const scope = root || document;
            scope.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                const attr = el.getAttribute('data-i18n-attr');
                const text = this.t(key);
                if (attr) {
                    el.setAttribute(attr, text);
                } else {
                    el.textContent = text;
                }
            });
        },
    };

    // Page data is delivered in <script type="application/json"> blocks
    // rather than inline executable script, because the app serves a strict
    // Content-Security-Policy (script-src 'self', no 'unsafe-inline') which
    // blocks inline <script>. A JSON block is a data block, not executable,
    // so CSP allows it.
    DomainLensI18n.pageData = function (id, fallback) {
        try {
            const el = document.getElementById(id);
            if (!el) return fallback;
            return JSON.parse(el.textContent);
        } catch (e) {
            console.warn('pageData parse failed for #' + id, e);
            return fallback;
        }
    };

    DomainLensI18n.pageLocale = function () {
        return DomainLensI18n.pageData('pageLocale', null) || 'en';
    };

    global.DomainLensI18n = DomainLensI18n;
    global.t = function (key, vars) { return DomainLensI18n.t(key, vars); };
})(window);
