// Minimal bootstrap for pages whose only client-side need is translations.
// Kept as an external file because the app serves a strict CSP
// (script-src 'self', no 'unsafe-inline'), so inline <script> is blocked.
(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', () => {
        try {
            DomainLensI18n.init(DomainLensI18n.pageLocale());
        } catch (e) {
            console.error('i18n init failed', e);
        }
    });
})();
