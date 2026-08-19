/* Theme switching.
 *
 * The server already rendered `data-theme` on <html>, so this file never
 * decides what the page looks like on load — it only changes it afterwards.
 * That split is deliberate: the CSP (`script-src 'self'`, no 'unsafe-inline')
 * rules out the inline <head> bootstrap that would otherwise set the
 * attribute before first paint, so doing it here would guarantee a flash of
 * the wrong palette on every navigation.
 *
 * The attribute is applied immediately and the preference is persisted in the
 * background. A theme switch that waits for a round trip feels broken, and a
 * failed save is worth reporting but not worth undoing the switch over — the
 * cookie is written by the same request, so the next page load is what
 * actually depends on it.
 */
(function () {
    'use strict';

    var THEMES = ['auto', 'light', 'dark'];

    function root() {
        return document.documentElement;
    }

    function current() {
        var attr = root().getAttribute('data-theme');
        return THEMES.indexOf(attr) > 0 ? attr : 'auto';
    }

    function apply(theme) {
        if (theme === 'auto') {
            // Removing it, not setting "auto": the absence is what hands the
            // decision back to prefers-color-scheme.
            root().removeAttribute('data-theme');
        } else {
            root().setAttribute('data-theme', theme);
        }
        reflect(theme);
    }

    function reflect(theme) {
        document.querySelectorAll('[data-theme-option]').forEach(function (el) {
            var mine = el.getAttribute('data-theme-option') === theme;
            el.classList.toggle('current', mine);
            el.setAttribute('aria-checked', mine ? 'true' : 'false');
        });
        var label = document.getElementById('themeMenuLabel');
        if (label) { label.setAttribute('data-theme-current', theme); }
    }

    function persist(body) {
        return fetch('/api/preferences/appearance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        }).then(function (resp) {
            if (!resp.ok) {
                return resp.json().catch(function () { return {}; }).then(function (data) {
                    // Named rather than swallowed: "Appearance is set centrally
                    // on this instance" is a real answer, and a switch that
                    // silently reverts on the next page load is a bug report.
                    console.warn('appearance not saved:', data.error || resp.status);
                });
            }
        }).catch(function (err) {
            console.warn('appearance not saved:', err);
        });
    }

    function choose(theme) {
        if (THEMES.indexOf(theme) < 0) { return; }
        apply(theme);
        persist({ theme: theme });
    }

    function chooseAccent(hex) {
        if (!/^#[0-9a-fA-F]{6}$/.test(hex)) { return; }
        persist({ accent: hex }).then(function () {
            // The accent reaches the page through an inline style the server
            // writes on <html>, so it is applied by reloading rather than
            // rebuilt here in a second, drifting implementation.
            window.location.reload();
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        reflect(current());

        document.querySelectorAll('[data-theme-option]').forEach(function (el) {
            el.addEventListener('click', function (event) {
                event.preventDefault();
                choose(el.getAttribute('data-theme-option'));
            });
        });

        var accent = document.getElementById('accentPicker');
        if (accent) {
            accent.addEventListener('change', function () {
                chooseAccent(accent.value);
            });
        }

        var reset = document.getElementById('accentReset');
        if (reset) {
            reset.addEventListener('click', function (event) {
                event.preventDefault();
                chooseAccent('#5b8def');
            });
        }
    });
})();
