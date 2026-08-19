(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    function escapeHtml(str) {
        return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function fieldValueToInput(value, type) {
        if (type === 'lines') {
            return Array.isArray(value) ? value.join('\n') : '';
        }
        if (type === 'json') {
            return JSON.stringify(value ?? {}, null, 2);
        }
        if (type === 'bool') {
            return !!value;
        }
        return value ?? '';
    }

    function inputToFieldValue(raw, type) {
        if (type === 'lines') {
            return String(raw || '').split('\n').map(s => s.trim()).filter(Boolean);
        }
        if (type === 'json') {
            return JSON.parse(String(raw || '{}'));
        }
        if (type === 'bool') {
            return !!raw;
        }
        if (type === 'int') {
            return parseInt(raw, 10);
        }
        if (type === 'float') {
            return parseFloat(raw);
        }
        return raw;
    }

    function fieldId(section, key) {
        return `field-${section}-${String(key).replace(/\./g, '-')}`;
    }

    function renderField(section, key, meta) {
        const id = fieldId(section, key);
        const label = t(meta.label || key);
        const locked = meta.locked;
        const type = meta.type || 'text';
        let control = '';

        if (type === 'bool') {
            control = `<label class="settings-check"><input type="checkbox" id="${id}" ${meta.value ? 'checked' : ''} ${locked ? 'disabled' : ''}> ${escapeHtml(label)}</label>`;
        } else if (type === 'select') {
            const opts = (meta.options || []).map(o =>
                `<option value="${escapeHtml(o)}" ${o === meta.value ? 'selected' : ''}>${escapeHtml(o)}</option>`
            ).join('');
            control = `<label>${escapeHtml(label)}<select id="${id}" ${locked ? 'disabled' : ''}>${opts}</select></label>`;
        } else if (type === 'color') {
            // A native colour input, so the value can only ever be a hex
            // colour. The server refuses anything else regardless — this
            // just means nobody has to type one correctly.
            control = `<label class="accent-row">${escapeHtml(label)}<input type="color" id="${id}" value="${escapeHtml(meta.value || '#5b8def')}" ${locked ? 'disabled' : ''}></label>`;
        } else if (type === 'lines' || type === 'json') {
            const rows = type === 'json' ? 8 : 5;
            control = `<label>${escapeHtml(label)}<textarea id="${id}" rows="${rows}" ${locked ? 'disabled' : ''}>${escapeHtml(fieldValueToInput(meta.value, type))}</textarea></label>`;
        } else {
            control = `<label>${escapeHtml(label)}<input type="${type === 'int' || type === 'float' ? 'number' : 'text'}" id="${id}" value="${escapeHtml(meta.value)}" ${locked ? 'disabled' : ''}></label>`;
        }

        const lockNote = locked ? `<p class="muted settings-locked">${escapeHtml(t('settings.env_locked'))}</p>` : '';
        const warn = meta.warning ? `<p class="login-hint">${escapeHtml(t(meta.warning))}</p>` : '';
        return `<div class="settings-field" data-section="${escapeHtml(section)}" data-key="${escapeHtml(key)}" data-type="${escapeHtml(type)}">${warn}${control}${lockNote}</div>`;
    }

    function collectSection(section, fields) {
        const patch = {};
        Object.keys(fields).forEach(key => {
            const meta = fields[key];
            if (meta.locked) return;
            const id = fieldId(section, key);
            const el = $(id);
            if (!el) return;
            let raw;
            if (meta.type === 'bool') {
                raw = el.checked;
            } else {
                raw = el.value;
            }
            patch[key] = inputToFieldValue(raw, meta.type);
        });
        return patch;
    }

    async function saveSection(section, fields) {
        const patch = collectSection(section, fields);
        const resp = await fetch('/api/admin/settings/' + encodeURIComponent(section), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(patch),
        });
        const data = await resp.json();
        if (!resp.ok) {
            throw new Error(data.error || t('common.error'));
        }
        return data;
    }

    // --- Optional API keys -------------------------------------------------
    // Write-only: the page can send a key but never receives one back, so a
    // stored key cannot be recovered through the admin HTML or via XSS.
    function initApiKeys() {
        const lists = ['apiKeyList', 'credentialList'].map($).filter(Boolean);
        if (!lists.length) return;
        const msg = $('apiKeysMsg');

        function notify(text, ok) {
            if (!msg) return;
            msg.textContent = text;
            msg.className = ok ? 'login-info' : 'login-error';
        }

        async function send(env, method, value) {
            const opts = { method, headers: { 'Content-Type': 'application/json' } };
            if (value !== undefined) opts.body = JSON.stringify({ value });
            const resp = await fetch('/api/admin/api-keys/' + encodeURIComponent(env), opts);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || 'Request failed');
            return data;
        }

        function findItem(env, data) {
            const inKeys = (data.keys || []).find(k => k.env === env);
            if (inKeys) return inKeys;
            for (const group of data.credentials || []) {
                const hit = (group.items || []).find(k => k.env === env);
                if (hit) return hit;
            }
            return null;
        }

        // Reflect the server's fresh status straight into the row, instead of
        // just showing a text banner and telling the operator to reload —
        // pressing Save with no visible change looked exactly like nothing
        // had happened.
        function applyStatus(listId, row, item) {
            const badge = row.querySelector('.api-key-head .status');
            if (badge) {
                badge.className = 'status ' + (item.configured ? 'status-pass' : 'status-warn');
                const verb = listId === 'apiKeyList' ? 'Configured' : 'Set';
                let html = item.configured ? verb : 'Not set';
                if (item.configured && item.source === 'environment') html += ' via environment';
                html = escapeHtml(html);
                if (item.configured && item.hint) html += ' <code>' + escapeHtml(item.hint) + '</code>';
                badge.innerHTML = html;
            }
            const controls = row.querySelector('.api-key-controls');
            if (!controls) return;
            let clearBtn = controls.querySelector('.api-key-clear');
            if (item.configured && !clearBtn) {
                clearBtn = document.createElement('button');
                clearBtn.type = 'button';
                clearBtn.className = 'btn-ghost api-key-clear';
                clearBtn.textContent = 'Remove';
                controls.appendChild(clearBtn);
            } else if (!item.configured && clearBtn) {
                clearBtn.remove();
            }
            // Test buttons only exist on individually-testable keys (the
            // OSINT card), never on the grouped credential rows.
            if (listId === 'apiKeyList') {
                let testBtn = controls.querySelector('.api-key-test');
                if (item.configured && !testBtn) {
                    testBtn = document.createElement('button');
                    testBtn.type = 'button';
                    testBtn.className = 'btn-ghost api-key-test';
                    testBtn.textContent = 'Test';
                    controls.appendChild(testBtn);
                } else if (!item.configured && testBtn) {
                    testBtn.remove();
                    const resultEl = row.querySelector('.api-key-test-result');
                    if (resultEl) { resultEl.textContent = ''; resultEl.className = 'api-key-test-result'; }
                }
            }
            const input = controls.querySelector('.api-key-input');
            if (input) {
                input.placeholder = item.configured
                    ? 'Enter a new value to replace the current one' : 'Paste value';
            }
        }

        // Runs a connection test and writes ok/fail into `resultEl`, with a
        // "Testing…" state on the triggering button while in flight.
        async function runTest(btn, target, resultEl) {
            const originalLabel = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Testing…';
            if (resultEl) { resultEl.textContent = ''; resultEl.className = resultEl.className.replace(/\bok\b|\bfail\b/g, '').trim(); }
            try {
                const resp = await fetch('/api/admin/api-keys/' + encodeURIComponent(target) + '/test', { method: 'POST' });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) throw new Error(data.error || 'Test failed');
                if (resultEl) {
                    resultEl.textContent = data.detail || (data.ok ? 'OK' : 'Failed');
                    resultEl.classList.add(data.ok ? 'ok' : 'fail');
                }
            } catch (err) {
                if (resultEl) {
                    resultEl.textContent = err.message || 'Test failed';
                    resultEl.classList.add('fail');
                }
            } finally {
                if (btn.isConnected) {
                    btn.disabled = false;
                    btn.textContent = originalLabel;
                }
            }
        }

        lists.forEach(list => list.addEventListener('click', async (e) => {
            const groupTestBtn = e.target.closest('.group-test-btn');
            if (groupTestBtn) {
                const group = groupTestBtn.getAttribute('data-group');
                const resultEl = list.querySelector('.group-test-result[data-group="' + group + '"]');
                await runTest(groupTestBtn, group, resultEl);
                return;
            }

            const testBtn = e.target.closest('.api-key-test');
            const saveBtn = e.target.closest('.api-key-save');
            const clearBtn = e.target.closest('.api-key-clear');
            if (!saveBtn && !clearBtn && !testBtn) return;
            const row = e.target.closest('.api-key-row');
            const env = row && row.getAttribute('data-env');
            if (!env) return;

            if (testBtn) {
                await runTest(testBtn, env, row.querySelector('.api-key-test-result'));
                return;
            }

            const btn = saveBtn || clearBtn;
            const originalLabel = btn.textContent;

            try {
                let data;
                if (saveBtn) {
                    const input = row.querySelector('.api-key-input');
                    const value = (input.value || '').trim();
                    if (!value) { notify('Enter a key first.', false); return; }
                    btn.disabled = true;
                    btn.textContent = 'Saving…';
                    data = await send(env, 'PUT', value);
                    input.value = '';
                    notify(env + ' saved.', true);
                } else {
                    if (!confirm('Remove the stored ' + env + '?')) return;
                    btn.disabled = true;
                    btn.textContent = 'Removing…';
                    data = await send(env, 'DELETE');
                    notify(env + ' removed.', true);
                }
                const item = findItem(env, data);
                if (item) applyStatus(list.id, row, item);
            } catch (err) {
                notify(err.message || 'Could not update the key', false);
            } finally {
                if (btn.isConnected) {
                    btn.disabled = false;
                    btn.textContent = originalLabel;
                }
            }
        }));
    }

    window.initAdminSettings = function initAdminSettings() {
        // The API key/credential panels are independent of the generic
        // settings form below. Keep one from breaking the other.
        try {
            initApiKeys();
        } catch (e) {
            console.error('API key panel failed to initialise', e);
        }
        const payload = DomainLensI18n.pageData('settingsSchema', {}) || {};
        const schema = payload.sections || {};
        const categories = payload.categories || [];
        const nav = $('settingsNav');
        const panels = $('settingsPanels');
        if (!nav || !panels) return;

        // Ordered by category, then by the order within it. A section the
        // server sent but no category claims is appended under "Other"
        // rather than dropped — an unreachable settings page is a worse
        // failure than an untidy heading.
        const claimed = new Set();
        categories.forEach(c => (c.sections || []).forEach(s => claimed.add(s)));
        const orphans = Object.keys(schema).filter(s => !claimed.has(s));
        const groups = categories
            .map(c => ({
                label: t(c.key) || c.key,
                sections: (c.sections || []).filter(s => schema[s]),
            }))
            .filter(g => g.sections.length);
        if (orphans.length) {
            groups.push({ label: t('settings.categories.other') || 'Other', sections: orphans });
        }

        const sections = groups.reduce((all, g) => all.concat(g.sections), []);
        nav.innerHTML = groups.map(g =>
            `<div class="settings-group">
                <p class="settings-group-label">${escapeHtml(g.label)}</p>
                ${g.sections.map(s =>
                    `<button type="button" class="settings-tab${sections[0] === s ? ' active' : ''}" data-section="${escapeHtml(s)}">${escapeHtml(t('settings.sections.' + s) || s)}</button>`
                ).join('')}
            </div>`
        ).join('');

        panels.innerHTML = sections.map((s, i) => {
            const sec = schema[s];
            const fields = sec.fields || {};
            const body = Object.keys(fields).map(k => renderField(s, k, fields[k])).join('');
            return `<section class="settings-panel${i === 0 ? ' active' : ''}" id="panel-${escapeHtml(s)}">
                <form class="settings-form" data-section="${escapeHtml(s)}">${body}
                <button type="submit" class="btn-primary-lite">${escapeHtml(t('common.save'))}</button>
                </form>
            </section>`;
        }).join('');

        nav.querySelectorAll('.settings-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                nav.querySelectorAll('.settings-tab').forEach(b => b.classList.remove('active'));
                panels.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                const sec = btn.getAttribute('data-section');
                $('panel-' + sec).classList.add('active');
            });
        });

        panels.querySelectorAll('.settings-form').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const section = form.getAttribute('data-section');
                const fields = schema[section].fields;
                try {
                    await saveSection(section, fields);
                    alert(t('common.success'));
                    if (section === 'general') {
                        const loc = collectSection(section, fields).locale;
                        if (loc) {
                            await fetch('/api/locale', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ locale: loc }),
                            });
                            location.reload();
                        }
                    }
                } catch (err) {
                    alert(err.message || t('common.error'));
                }
            });
        });
    };

    // --- Bootstrap ---------------------------------------------------------
    // This lives here rather than in an inline <script> in the template
    // because the app serves script-src 'self' with no 'unsafe-inline', so
    // inline blocks are blocked by CSP and never ran.
    async function refreshUpdates(force) {
        const hint = $('settingsUpdateHint');
        const cmds = $('settingsUpdateCommands');
        if (!hint) return;
        try {
            const resp = await fetch('/api/updates/check' + (force ? '?force=1' : ''));
            const data = await resp.json();
            if (!resp.ok) {
                hint.textContent = data.error || 'Update check failed';
                return;
            }
            if (data.update_available) {
                hint.textContent = '';
                const link = document.createElement('a');
                link.href = data.release_url || '#';
                link.target = '_blank';
                link.rel = 'noopener';
                link.textContent = 'v' + data.latest_version;
                hint.appendChild(document.createTextNode('Update available: '));
                hint.appendChild(link);
                hint.appendChild(document.createTextNode(
                    ' (running v' + data.current_version + '). Prefer ./scripts/docker-update.sh.'));
                if (cmds && data.docker_commands) {
                    cmds.textContent = (data.docker_commands || []).join('\n');
                    cmds.classList.remove('hidden');
                }
            } else {
                hint.textContent = 'Running v' + (data.current_version || '?')
                    + (data.latest_version ? ' — latest release v' + data.latest_version : '')
                    + (data.error ? ' (' + data.error + ')' : '');
                if (cmds) cmds.classList.add('hidden');
            }
        } catch (e) {
            hint.textContent = 'Update check failed';
        }
    }

    document.addEventListener('DOMContentLoaded', async () => {
        // i18n must never be able to take the rest of the page down with it.
        try {
            await DomainLensI18n.init(DomainLensI18n.pageLocale());
        } catch (e) {
            console.error('i18n init failed; continuing without translations', e);
        }
        try {
            window.initAdminSettings();
        } catch (e) {
            console.error('Settings page failed to initialise', e);
            const banner = $('apiKeysMsg');
            if (banner) {
                banner.className = 'login-error';
                banner.textContent =
                    'This page failed to initialise, so its buttons will not work: '
                    + (e && e.message ? e.message : e)
                    + '. Check the browser console for details.';
            }
        }
        const btn = $('settingsCheckUpdatesBtn');
        if (btn) btn.addEventListener('click', () => refreshUpdates(true));
        refreshUpdates(false);
    });
})();
