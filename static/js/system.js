/** DomainLens system helpers: version chip + update status. */
(function () {
    function el(id) {
        return document.getElementById(id);
    }

    async function loadVersion() {
        try {
            const resp = await fetch("/api/version");
            if (!resp.ok) return null;
            return await resp.json();
        } catch (_) {
            return null;
        }
    }

    async function checkUpdates() {
        try {
            const resp = await fetch("/api/updates/check");
            if (!resp.ok) return null;
            return await resp.json();
        } catch (_) {
            return null;
        }
    }

    function renderUpdate(status) {
        const node = el("updateStatus");
        if (!node || !status) return;
        node.hidden = false;
        if (status.update_available) {
            node.classList.remove("muted");
            node.classList.add("update-available");
            const latest = status.latest_version || "?";
            const url = status.release_url || "#";
            node.innerHTML =
                '<a href="' +
                url +
                '" target="_blank" rel="noopener">' +
                "Update available: v" +
                latest +
                "</a>";
        } else if (status.error) {
            node.textContent = "";
            node.hidden = true;
        } else {
            node.classList.add("muted");
            node.textContent =
                "Up to date (v" + (status.current_version || "?") + ")";
        }
    }

    async function init() {
        const info = await loadVersion();
        const chip = el("appVersionChip");
        if (chip && info && info.version) {
            chip.textContent = "v" + info.version;
            chip.title =
                "DomainLens " +
                info.version +
                (info.git_revision ? " (" + info.git_revision + ")" : "");
        }
        // Only poll updates when an admin/settings context or anonymous (auth off)
        const status = await checkUpdates();
        renderUpdate(status);
    }

    document.addEventListener("DOMContentLoaded", init);
    window.DomainLensSystem = { loadVersion, checkUpdates };
})();
