// Wide lists on a phone: a table marked "stack-table" shows each row as a
// card (style.css), and every value needs its column name beside it there.
// The names are taken from the header row, so a table only has to carry the
// class: no page writes its labels twice. Tables filled in later (most are,
// from an API) are labelled as they change.

(function () {
    const LABEL = 'stack-label';

    function headerOf(table) {
        for (const row of table.rows) {
            if (row.cells.length > 1 && [...row.cells].every(c => c.tagName === 'TH')) return row;
        }
        return null;
    }

    function label(table) {
        const head = headerOf(table);
        if (!head) return;
        head.classList.add('stack-head');
        // Column names by position; a header cell with a control in it (a
        // "select all" box) stays visible on a phone.
        const names = [];
        for (const th of head.cells) {
            const span = Number(th.colSpan) || 1;
            if (th.querySelector('input, select, button')) th.classList.add('stack-keep');
            const name = th.textContent.replace(/\s+/g, ' ').trim();
            for (let i = 0; i < span; i++) names.push(name);
        }
        for (const row of table.rows) {
            if (row === head) continue;
            const cells = [...row.cells];
            if (cells.length === 1) { row.classList.add('stack-section'); continue; }
            let first = 0;
            if (cells[0].querySelector('input[type="checkbox"]') && !cells[0].textContent.trim()) {
                cells[0].classList.add('stack-check');
                first = 1;
            }
            if (cells[first]) cells[first].classList.add('stack-main');
            let col = 0;
            cells.forEach((cell, i) => {
                const name = names[col];
                col += Number(cell.colSpan) || 1;
                if (i <= first || !name) return;
                const existing = cell.firstElementChild;
                if (existing && existing.classList.contains(LABEL)) return;
                const span = document.createElement('span');
                span.className = LABEL;
                span.textContent = name;
                cell.insertBefore(span, cell.firstChild);
            });
        }
    }

    let pending = false;
    function run() {
        pending = false;
        document.querySelectorAll('table.stack-table').forEach(label);
    }
    function soon() {
        if (pending) return;
        pending = true;
        // Not requestAnimationFrame: it waits while a tab is in the background.
        setTimeout(run, 0);
    }

    document.addEventListener('DOMContentLoaded', () => {
        run();
        new MutationObserver(mutations => {
            // Our own labels are mutations too; only a change that brings
            // something else in needs another pass.
            if (mutations.some(m => [...m.addedNodes].some(n => !(n.classList && n.classList.contains(LABEL))))) soon();
        }).observe(document.body, { childList: true, subtree: true });
    });
})();
