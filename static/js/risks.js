// Admin -> Accepted risks: the name and e-mail fields for a new risk owner
// show only when "Someone else" is chosen. Without this script they are
// always there, and the form works the same.

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('select.risk-owner').forEach(select => {
        const fields = select.closest('form').querySelector('.risk-owner-new');
        if (!fields) return;
        const sync = () => {
            const isNew = select.value === 'new';
            fields.classList.toggle('hidden', !isNew);
            fields.querySelector('input[name="owner_name"]').required = isNew;
        };
        select.addEventListener('change', () => {
            sync();
            if (select.value === 'new') fields.querySelector('input').focus();
        });
        sync();
    });
});
