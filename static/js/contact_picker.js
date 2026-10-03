// Choosing a contact, shared by Organisation and the domain portfolio: an
// existing contact, an account (single sign-on or local) that becomes one,
// or a new contact typed in on the spot. Uses esc and requestJson from
// lookup.js, which these pages load first.

const contactBook = { contacts: [], accounts: [] };

async function contactBookLoad() {
    try {
        const res = await requestJson('/api/contacts');
        contactBook.contacts = res.contacts || [];
        contactBook.accounts = res.accounts || [];
    } catch (err) { /* the picker then offers only "new" */ }
    return contactBook;
}

function contactLabel(c) {
    return c.email && c.email !== c.name ? `${c.name} (${c.email})` : c.name;
}

// <option>s: blank first, then contacts (c<id>), accounts (u<id>) and "new".
function contactOptions(blank, current) {
    const opts = [`<option value="">${esc(blank)}</option>`]
        .concat(contactBook.contacts.map(c => `<option value="c${c.id}"${String(c.id) === String(current) ? ' selected' : ''}>${esc(contactLabel(c))}</option>`));
    if (contactBook.accounts.length) {
        opts.push('<optgroup label="Accounts">'
            + contactBook.accounts.map(a => `<option value="u${a.id}">${esc(a.name ? `${a.name} (${a.email})` : a.email)}</option>`).join('')
            + '</optgroup>');
    }
    opts.push('<option value="new">New contact…</option>');
    return opts.join('');
}

// The fields for a new contact, shown when "New contact…" is chosen.
function contactNewFields(prefix) {
    return `<div class="contact-new hidden" data-prefix="${prefix}">`
        + `<input type="text" class="contact-new-name" placeholder="Name" aria-label="Name" autocomplete="off">`
        + `<input type="text" class="contact-new-email" placeholder="E-mail" aria-label="E-mail" autocomplete="off">`
        + '</div>';
}

function contactToggleNew(select) {
    const box = select.parentElement.querySelector('.contact-new');
    if (!box) return;
    box.classList.toggle('hidden', select.value !== 'new');
    if (select.value === 'new') box.querySelector('.contact-new-name').focus();
}

// The contact id a choice stands for, making the contact first when it is
// an account or new. null for the blank choice.
async function contactResolve(select) {
    const value = select.value;
    if (!value) return null;
    if (value.startsWith('c')) return Number(value.slice(1));
    let body;
    if (value.startsWith('u')) {
        body = { user_id: Number(value.slice(1)) };
    } else {
        const box = select.parentElement.querySelector('.contact-new');
        body = { name: box.querySelector('.contact-new-name').value, email: box.querySelector('.contact-new-email').value };
        if (!body.name.trim() && !body.email.trim()) throw new Error('Give the new contact a name or an e-mail address.');
    }
    const made = await requestJson('/api/contacts', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    await contactBookLoad();
    return made.id;
}
