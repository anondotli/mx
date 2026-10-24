'use strict';

const addressRfc2822 = require('address-rfc2822');

// Local part and (lowercased) domain of an address, split at the last "@";
// null when there is no local part or domain.
function splitAddress(raw) {
    const email = String(raw || '').trim();
    const at = email.lastIndexOf('@');
    if (at <= 0 || at === email.length - 1) return null;
    return { local: email.slice(0, at), domain: email.slice(at + 1).toLowerCase() };
}

function domainOf(raw) {
    return splitAddress(raw)?.domain || '';
}

const GMAIL_DOMAINS = new Set(['gmail.com', 'googlemail.com']);

// Lowercased, with the dots Gmail ignores removed; '' for non-addresses.
function canonical(raw) {
    const parts = splitAddress(String(raw || '').toLowerCase());
    if (!parts) return '';
    if (GMAIL_DOMAINS.has(parts.domain)) return `${parts.local.replace(/\./g, '')}@gmail.com`;
    return `${parts.local}@${parts.domain}`;
}

// Whether `sender` is the mailbox of the registered address: the same address
// (ignoring case and Gmail's dots), or the registered address without its
// +tag — mail for bob+anon@ lands in bob@'s mailbox, and replies leave from
// bob@. A tag on the sender's side is never ignored: elsewhere bob+x@ can be
// someone else's account.
function sameMailbox(sender, registered) {
    const s = canonical(sender);
    if (!s) return false;
    const parts = splitAddress(registered);
    const untagged = parts ? `${parts.local.replace(/\+.*$/, '')}@${parts.domain}` : '';
    return s === canonical(registered) || s === canonical(untagged);
}

// The first mailbox of an RFC 5322 address header value: { address, name }
// (name: the display name as written, unquoted), or null.
function firstMailbox(value) {
    if (!value) return null;
    try {
        const parsed = addressRfc2822.parse(value);
        const first = Array.isArray(parsed) ? parsed.find(entry => entry?.address) : null;
        return first ? { address: first.address, name: (first.phrase || '').trim() } : null;
    } catch (_err) {
        return null;
    }
}

module.exports = { splitAddress, domainOf, sameMailbox, firstMailbox };
