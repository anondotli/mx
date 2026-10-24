'use strict';

const crypto = require('crypto');
const { createStore } = require('./token-store');
const { OWN_DOMAIN } = require('./constants');

// Message-ID privacy for the reply path.
//
// A reply leaves with a Message-ID derived (HMAC) from the one the user's mail
// client gave it, because that ID names the user's host or domain. The client
// keeps its own ID in the Sent copy and lists it in References / In-Reply-To of
// later messages in the thread, so:
//   - replies: IDs of earlier replies are rewritten to the IDs the
//     correspondent saw;
//   - forwards: those public IDs in the correspondent's References /
//     In-Reply-To are mapped back, so the user's client keeps threading — but
//     only on mail to the alias the reply was sent from: anyone else seeing a
//     public ID (another anon.li user the reply went to) must not learn the
//     client ID behind it.
// Only IDs of replies that went out through us are touched; IDs minted by the
// correspondent are left alone (their threading depends on them).

const ID_RE = /<[^<>\s]+>/g;
const PUBLIC_ID_RE = new RegExp(`^<([A-Za-z0-9_-]{32})@${OWN_DOMAIN.replace(/\./g, '\\.')}>$`);

// digest -> { clientId, alias } it was derived from / sent as
const store = createStore({ keyPrefix: 'msgid:', ttlSeconds: 180 * 24 * 60 * 60 });

function digest(clientId) {
    return crypto.createHmac('sha256', process.env.MAIL_API_SECRET || '')
        .update(clientId)
        .digest('base64url')
        .slice(0, 32);
}

// The first <id> in a Message-ID / In-Reply-To value, or null.
function firstId(value) {
    return String(value || '').match(ID_RE)?.[0] || null;
}

function publicId(clientId) {
    return `<${digest(clientId)}@${OWN_DOMAIN}>`;
}

async function remember(clientId, aliasEmail) {
    await store.set(digest(clientId), { clientId, alias: String(aliasEmail).toLowerCase() });
}

// Reply direction: in each value, client IDs of earlier replies → the public
// IDs we sent. One store lookup for all values.
async function toPublic(values) {
    const ids = [...new Set(values.flatMap(v => String(v).match(ID_RE) || []))];
    if (ids.length === 0) return values;
    const known = await store.getMany(ids.map(digest));
    const mapped = new Map(ids.map((id, i) => [id, known[i]?.clientId === id ? publicId(id) : id]));
    return values.map(v => String(v).replace(ID_RE, id => mapped.get(id)));
}

// Forward direction (mail to aliasEmail): in each value, public IDs of replies
// sent as that alias → the user's own client IDs. One store lookup for all
// values.
async function toClient(values, aliasEmail) {
    const alias = String(aliasEmail).toLowerCase();
    const ids = [...new Set(values.flatMap(v => String(v).match(ID_RE) || []))].filter(id => PUBLIC_ID_RE.test(id));
    if (ids.length === 0) return values;
    const known = await store.getMany(ids.map(id => PUBLIC_ID_RE.exec(id)[1]));
    const mapped = new Map(ids.map((id, i) => [id, (known[i]?.alias === alias && known[i].clientId) || id]));
    return values.map(v => String(v).replace(ID_RE, id => mapped.get(id) ?? id));
}

// Exposed for tests / introspection only
function _clearLocalStore() {
    store.clear();
}

module.exports = { firstId, publicId, remember, toPublic, toClient, _clearLocalStore };
