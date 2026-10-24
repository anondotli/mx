'use strict';

const { createTokenStore } = require('./token-store');
const { OWN_DOMAIN } = require('./constants');

// Short, reversible envelope-sender tokens for the forward path.
//
// SRS rewrites the envelope sender into our domain so SPF aligns and bounces
// route back to us, but it does so by *prefixing* the original address into the
// local-part. For long senders — typically ESP/VERP bounce addresses such as
// "bounces+108370056-3140-...=anon.li@em6623.email.openai.com" — the SRS
// local-part blows past the RFC-5321 §4.5.3.1.1 64-octet limit, and
// Haraka's Address throws ("RFC-5321 local-part exceeds 64 octets"), DENYSOFTing
// the whole forward so the alias never receives the mail.
//
// SRS cannot encode an arbitrary-length sender inside 64 octets, so for those
// senders we fall back to the same trick reply tokens use: mint a short random
// token, store the original sender server-side with a TTL, and emit a compact
// "BNC=<token>@anon.li" envelope. rcpt_to.bounce resolves the token back to the
// original sender when a DSN arrives. (In-memory fallback mirrors limit-upstash
// for dev/tests.) See also [[reply-token]] and lib/token-store.js.

const store = createTokenStore({
    keyPrefix: 'bounce:',
    ttlSeconds: 7 * 24 * 60 * 60,
    tokenBytes: 18, // 144 bits of entropy → 29 base32 chars, well under 64
});

// Local-part marker for tokenised bounce addresses (BNC=<token>@anon.li). Uses
// '=' like SRS0=/SRS1= so it can never collide with a generated [a-z0-9] alias,
// and is matched case-insensitively the same way rcpt_to.bounce matches SRS.
const ADDRESS_PREFIX = 'BNC=';

// Creates a bounce token and persists the original sender. Returns the token
// (the local-part body of a BNC=<token>@anon.li address). Async: may perform a
// Redis write. `relay` marks return paths whose bounces may be passed on to
// originalSender (the envelope of a reply, leading back to its alias); bounces
// for forwarded mail never are — they name the alias owner's address.
async function create(originalSender, { relay = false } = {}) {
    return store.put({ originalSender, relay: relay === true });
}

// Resolves a token back to the original sender. Returns null for unknown /
// expired / malformed tokens. Throws only on backing-store (Redis) errors so the
// caller can tempfail rather than permanently reject a bounce during an outage.
async function decode(token) {
    const data = await store.get(token);
    if (!data?.originalSender) return null;
    return { originalSender: data.originalSender, relay: data.relay === true };
}

// The return-path address for a token.
function address(token) {
    return `${ADDRESS_PREFIX}${token}@${OWN_DOMAIN}`;
}

// Exposed for tests / introspection only
function _clearLocalStore() {
    store.clear();
}

module.exports = { create, decode, address, ADDRESS_PREFIX, _clearLocalStore };
