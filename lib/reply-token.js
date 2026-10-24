'use strict';

const { createTokenStore } = require('./token-store');

// Opaque reply tokens.
//
// The previous design packed sender+alias+recipient+expiry into an AES-GCM blob
// and base64url-encoded it into the address local-part. That produced ~122-octet
// local-parts. Haraka's address parser (RFC-5321 §4.5.3.1.1) rejects any
// local-part over 64 octets, so Haraka bounced every reply at RCPT TO ("501
// Invalid RCPT TO address") before rcpt_to.reply could run. An encrypted blob
// cannot fit three email addresses inside 64 base64url chars, so the mapping has
// to live server-side: we mint a short random token and store the mapping in
// Redis with a TTL (in-memory fallback mirrors limit-upstash for dev/tests).

const store = createTokenStore({
    keyPrefix: 'reply:',
    ttlSeconds: 7 * 24 * 60 * 60,
    tokenBytes: 18, // 144 bits of entropy → 29 base32 chars, well under 64
});

// Creates a reply token and persists the sender→recipient mapping. Returns the
// token (the local-part of a @reply.anon.li address). Async: may perform a
// Redis write.
async function create(sender, aliasEmail, recipient) {
    return store.put({
        originalSender: sender,
        aliasEmail,
        recipientEmail: recipient,
    });
}

// Resolves a token back to its mapping. Returns null for unknown / expired /
// malformed tokens. Throws only on backing-store (Redis) errors so the caller
// can tempfail rather than permanently reject a reply during an outage.
async function decode(token) {
    const data = await store.get(token);
    if (!data?.originalSender || !data.aliasEmail || !data.recipientEmail) return null;

    return {
        originalSender: data.originalSender,
        aliasEmail: data.aliasEmail,
        recipientEmail: data.recipientEmail,
    };
}

// Exposed for tests / introspection only
function _clearLocalStore() {
    store.clear();
}

module.exports = { create, decode, _clearLocalStore };
