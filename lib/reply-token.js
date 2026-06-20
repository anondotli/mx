'use strict';

const crypto = require('crypto');
const redis = require('./upstash');

// Opaque reply tokens.
//
// The previous design packed sender+alias+recipient+expiry into an AES-GCM blob
// and base64url-encoded it into the address local-part. That produced ~122-octet
// local-parts. address-rfc2821 (>= 2.2.x, RFC-5321 §4.5.3.1.1) now rejects any
// local-part over 64 octets, so Haraka bounced every reply at RCPT TO ("501
// Invalid RCPT TO address") before rcpt_to.reply could run. An encrypted blob
// cannot fit three email addresses inside 64 base64url chars, so the mapping has
// to live server-side: we mint a short random token and store the mapping in
// Redis with a TTL (in-memory fallback mirrors limit-upstash for dev/tests).

const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const TOKEN_BYTES = 18; // 144 bits of entropy → 24 base64url chars, well under 64
const KEY_PREFIX = 'reply:';
const TOKEN_RE = /^[A-Za-z0-9_-]+$/;

// In-memory fallback store: token -> { data, expiresAt(ms) }
const localStore = new Map();

function pruneLocal() {
    const now = Date.now();
    for (const [k, v] of localStore) {
        if (v.expiresAt <= now) localStore.delete(k);
    }
}

// Creates a reply token and persists the sender→recipient mapping. Returns the
// token (the local-part of a @reply.anon.li address). Async: may perform a
// Redis write.
async function create(sender, aliasEmail, recipient) {
    const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
    const data = {
        originalSender: sender,
        aliasEmail,
        recipientEmail: recipient,
    };

    if (redis) {
        await redis.set(`${KEY_PREFIX}${token}`, data, { ex: TOKEN_TTL_SECONDS });
    } else {
        pruneLocal();
        localStore.set(token, { data, expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000 });
    }

    return token;
}

// Resolves a token back to its mapping. Returns null for unknown / expired /
// malformed tokens. Throws only on backing-store (Redis) errors so the caller
// can tempfail rather than permanently reject a reply during an outage.
async function decode(token) {
    if (!token || !TOKEN_RE.test(token)) return null;

    let data;
    if (redis) {
        data = await redis.get(`${KEY_PREFIX}${token}`);
    } else {
        const entry = localStore.get(token);
        if (!entry || entry.expiresAt <= Date.now()) {
            if (entry) localStore.delete(token);
            return null;
        }
        data = entry.data;
    }

    if (!data) return null;
    // @upstash/redis normally auto-parses JSON, but tolerate a raw string too.
    if (typeof data === 'string') {
        try { data = JSON.parse(data); } catch { return null; }
    }
    if (!data.originalSender || !data.aliasEmail || !data.recipientEmail) return null;

    return {
        originalSender: data.originalSender,
        aliasEmail: data.aliasEmail,
        recipientEmail: data.recipientEmail,
    };
}

// Exposed for tests / introspection only
function _clearLocalStore() {
    localStore.clear();
}

module.exports = { create, decode, _clearLocalStore };
