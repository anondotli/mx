'use strict';

const crypto = require('crypto');
const redis = require('./upstash');

// Short, reversible envelope-sender tokens for the forward path.
//
// SRS rewrites the envelope sender into our domain so SPF aligns and bounces
// route back to us, but it does so by *prefixing* the original address into the
// local-part. For long senders — typically ESP/VERP bounce addresses such as
// "bounces+108370056-3140-...=anon.li@em6623.email.openai.com" — the SRS
// local-part blows past the RFC-5321 §4.5.3.1.1 64-octet limit, and
// address-rfc2821 throws ("RFC-5321 local-part exceeds 64 octets"), DENYSOFTing
// the whole forward so the alias never receives the mail.
//
// SRS cannot encode an arbitrary-length sender inside 64 octets, so for those
// senders we fall back to the same trick reply tokens use: mint a short random
// token, store the original sender server-side with a TTL, and emit a compact
// "BNC=<token>@anon.li" envelope. rcpt_to.bounce resolves the token back to the
// original sender when a DSN arrives. (In-memory fallback mirrors limit-upstash
// for dev/tests.) See also [[reply-token]].

const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const TOKEN_BYTES = 18; // 144 bits of entropy → 24 base64url chars, well under 64
const KEY_PREFIX = 'bounce:';
const TOKEN_RE = /^[A-Za-z0-9_-]+$/;

// Local-part marker for tokenised bounce addresses (BNC=<token>@anon.li). Uses
// '=' like SRS0=/SRS1= so it can never collide with a generated [a-z0-9] alias,
// and is matched case-insensitively the same way rcpt_to.bounce matches SRS.
const ADDRESS_PREFIX = 'BNC=';

// In-memory fallback store: token -> { sender, expiresAt(ms) }
const localStore = new Map();

function pruneLocal() {
    const now = Date.now();
    for (const [k, v] of localStore) {
        if (v.expiresAt <= now) localStore.delete(k);
    }
}

// Creates a bounce token and persists the original sender. Returns the token
// (the local-part body of a BNC=<token>@anon.li address). Async: may perform a
// Redis write.
async function create(originalSender) {
    const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');

    if (redis) {
        await redis.set(`${KEY_PREFIX}${token}`, { originalSender }, { ex: TOKEN_TTL_SECONDS });
    } else {
        pruneLocal();
        localStore.set(token, { sender: originalSender, expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000 });
    }

    return token;
}

// Resolves a token back to the original sender. Returns null for unknown /
// expired / malformed tokens. Throws only on backing-store (Redis) errors so the
// caller can tempfail rather than permanently reject a bounce during an outage.
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
        data = { originalSender: entry.sender };
    }

    if (!data) return null;
    // @upstash/redis normally auto-parses JSON, but tolerate a raw string too.
    if (typeof data === 'string') {
        try { data = JSON.parse(data); } catch { return null; }
    }
    if (!data.originalSender) return null;

    return { originalSender: data.originalSender };
}

// Exposed for tests / introspection only
function _clearLocalStore() {
    localStore.clear();
}

module.exports = { create, decode, ADDRESS_PREFIX, _clearLocalStore };
