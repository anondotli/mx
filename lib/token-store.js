'use strict';

const crypto = require('crypto');
const redis = require('./upstash');

// Short-lived key → value stores (reply and bounce tokens, Message-ID map):
// Redis with a TTL, or an in-memory fallback for dev/tests (mirrors
// limit-upstash).
//
// Tokens are lowercase base32 and looked up case-insensitively: some MTAs
// lowercase the local part of the address they reply or bounce to. Tokens
// issued before that change were mixed-case base64url, so the exact form is
// tried first.

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const TOKEN_RE = /^[A-Za-z0-9_-]+$/;

function randomToken(bytes) {
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of crypto.randomBytes(bytes)) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
}

// Key → value store with a TTL: Redis, or an in-memory fallback. Store objects:
// Redis round-trips them as JSON.
function createStore({ keyPrefix, ttlSeconds }) {
    // key -> { value, expiresAt(ms) }
    const localStore = new Map();

    function pruneLocal() {
        const now = Date.now();
        for (const [k, v] of localStore) {
            if (v.expiresAt <= now) localStore.delete(k);
        }
    }

    // @upstash/redis auto-parses JSON values; a string that is not JSON comes
    // back as-is.
    function parse(value) {
        if (typeof value !== 'string') return value ?? null;
        try { return JSON.parse(value); } catch { return value; }
    }

    async function set(key, value) {
        if (redis) {
            await redis.set(`${keyPrefix}${key}`, value, { ex: ttlSeconds });
            return;
        }
        pruneLocal();
        localStore.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    }

    // Values for the given keys (null where unknown/expired), in one round trip.
    // Throws only on backing-store (Redis) errors.
    async function getMany(keys) {
        if (keys.length === 0) return [];
        if (redis) {
            const values = await redis.mget(...keys.map(k => `${keyPrefix}${k}`));
            return values.map(parse);
        }
        const now = Date.now();
        return keys.map(k => {
            const entry = localStore.get(k);
            return entry && entry.expiresAt > now ? entry.value : null;
        });
    }

    return { set, getMany, clear: () => localStore.clear() };
}

// Random-token store behind reply and bounce addresses.
function createTokenStore({ keyPrefix, ttlSeconds, tokenBytes }) {
    const store = createStore({ keyPrefix, ttlSeconds });

    // Stores `data` under a new token and returns the token.
    async function put(data) {
        const token = randomToken(tokenBytes);
        await store.set(token, data);
        return token;
    }

    // The stored value, or null for unknown / expired / malformed tokens.
    // Throws only on backing-store (Redis) errors so callers can tempfail.
    async function get(token) {
        if (!token || !TOKEN_RE.test(token)) return null;
        const lower = token.toLowerCase();
        const values = await store.getMany(lower === token ? [token] : [token, lower]);
        return values.find(Boolean) || null;
    }

    return { put, get, clear: store.clear };
}

module.exports = { createStore, createTokenStore };
