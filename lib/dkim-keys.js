'use strict';

const fs = require('fs');
const path = require('path');
const db = require('./db');

// DKIM signing keys for dkim.custom, arc.sign and queue.forward: a key staged on
// disk (config/dkim/<domain>/private, see docker-entrypoint.sh) first, then the
// domain's key from the database. One cache for all of them (TTL: 1 hour;
// misses: 5 minutes; lookup errors: 1 minute).

const keyCache = new Map();
const KEY_CACHE_TTL = 3600000;
const KEY_MISS_TTL = 300000;
const KEY_ERROR_TTL = 60000;

const DOMAIN_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

function getLocalKeyRoot() {
    return process.env.LOCAL_DKIM_DIR || path.resolve(__dirname, '..', 'config', 'dkim');
}

function getLocalKeyPath(domain) {
    return path.resolve(getLocalKeyRoot(), domain, 'private');
}

function cache(domain, data, ttl) {
    keyCache.set(domain, { data, expires: Date.now() + ttl });
    return data;
}

// { privateKey, selector } for a domain, or null. `config` is Haraka's config
// reader (dkim_sign.ini holds the selectors of local keys).
async function getKey(domainRaw, config, logerror = () => {}) {
    const domain = String(domainRaw || '').toLowerCase();
    if (!DOMAIN_RE.test(domain)) return null;

    const cached = keyCache.get(domain);
    if (cached && cached.expires > Date.now()) return cached.data;

    try {
        const privateKey = fs.readFileSync(getLocalKeyPath(domain), 'utf8');
        const selector = config?.get('dkim_sign.ini')?.[`domain ${domain}`]?.selector || 'default';
        return cache(domain, { privateKey, selector }, KEY_CACHE_TTL);
    } catch (_e) {
        // No local key, try the database
    }

    try {
        const data = await db.getDkimKey(domain);
        return cache(domain, data, data ? KEY_CACHE_TTL : KEY_MISS_TTL);
    } catch (err) {
        // Database outage or undecryptable key: callers fall back to anon.li.
        // Cached briefly so a persistent problem isn't retried on every message.
        logerror(`DKIM key lookup for ${domain} failed: ${err.message}`);
        return cache(domain, null, KEY_ERROR_TTL);
    }
}

function clearCache() {
    keyCache.clear();
}

module.exports = { getKey, getLocalKeyRoot, getLocalKeyPath, clearCache };
