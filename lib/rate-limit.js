'use strict';

const redis = require('./upstash');

// Fixed-window counters (connections per IP, messages per alias): Redis
// INCR + EXPIRE NX, or an in-memory fallback — also used while Redis errors.

function createRateLimiter({ keyPrefix, windowSeconds, maxCount }) {
    const windowMs = windowSeconds * 1000;
    const local = new Map(); // key -> { count, start }

    function localExceeded(key) {
        const now = Date.now();
        const entry = local.get(key);
        if (!entry || now - entry.start > windowMs) {
            local.set(key, { count: 1, start: now });
            return false;
        }
        entry.count++;
        return entry.count > maxCount;
    }

    const cleanup = setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of local) {
            if (now - entry.start > windowMs) local.delete(key);
        }
    }, windowMs);
    cleanup.unref();

    // Counts one hit for `key`; true when it exceeds the limit. Redis errors are
    // reported through onError and fall back to the in-memory counter.
    async function hit(key, onError = () => {}) {
        if (redis) {
            try {
                const pipeline = redis.pipeline();
                pipeline.incr(`${keyPrefix}${key}`);
                pipeline.expire(`${keyPrefix}${key}`, windowSeconds, 'NX');
                const [count] = await pipeline.exec();
                return count > maxCount;
            } catch (err) {
                onError(err);
            }
        }
        return localExceeded(key);
    }

    return { hit, stop: () => clearInterval(cleanup) };
}

module.exports = { createRateLimiter };
