const redis = require('../lib/upstash');
// In-memory fallback when Redis is unavailable
const localCounts = new Map();
const LOCAL_WINDOW_MS = 60000;
const LOCAL_MAX = 100;

function cleanupLocalCounts() {
    const now = Date.now();
    for (const [key, entry] of localCounts) {
        if (now - entry.start > LOCAL_WINDOW_MS) localCounts.delete(key);
    }
}

function checkLocalLimit(ip) {
    const now = Date.now();
    const entry = localCounts.get(ip);
    if (!entry || now - entry.start > LOCAL_WINDOW_MS) {
        localCounts.set(ip, { count: 1, start: now });
        return false;
    }
    entry.count++;
    return entry.count > LOCAL_MAX;
}

exports.register = function () {
    const plugin = this;

    const cfg = plugin.config.get('limit.ini') || {};
    const main = cfg?.main || {};
    plugin.cfg = {
        max_connections: main.max_connections || 10,
        rate_limit_window: main.rate_limit_window || 60,
        rate_limit_count: main.rate_limit_count || 20
    };

    plugin.redis = redis;
    // Always register — fall back to in-memory limiting when Redis is absent
    plugin.register_hook('connect', 'check_limit');

    // Periodically clean up expired local rate-limit entries
    plugin._cleanupTimer = setInterval(cleanupLocalCounts, LOCAL_WINDOW_MS);
    plugin._cleanupTimer.unref();
};

exports.shutdown = function () {
    if (this._cleanupTimer) clearInterval(this._cleanupTimer);
};

exports.check_limit = async function(next, connection) {
    const plugin = this;

    // SKIP LOCALHOST (Healthchecks)
    if (connection.remote.ip === '127.0.0.1' || connection.remote.ip === '::1') {
        return next();
    }

    const ip = connection.remote.ip;

    if (!plugin.redis) {
        // No Redis — use in-memory fallback
        if (checkLocalLimit(ip)) {
            plugin.loginfo(`Rate limit exceeded for ${ip} (local)`);
            return next(DENYSOFT, 'Rate limit exceeded');
        }
        return next();
    }

    try {
        const pipeline = plugin.redis.pipeline();
        pipeline.incr(`rate:${ip}`);
        pipeline.expire(`rate:${ip}`, plugin.cfg.rate_limit_window, 'NX');
        const results = await pipeline.exec();
        const count = results[0];

        if (count > plugin.cfg.rate_limit_count) {
            plugin.loginfo(`Rate limit exceeded for ${ip}`);
            return next(DENYSOFT, 'Rate limit exceeded');
        }

        return next();
    } catch (err) {
        plugin.logerror(`Redis Error: ${err.message} — using local fallback`);
        if (checkLocalLimit(ip)) {
            return next(DENYSOFT, 'Rate limit exceeded');
        }
        return next();
    }
};
