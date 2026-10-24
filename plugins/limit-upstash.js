'use strict';

const { createRateLimiter } = require('../lib/rate-limit');

// Connections per IP (limit.ini: rate_limit_window seconds, rate_limit_count)

exports.register = function () {
    const plugin = this;

    const main = plugin.config.get('limit.ini')?.main || {};
    plugin.limiter = createRateLimiter({
        keyPrefix: 'rate:',
        windowSeconds: parseInt(main.rate_limit_window, 10) || 60,
        maxCount: parseInt(main.rate_limit_count, 10) || 20,
    });

    plugin.register_hook('connect', 'check_limit');
};

exports.shutdown = function () {
    this.limiter?.stop();
};

exports.check_limit = async function (next, connection) {
    const plugin = this;
    const ip = connection.remote.ip;

    // SKIP LOCALHOST (healthchecks, mail for hosted domains re-entering us)
    if (ip === '127.0.0.1' || ip === '::1') return next();

    const limited = await plugin.limiter.hit(ip, (err) => {
        plugin.logerror(`Redis Error: ${err.message} — using local fallback`);
    });
    if (limited) {
        plugin.loginfo(`Rate limit exceeded for ${ip}`);
        return next(DENYSOFT, 'Rate limit exceeded');
    }
    return next();
};
