'use strict';

const net = require('node:net');
const { createRateLimiter } = require('../lib/rate-limit');

// Connections per IP (limit.ini: rate_limit_window seconds, rate_limit_count)
// and rejected recipients per connection (max_rejected_rcpts)

exports.register = function () {
    const plugin = this;

    const main = plugin.config.get('limit.ini')?.main || {};
    plugin.limiter = createRateLimiter({
        keyPrefix: 'rate:',
        windowSeconds: parseInt(main.rate_limit_window, 10) || 60,
        maxCount: parseInt(main.rate_limit_count, 10) || 20,
    });
    plugin.maxRejectedRcpts = parseInt(main.max_rejected_rcpts, 10) || 10;

    plugin.register_hook('connect', 'check_limit');
    // Before the rcpt_to.* plugins (config/plugins order)
    plugin.register_hook('rcpt', 'check_rcpt_limit');
};

exports.shutdown = function () {
    this.limiter?.stop();
};

// Localhost: healthchecks, mail for hosted domains re-entering us
function isLocal(ip) {
    return ip === '127.0.0.1' || ip === '::1';
}

// The rate-limit bucket of a client address: an IPv4 address itself, an IPv6
// address its /64 — one customer's allocation, whose 2^64 addresses would
// otherwise each get a limit of their own.
function clientBucket(ip) {
    const address = String(ip || '');
    if (!net.isIPv6(address)) return address;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) return mapped[1];

    // Expand "::" to the missing zero groups (an embedded IPv4 tail is two)
    const groups = (part) => (part ? part.split(':') : []).flatMap(g => (g.includes('.') ? ['0', '0'] : [g]));
    const [head, tail] = address.split('::');
    const left = groups(head);
    const right = groups(tail);
    const all = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
    return `${all.slice(0, 4).map(g => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

exports.check_limit = async function (next, connection) {
    const plugin = this;
    const ip = connection.remote.ip;
    if (isLocal(ip)) return next();

    const limited = await plugin.limiter.hit(clientBucket(ip), (err) => {
        plugin.logerror(`Redis Error: ${err.message} — using local fallback`);
    });
    if (limited) {
        plugin.loginfo(`Rate limit exceeded for ${ip}`);
        return next(DENYSOFT, 'Rate limit exceeded');
    }
    return next();
};

// Every RCPT costs a database lookup and tells whether an alias exists, and one
// connection can send any number of them (RSET starts over). Legitimate senders
// reach many aliases per connection, one transaction each, so only rejected
// recipients count; past the cap the client is disconnected and may retry.
exports.check_rcpt_limit = function (next, connection) {
    if (isLocal(connection.remote.ip)) return next();
    if (connection.rcpt_count.reject >= this.maxRejectedRcpts) {
        this.loginfo(`${connection.rcpt_count.reject} rejected recipients from ${connection.remote.ip}, disconnecting`);
        return next(DENYSOFTDISCONNECT, 'Too many invalid recipients');
    }
    return next();
};

exports.clientBucket = clientBucket;
