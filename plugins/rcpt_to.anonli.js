'use strict';

const fs = require('fs');
const path = require('path');
const db = require('../lib/db');
const rcptPolicy = require('../lib/rcpt-policy');
const { createRateLimiter } = require('../lib/rate-limit');
const { OWN_DOMAIN, REPLY_DOMAIN } = require('../lib/constants');
const { splitAddress } = require('../lib/address');

let reservedAliases = new Set();

exports.register = function () {
    const plugin = this;
    this.register_hook('rcpt', 'check_alias');
    // After every data_post check, before queue.forward (config/plugins order)
    this.register_hook('queue', 'create_catch_all_alias');

    // Messages per alias (limit.ini: alias_rate_limit_window seconds, alias_rate_limit_count)
    const main = plugin.config.get('limit.ini')?.main || {};
    plugin.aliasLimiter = createRateLimiter({
        keyPrefix: 'alias_rate:',
        windowSeconds: parseInt(main.alias_rate_limit_window, 10) || 300,
        maxCount: parseInt(main.alias_rate_limit_count, 10) || 50,
    });
    // New catch-all aliases per domain (limit.ini: catch_all_rate_limit_window
    // seconds, catch_all_rate_limit_count)
    plugin.catchAllLimiter = createRateLimiter({
        keyPrefix: 'catch_all_rate:',
        windowSeconds: parseInt(main.catch_all_rate_limit_window, 10) || 3600,
        maxCount: parseInt(main.catch_all_rate_limit_count, 10) || 30,
    });

    try {
        const configPath = path.resolve(__dirname, '..', 'config', 'reserved_aliases.json');
        const list = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        reservedAliases = new Set(list.map(a => a.toLowerCase()));
        plugin.loginfo(`Loaded ${reservedAliases.size} reserved aliases`);
    } catch (err) {
        plugin.logerror(`Failed to load reserved aliases: ${err.message}`);
    }
};

exports.shutdown = function () {
    this.aliasLimiter?.stop();
    this.catchAllLimiter?.stop();
};

exports.check_alias = async function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    const rcpt = params[0];
    if (!rcpt?.address()) return next(DENY, 'Invalid address');

    const email = rcpt.address().toLowerCase();

    // Ignore replies (handled by other plugin)
    if (email.endsWith(`@${REPLY_DOMAIN}`)) return next();

    // One recipient per transaction (lib/rcpt-policy.js)
    if (rcptPolicy.answered(next, txn, email)) return;

    const { local: localPart, domain } = splitAddress(email) || {};
    if (domain === OWN_DOMAIN && reservedAliases.has(localPart)) {
        txn.notes.purelymail_relay = true;
        txn.notes.purelymail_recipient = email;
        rcptPolicy.accept(txn, email);
        plugin.loginfo(`Reserved alias ${email} → Purelymail relay`);
        return next(OK);
    }

    try {
        const aliasData = await db.lookupAlias(email);

        if (!aliasData) {
            return next(DENY, 'No such user here');
        }

        // Per-alias rate limiting
        const limited = await plugin.aliasLimiter.hit(email, (err) => {
            plugin.logerror(`Alias rate limit error: ${err.message} — using local fallback`);
        });
        if (limited) {
            plugin.loginfo(`Alias rate limit exceeded for ${email}`);
            return next(DENYSOFT, 'Too many messages to this address');
        }

        // Store for queue plugin
        txn.notes.alias = aliasData;
        rcptPolicy.accept(txn, email);
        return next(OK);

    } catch (err) {
        plugin.logerror(`Alias lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary lookup failure');
    }
};

// A catch-all address accepted at RCPT gets its alias only now, once the
// message has passed every check: probes and rejected mail must not create
// aliases, which count against the owner's quota and fill their dashboard.
exports.create_catch_all_alias = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    const pending = txn?.notes?.alias;
    if (!pending?.catchAll) return next();

    const limited = await plugin.catchAllLimiter.hit(pending.domain, (err) => {
        plugin.logerror(`Catch-all rate limit error: ${err.message} — using local fallback`);
    });
    if (limited) {
        plugin.loginfo(`Catch-all rate limit exceeded for ${pending.domain}`);
        return next(DENYSOFT, 'Too many new addresses on this domain, try again later');
    }

    try {
        const alias = await db.createCatchAllAlias(pending);
        if (!alias) return next(DENY, 'No such user here');
        txn.notes.alias = alias;
        return next();
    } catch (err) {
        plugin.logerror(`Catch-all alias creation failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary lookup failure');
    }
};
