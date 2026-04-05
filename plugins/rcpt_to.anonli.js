'use strict';

const { fetch } = require('undici');
const fs = require('fs');
const path = require('path');
// Circuit breaker / retry logic integrated into security lib
const { retryCall } = require('../lib/security');
const redis = require('../lib/upstash');

// In-memory fallback for alias rate limiting
const aliasLocalCounts = new Map();

function cleanupAliasLocalCounts(windowMs) {
    const now = Date.now();
    for (const [key, entry] of aliasLocalCounts) {
        if (now - entry.start > windowMs) aliasLocalCounts.delete(key);
    }
}

function checkAliasLocalLimit(email, windowMs, maxCount) {
    const now = Date.now();
    const entry = aliasLocalCounts.get(email);
    if (!entry || now - entry.start > windowMs) {
        aliasLocalCounts.set(email, { count: 1, start: now });
        return false;
    }
    entry.count++;
    return entry.count > maxCount;
}

let reservedAliases = new Set();

exports.register = function () {
    const plugin = this;
    this.register_hook('rcpt', 'check_alias');

    // Load alias rate limit config
    const cfg = plugin.config.get('limit.ini') || {};
    const main = cfg?.main || {};
    plugin.aliasRateWindow = parseInt(main.alias_rate_limit_window, 10) || 300;
    plugin.aliasRateCount = parseInt(main.alias_rate_limit_count, 10) || 50;

    // Periodically clean up expired alias rate-limit entries
    plugin._aliasCleanupTimer = setInterval(
        () => cleanupAliasLocalCounts(plugin.aliasRateWindow * 1000),
        plugin.aliasRateWindow * 1000
    );
    plugin._aliasCleanupTimer.unref();
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
    if (this._aliasCleanupTimer) clearInterval(this._aliasCleanupTimer);
};

exports.check_alias = async function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    const rcpt = params[0];
    if (!rcpt.address()) return next(DENY, 'Invalid address');

    const email = rcpt.address().toLowerCase();

    // Ignore replies (handled by other plugin)
    if (email.endsWith('@reply.anon.li')) return next();

    // Reject mixed-mode transactions (alias + reply/bounce in same SMTP session)
    if (txn.notes.reply || txn.notes.bounce) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    const [localPart, domain] = email.split('@');
    if (domain === 'anon.li' && reservedAliases.has(localPart)) {
        // Only one Zoho relay per transaction
        if (txn.notes.zoho_relay && txn.notes.zoho_recipient !== email) {
            return next(DENY, 'Only one recipient per transaction');
        }
        txn.notes.zoho_relay = true;
        txn.notes.zoho_recipient = email;
        plugin.loginfo(`Reserved alias ${email} → Zoho relay`);
        return next(OK);
    }
    
    if (txn.notes.zoho_relay) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    // Reject if a different alias is already set in this transaction
    if (txn.notes.alias) {
        return next(DENY, 'Only one alias per transaction');
    }

    // API Check
    const apiSecret = process.env.MAIL_API_SECRET;
    if (!apiSecret) return next(DENYSOFT, 'Config error');

    try {
        const aliasData = await retryCall(async (signal) => {
            const res = await fetch(`${process.env.FRONTEND_URL}/api/internal/aliases`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-secret': apiSecret
                },
                body: JSON.stringify({ email }),
                signal
            });
            // Permanent client errors (unknown/invalid alias) — do NOT retry;
            // signal upstream via a sentinel so caller emits 550.
            if (res.status === 404 || res.status === 400) {
                return { __notFound: true };
            }
            if (!res.ok) throw new Error(`API ${res.status}`);
            return res.json();
        }, { breakerKey: 'alias-lookup' });

        if (aliasData?.__notFound || !aliasData || !aliasData.active) {
            return next(DENY, 'No such user here');
        }

        // Per-alias rate limiting
        try {
            let limited = false;
            if (redis) {
                const pipeline = redis.pipeline();
                pipeline.incr(`alias_rate:${email}`);
                pipeline.expire(`alias_rate:${email}`, plugin.aliasRateWindow, 'NX');
                const results = await pipeline.exec();
                const count = results[0];
                limited = count > plugin.aliasRateCount;
            } else {
                limited = checkAliasLocalLimit(email, plugin.aliasRateWindow * 1000, plugin.aliasRateCount);
            }

            if (limited) {
                plugin.loginfo(`Alias rate limit exceeded for ${email}`);
                return next(DENYSOFT, 'Too many messages to this address');
            }
        } catch (err) {
            plugin.logerror(`Alias rate limit error: ${err.message} — using local fallback`);
            if (checkAliasLocalLimit(email, plugin.aliasRateWindow * 1000, plugin.aliasRateCount)) {
                return next(DENYSOFT, 'Too many messages to this address');
            }
        }

        // Store for queue plugin
        txn.notes.alias = aliasData;
        return next(OK);

    } catch (err) {
        plugin.logerror(`Alias lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary lookup failure');
    }
};
