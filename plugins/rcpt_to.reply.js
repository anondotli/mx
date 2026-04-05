'use strict';

const { fetch } = require('undici');
const { retryCall } = require('../lib/security');

exports.register = function () {
    this.register_hook('rcpt', 'check_reply_token');
};

exports.check_reply_token = async function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    const email = params[0].address();
    if (!email.toLowerCase().endsWith('@reply.anon.li')) return next();

    // Reject mixed-mode transactions
    if (txn.notes.alias || txn.notes.bounce || txn.notes.zoho_relay || txn.notes.reply) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    const token = email.split('@')[0];

    try {
        const replyData = await retryCall(async (signal) => {
            const res = await fetch(
                `${process.env.FRONTEND_URL}/api/internal/reply-token?token=${encodeURIComponent(token)}`,
                {
                    method: 'GET',
                    headers: { 'x-api-secret': process.env.MAIL_API_SECRET },
                    signal,
                }
            );
            if (res.status === 404) return null;
            if (!res.ok) throw new Error(`API ${res.status}`);
            return res.json();
        }, { breakerKey: 'reply-token' });

        if (!replyData) return next(DENY, 'Invalid reply token');

        txn.notes.reply = replyData;
        txn.notes.is_reply = true;
        return next(OK);

    } catch (err) {
        plugin.logerror(`Reply check failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary error');
    }
};
