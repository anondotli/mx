'use strict';

const replyToken = require('../lib/reply-token');

exports.register = function () {
    this.register_hook('rcpt', 'check_reply_token');
};

exports.check_reply_token = async function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const email = params[0].address();
    if (!email.toLowerCase().endsWith('@reply.anon.li')) return next();

    // Reject mixed-mode transactions
    if (txn.notes.alias || txn.notes.bounce || txn.notes.zoho_relay || txn.notes.reply) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    const token = email.split('@')[0];
    let decoded;
    try {
        decoded = await replyToken.decode(token);
    } catch (err) {
        // Backing-store (Redis) error — tempfail so the sender retries instead
        // of permanently losing a valid reply.
        this.logerror(`Reply token lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary error, please retry');
    }
    if (!decoded) return next(DENY, 'Invalid reply token');

    txn.notes.reply = {
        originalSender: decoded.originalSender,
        aliasEmail: decoded.aliasEmail,
        recipientEmail: decoded.recipientEmail,
    };
    txn.notes.is_reply = true;
    return next(OK);
};
