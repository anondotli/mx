'use strict';

const replyToken = require('../lib/reply-token');

exports.register = function () {
    this.register_hook('rcpt', 'check_reply_token');
};

exports.check_reply_token = function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const email = params[0].address();
    if (!email.toLowerCase().endsWith('@reply.anon.li')) return next();

    // Reject mixed-mode transactions
    if (txn.notes.alias || txn.notes.bounce || txn.notes.zoho_relay || txn.notes.reply) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    const token = email.split('@')[0];
    const decoded = replyToken.decode(token);
    if (!decoded) return next(DENY, 'Invalid reply token');

    txn.notes.reply = {
        originalSender: decoded.originalSender,
        aliasEmail: decoded.aliasEmail,
        recipientEmail: decoded.recipientEmail,
    };
    txn.notes.is_reply = true;
    return next(OK);
};
