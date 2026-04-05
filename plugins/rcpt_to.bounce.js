'use strict';

const srs = require('../lib/srs');

exports.register = function () {
    this.register_hook('rcpt', 'check_bounce');
};

exports.check_bounce = function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const rcpt = params[0];
    if (!rcpt.address()) return next();

    const email = rcpt.address();
    const localPart = email.split('@')[0];

    // Only intercept SRS0/SRS1 addresses
    const upper = localPart.toUpperCase();
    if (!upper.startsWith('SRS0=') && !upper.startsWith('SRS1=')) return next();

    // Reject mixed-mode transactions
    if (txn.notes.alias || txn.notes.reply || txn.notes.zoho_relay || txn.notes.bounce) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

    const secret = process.env.MAIL_API_SECRET;
    if (!secret) {
        this.logerror('No MAIL_API_SECRET for SRS bounce validation');
        return next(DENYSOFT, 'Configuration error');
    }

    const result = srs.reverse(email, secret);

    if (!result.valid) {
        this.loginfo(`Invalid SRS bounce address: ${email}`);
        return next(DENY, 'Invalid bounce address');
    }

    txn.notes.bounce = { originalSender: result.originalSender };
    this.loginfo(`SRS bounce validated: ${email} → ${result.originalSender}`);
    return next(OK);
};
