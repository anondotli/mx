'use strict';

const MAX_RECEIVED_HEADERS = 25;

exports.register = function () {
    this.register_hook('data_post', 'check_loops');
};

exports.check_loops = function (next, connection) {
    const txn = connection.transaction;
    if (!txn) return next();

    // Already forwarded by us — this is a loop
    if (txn.header.get('X-Anon-Forward')) {
        this.loginfo(`Loop detected: X-Anon-Forward already present in ${txn.uuid}`);
        return next(DENY, 'Mail loop detected');
    }

    // Too many hops (RFC 5321 §6.3 recommends max ~100, we use 25 as a practical limit)
    const receivedCount = txn.header.get_all('Received').length;
    if (receivedCount > MAX_RECEIVED_HEADERS) {
        this.loginfo(`Loop detected: ${receivedCount} Received headers in ${txn.uuid}`);
        return next(DENY, 'Too many hops — possible mail loop');
    }

    return next();
};
