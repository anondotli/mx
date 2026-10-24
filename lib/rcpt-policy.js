'use strict';

const DSN = require('haraka-dsn');
const constants = require('haraka-constants');

// One recipient per SMTP transaction: an alias, a reserved (Purelymail)
// address, a reply token or a return path each has its own delivery mode, and
// an alias's copies carry per-recipient headers. A repeat of the accepted
// address is accepted again (it is delivered once); any other address gets
// 452 4.5.3, so the sending MTA retries it in a separate transaction
// (RFC 5321 §4.5.3.1.10) instead of bouncing it.

// When the transaction already has a recipient, answers this RCPT and returns
// true; otherwise returns false and the caller decides.
function answered(next, txn, email) {
    const accepted = txn.notes.accepted_rcpt;
    if (!accepted) return false;
    if (accepted === String(email).toLowerCase()) {
        next(constants.ok);
    } else {
        next(constants.denysoft, DSN.proto_too_many_rcpts('Only one recipient per transaction', 452));
    }
    return true;
}

function accept(txn, email) {
    txn.notes.accepted_rcpt = String(email).toLowerCase();
}

module.exports = { answered, accept };
