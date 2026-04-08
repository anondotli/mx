'use strict';

exports.register = function () {
    this.register_hook('data_post', 'spam_check');
};

function hasPassingDkim(auth) {
    const dkimResults = auth?.dkim?.results || [];
    return dkimResults.some(r => r.status?.result === 'pass');
}

exports.spam_check = function (next, connection) {
    const txn = connection.transaction;
    if (!txn) return next();

    // Skip trusted paths
    if (txn.notes.is_reply) return next();
    if (txn.notes.zoho_relay) return next();

    const auth = txn.notes.mailauth;
    if (!auth) return next();

    // DMARC reject
    if (auth.dmarc?.status?.result === 'fail' && auth.dmarc?.policy === 'reject') {
        if (txn.notes.alias) {
            this.loginfo(`DMARC reject on alias, flagging: ${txn.mail_from.address()}`);
            txn.add_header('X-Spam-Flag', 'YES');
            txn.add_header('X-Spam-Reason', 'DMARC fail (policy=reject)');
        } else {
            this.loginfo(`DMARC reject: ${txn.mail_from.address()}`);
            return next(DENY, 'Message failed DMARC policy (reject)');
        }
    }

    // DMARC quarantine — flag but deliver
    if (auth.dmarc?.status?.result === 'fail' && auth.dmarc?.policy === 'quarantine') {
        this.loginfo(`DMARC quarantine: ${txn.mail_from.address()}`);
        txn.add_header('X-Spam-Flag', 'YES');
        txn.add_header('X-Spam-Reason', 'DMARC fail (policy=quarantine)');
    }

    // SPF hard fail + no passing DKIM
    if (auth.spf?.status?.result === 'fail') {
        if (!hasPassingDkim(auth)) {
            this.loginfo(`SPF fail + no DKIM pass: ${txn.mail_from.address()}`);
            return next(DENY, 'Message failed SPF with no valid DKIM');
        }
    }

    return next();
};

exports.hasPassingDkim = hasPassingDkim;
