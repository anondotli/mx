'use strict';

exports.register = function () {
    this.register_hook('data_post', 'spam_check');
};

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
        this.loginfo(`DMARC reject: ${txn.mail_from.address()}`);
        return next(DENY, 'Message failed DMARC policy (reject)');
    }

    // DMARC quarantine — flag but deliver
    if (auth.dmarc?.status?.result === 'fail' && auth.dmarc?.policy === 'quarantine') {
        this.loginfo(`DMARC quarantine: ${txn.mail_from.address()}`);
        txn.add_header('X-Spam-Flag', 'YES');
    }

    // SPF hard fail + no passing DKIM
    if (auth.spf?.status?.result === 'fail') {
        const dkimResults = auth.dkim?.results || [];
        const hasDkimPass = dkimResults.some(r => r.status?.result === 'pass');
        if (!hasDkimPass) {
            this.loginfo(`SPF fail + no DKIM pass: ${txn.mail_from.address()}`);
            return next(DENY, 'Message failed SPF with no valid DKIM');
        }
    }

    return next();
};
