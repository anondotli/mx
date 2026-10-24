'use strict';

// Real Haraka building blocks for tests that need the actual MIME parser and
// message stream rather than hand-written stubs.

const path = require('node:path');
const { Transaction } = require(path.join(__dirname, '../../node_modules/haraka/transaction'));

// Haraka plugin return codes (haraka-constants)
const codes = { CONT: 900, STOP: 901, DENY: 902, DENYSOFT: 903, DENYDISCONNECT: 904, DENYSOFTDISCONNECT: 905, OK: 906 };
Object.assign(globalThis, codes);

let counter = 0;
function createTransaction(uuid) {
    return new Transaction(uuid || `test-${++counter}`, {});
}

// A transaction as Haraka builds it while receiving DATA (dot-stuffed lines).
async function receivedTransaction(raw, { notes = {}, mailFrom, rcptTo = [] } = {}) {
    const { writeRawMessage } = require('../../lib/raw-message');
    const txn = createTransaction();
    Object.assign(txn.notes, notes);
    if (mailFrom !== undefined) txn.mail_from = mailFrom;
    txn.rcpt_to = rcptTo;
    await writeRawMessage(txn, Buffer.isBuffer(raw) ? raw : Buffer.from(raw));
    return txn;
}

function readStored(txn, options = {}) {
    return new Promise(resolve => txn.message_stream.get_data(options, resolve));
}

module.exports = { ...codes, createTransaction, receivedTransaction, readStored };
