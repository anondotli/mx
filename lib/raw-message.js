'use strict';

// Transfer of a raw RFC 5322 message (Buffer) into and out of a Haraka
// Transaction: the body byte for byte. (Header lines are parsed and re-emitted
// by Haraka from its UTF-8 header list, as for all mail it receives — raw
// non-UTF-8 header bytes, invalid under RFC 5322/6532, do not survive that.)
//
// Haraka stores message data the way it arrives over SMTP: CRLF line endings
// and dot-stuffed, and the outbound queue file is later sent verbatim. Haraka's
// outbound.send_email() only dot-stuffs *string* contents — its stream path
// stores lines raw, so a forwarded body line of "." ends DATA early at the next
// hop (truncating the message) and a line like ".button {" loses its dot. Both
// of its paths also round-trip the bytes through UTF-8, corrupting 8-bit bodies
// in other charsets. So we feed transactions ourselves.

const CRLF = Buffer.from('\r\n');
const DOT = Buffer.from('.');
const EMPTY = Buffer.alloc(0);

// One line of the message, terminated with CRLF and dot-stuffed as if it had
// arrived over SMTP.
function stuffLine(line) {
    let end = line.length;
    if (end > 0 && line[end - 1] === 0x0a) end--;
    if (end > 0 && line[end - 1] === 0x0d) end--;
    const content = line.subarray(0, end);
    return Buffer.concat([content[0] === 0x2e ? DOT : EMPTY, content, CRLF]);
}

// Writes `raw` into a fresh transaction and finishes it (end_data flushes any
// body filters). Resolves once the message stream is complete.
function writeRawMessage(txn, raw) {
    const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    let start = 0;
    while (start < buf.length) {
        const lf = buf.indexOf(0x0a, start);
        const end = lf === -1 ? buf.length : lf + 1;
        txn.add_data(stuffLine(buf.subarray(start, end)));
        start = end;
    }
    return new Promise(resolve => txn.end_data(resolve));
}

// The stored message with dot-stuffing removed (what the recipient will see).
function readRawMessage(txn) {
    return new Promise(resolve => {
        txn.message_stream.get_data(buf => resolve(Buffer.isBuffer(buf) ? buf : Buffer.from(buf)));
    });
}

module.exports = { writeRawMessage, readRawMessage, stuffLine };
