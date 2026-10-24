'use strict';

const dns = require('node:dns').promises;
const Address = require('address-rfc2821').Address;
const srs = require('../lib/srs');
const pgpEncrypt = require('../lib/pgp-encrypt');
const pgpMime = require('../lib/pgp-mime');
const db = require('../lib/db');
const replyToken = require('../lib/reply-token');
const bounceToken = require('../lib/bounce-token');
const trackingRemove = require('../lib/tracking-remove');
const messageIds = require('../lib/message-ids');
const { writeRawMessage, readRawMessage } = require('../lib/raw-message');
const { OWN_DOMAIN, REPLY_DOMAIN } = require('../lib/constants');
const { domainOf, firstMailbox } = require('../lib/address');
const dkimKeys = require('../lib/dkim-keys');
let outbound;
let createTransaction;

const MAX_LOCAL_PART_OCTETS = 64; // RFC 5321 §4.5.3.1.1

// Marks a header for removal in setRawHeaders / replaceHeaderInBlock
const DROP = Symbol('drop header');

// Headers that make the recipient's mail client answer someone other than the
// Reply-To token — read receipts (MDNs), followup and error addresses — which
// would go out from the recipient's real address. Dropped from forwarded copies.
const FORWARD_DROPPED_HEADERS = [
    'Disposition-Notification-To', 'Return-Receipt-To', 'X-Confirm-Reading-To',
    'Mail-Followup-To', 'Mail-Reply-To', 'Errors-To',
];

// Headers of a user's reply that are passed on to the correspondent. Everything
// else is dropped: the user's provider and our own MTA add headers carrying the
// real address or client IP (Received "envelope-from", Received-SPF,
// Authentication-Results smtp.mailfrom, Sender, Return-Path, Reply-To, read
// receipt requests, X-Originating-IP, DKIM-Signature i=, Autocrypt, ...), the
// Message-ID names the sending host and Date carries the user's timezone. A
// fresh Message-ID and Date are added by outbound.send_trans_email.
const REPLY_HEADER_ALLOWLIST = new Set([
    'subject', 'in-reply-to', 'references',
    'mime-version', 'content-type', 'content-transfer-encoding',
    'content-language', 'content-disposition', 'content-id', 'content-description',
    'importance', 'priority', 'x-priority', 'sensitivity',
    'thread-topic', 'thread-index',
]);

// SRS-rewrite an envelope sender into @anon.li, falling back to a short
// server-side bounce token when the SRS local-part would exceed the RFC-5321
// 64-octet limit. SRS encodes the original address into the local-part, so long
// ESP/VERP bounce senders overflow it and address-rfc2821 throws — DENYSOFTing
// the entire forward. The returned address is always safe to hand to the Address
// constructor; over-length senders come back as BNC=<token>@anon.li, which
// rcpt_to.bounce resolves on the return path. See [[bounce-token]]. A null
// sender (<>, e.g. a DSN) has nothing to rewrite and returns null.
async function buildEnvelopeSender(sender, srsSecret) {
    if (!sender) return null;
    const srsSender = srs.rewrite(sender, OWN_DOMAIN, srsSecret);
    const at = srsSender.lastIndexOf('@');
    const localPart = at === -1 ? srsSender : srsSender.slice(0, at);
    if (Buffer.byteLength(localPart, 'utf8') <= MAX_LOCAL_PART_OCTETS) {
        return srsSender;
    }
    return bounceToken.address(await bounceToken.create(sender));
}

function envelopeAddress(address) {
    return address ? new Address(address) : new Address('<>');
}

// A return path whose bounces rcpt_to.bounce accepts for relaying to returnTo.
async function relayEnvelope(returnTo) {
    return new Address(bounceToken.address(await bounceToken.create(returnTo, { relay: true })));
}

function getOriginalSenderAddress(txn) {
    return firstMailbox(txn?.header?.get('Reply-To'))?.address
        || firstMailbox(txn?.header?.get('From'))?.address
        || txn?.mail_from?.address()
        || null;
}

// Drop every existing instance of headerName (including folded continuation
// lines, and the obsolete "Name :" form clients still honour) from a
// CRLF-joined header block, then append a single fresh instance — unless
// headerValue is DROP.
function replaceHeaderInBlock(headerBlock, headerName, headerValue) {
    const matcher = new RegExp(`^${headerName}[ \t]*:`, 'i');
    const kept = [];
    let skipping = false;

    for (const line of headerBlock.split('\r\n')) {
        if (/^[ \t]/.test(line)) {
            // Continuation line: keep it only if its parent header was kept.
            if (!skipping) kept.push(line);
            continue;
        }
        skipping = matcher.test(line);
        if (!skipping) kept.push(line);
    }

    if (headerValue !== DROP) kept.push(`${headerName}: ${headerValue}`);
    return kept.join('\r\n');
}

// Sets or (value DROP) removes headers ([name, value] pairs; empty values are
// skipped) with a single rewrite of the header block. latin1 keeps every byte of
// the other headers as it was; the body bytes are reused untouched.
function setRawHeaders(rawMessage, headers) {
    const changes = headers.filter(([, value]) => value);
    if (changes.length === 0) return rawMessage;

    const eoh = rawMessage.indexOf('\r\n\r\n');
    if (eoh === -1) return rawMessage;

    let headerBlock = rawMessage.subarray(0, eoh).toString('latin1');
    for (const [name, value] of changes) {
        headerBlock = replaceHeaderInBlock(headerBlock, name, value);
    }

    return Buffer.concat([
        Buffer.from(`${headerBlock}\r\n\r\n`, 'latin1'),
        rawMessage.subarray(eoh + 4),
    ]);
}


// RFC 5322 display-name encoding: a quoted-string for plain ASCII, or an
// RFC 2047 base64 encoded-word when the name carries non-ASCII bytes.
function encodeFromDisplayName(name) {
    if (/^[\x20-\x7E]*$/.test(name)) {
        return `"${name.replace(/[\\"]/g, '\\$&')}"`;
    }
    return `=?UTF-8?B?${Buffer.from(name, 'utf8').toString('base64')}?=`;
}

// Forwarding breaks the original sender's DMARC: SRS moves the envelope to
// @anon.li (SPF no longer aligns) and the forward rewrites headers (and
// sometimes the body), so the original DKIM may not validate. Senders that
// publish p=reject/quarantine therefore bounce at the receiver. Rewrite From
// onto the alias — a domain we DKIM-sign — so DMARC aligns, keeping the sender's
// display name. Replies still route through the Reply-To reply token.
function shouldMungeFrom(txn) {
    const policy = txn?.notes?.mailauth?.dmarc?.policy;
    return policy === 'reject' || policy === 'quarantine';
}

function buildMungedFrom(txn, aliasEmail) {
    // The decoded display name (an RFC 2047 encoded-word would otherwise end up
    // quoted, and shown literally); it is re-encoded below if needed.
    const sender = firstMailbox(txn?.header?.get_decoded?.('From')) || firstMailbox(txn?.header?.get('From'));
    const display = sender?.name || sender?.address || '';

    const phrase = display ? `${display} via anon.li` : 'Anonymous via anon.li';
    return `${encodeFromDisplayName(phrase)} <${aliasEmail}>`;
}

// Queues one message for delivery, byte for byte (see lib/raw-message.js for
// why outbound.send_email cannot be used).
async function queueRawMessage({ uuid, from, to, raw, notes }) {
    const txn = createTransaction(uuid);
    try {
        Object.assign(txn.notes, notes);
        txn.mail_from = from;
        txn.rcpt_to = [to];
        await writeRawMessage(txn, raw);

        await new Promise((resolve, reject) => {
            outbound.send_trans_email(txn, (code, msg) => {
                if (code === OK) resolve();
                else reject(new Error(`queueing failed: ${msg}`));
            });
        });
    } finally {
        // The queue file is written by now; drop the spool file of a large copy
        txn.message_stream.destroy();
    }
}

// `headers`: [name, value] pairs for the outer (unencrypted) message. Headers
// to DROP are removed before encryption — they may belong inside the entity.
async function buildEncryptedCopy(raw, publicKey, headers) {
    const drops = headers.filter(([, value]) => value === DROP);
    const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(setRawHeaders(raw, drops));
    const encryptedArmor = await pgpEncrypt.encryptMime(mimeEntity, publicKey);

    let block = transportHeaders;
    for (const [name, value] of headers) {
        if (value && value !== DROP) block = replaceHeaderInBlock(block, name, value);
    }
    return Buffer.from(pgpMime.buildPgpMimeMessage(block, encryptedArmor), 'latin1');
}

// Validates one recipient and mints its reply token. Returns null for an
// address that can never be delivered; throws on transient failures (token
// store).
async function prepareTarget(plugin, { recipient, originalSender, aliasEmail }) {
    let to;
    try {
        to = new Address(recipient.email);
    } catch (_err) {
        plugin.logerror(`Skipping invalid recipient address <${recipient.email}> of ${aliasEmail}`);
        return null;
    }
    // The website refuses recipients on alias domains (a forwarding loop that
    // data.loop_detect would reject); never queue one left over from old data.
    if ([OWN_DOMAIN, REPLY_DOMAIN].includes(domainOf(recipient.email))) {
        plugin.logerror(`Skipping recipient <${recipient.email}> of ${aliasEmail}: alias domains cannot be recipients`);
        return null;
    }

    // Every copy carries a reply token; without one the recipient's reply would
    // go straight to the sender from their real address. A token store outage
    // therefore tempfails the message instead of leaking.
    let replyTo = null;
    if (originalSender) {
        const token = await replyToken.create(originalSender, aliasEmail, recipient.email);
        replyTo = `${token}@${REPLY_DOMAIN}`;
    }
    return { recipient, to, replyTo };
}

// Builds one recipient's copy (`headers`: message-wide changes; `fromFor`:
// the copy's From, or null to keep it), PGP-encrypted when they have a key.
async function buildCopy(plugin, { recipient, replyTo }, { raw, headers, fromFor }) {
    const copyHeaders = [...headers, ['Reply-To', replyTo], ['From', fromFor(replyTo)]];

    if (recipient.pgpPublicKey) {
        try {
            return { encrypted: true, message: await buildEncryptedCopy(raw, recipient.pgpPublicKey, copyHeaders) };
        } catch (err) {
            plugin.logwarn(`PGP/MIME failed for ${recipient.email}, sending unencrypted: ${err.message}`);
        }
    }

    const message = setRawHeaders(raw, [
        ...copyHeaders,
        ['X-PGP-Encryption-Failed', recipient.pgpPublicKey ? 'true' : null],
    ]);
    return { encrypted: false, message };
}

// From for the forwarded copies. Senders publishing a strict DMARC policy get
// From rewritten onto an address we sign, otherwise the forward bounces at the
// receiver: the alias itself, or — for a custom domain without a usable DKIM
// key — the copy's reply address (reply.anon.li aligns with our anon.li
// signature, and replies to it route back correctly).
async function chooseFrom(plugin, txn, aliasEmail, aliasDomain) {
    if (!shouldMungeFrom(txn)) return { fromFor: () => null };

    const policy = txn.notes.mailauth.dmarc.policy;
    if (aliasDomain === OWN_DOMAIN || await dkimKeys.getKey(aliasDomain, plugin.config, (msg) => plugin.logerror(msg))) {
        plugin.loginfo(`DMARC ${policy} sender — rewriting From to align with ${aliasEmail}`);
        const from = buildMungedFrom(txn, aliasEmail);
        return { fromFor: () => from, dkimDomain: aliasDomain === OWN_DOMAIN ? null : aliasDomain };
    }
    plugin.logwarn(`DMARC ${policy} sender — no DKIM key for ${aliasDomain}, rewriting From onto the reply address`);
    return { fromFor: (replyTo) => buildMungedFrom(txn, replyTo || aliasEmail) };
}

// == FORWARD MODE == one queued copy per recipient (own Reply-To token, PGP).
async function forwardToRecipients(plugin, txn, next) {
    const aliasData = txn.notes.alias;
    const aliasEmail = aliasData.email;
    const aliasDomain = domainOf(aliasEmail);
    const sender = txn.mail_from?.address() || null;
    const originalSender = getOriginalSenderAddress(txn);

    // Rewrite the envelope sender using SRS (or a short bounce token when the
    // SRS address would exceed 64 octets); a null sender stays null.
    const envelope = await buildEnvelopeSender(sender, process.env.MAIL_API_SECRET);
    const from = envelopeAddress(envelope);

    txn.add_header('X-Anon-Forward', 'true');

    // Message-wide header changes, applied together with each copy's own
    const headers = FORWARD_DROPPED_HEADERS.map(name => [name, DROP]);

    // Tracking removal must never stand in the way of delivery
    let raw = await readRawMessage(txn);
    try {
        const tracking = await trackingRemove.removeTracking(raw, () => createTransaction());
        if (tracking.changed) {
            raw = tracking.raw;
            headers.push(['X-Privacy', 'Tracking-Removed']);
        }
    } catch (err) {
        plugin.logwarn(`Tracking removal skipped for ${txn.uuid}: ${err.message}`);
    }

    // Map the public Message-IDs of the user's earlier replies back to their
    // own, so their mail client threads the conversation (best effort)
    try {
        headers.push(...await mapThreadingHeaders(txn, values => messageIds.toClient(values, aliasEmail)));
    } catch (err) {
        plugin.logwarn(`Message-ID mapping skipped for ${txn.uuid}: ${err.message}`);
    }

    const { fromFor, dkimDomain } = await chooseFrom(plugin, txn, aliasEmail, aliasDomain);
    const notes = {
        forward: { aliasId: aliasData.id, aliasEmail },
        mailauth: txn.notes.mailauth,
    };
    if (dkimDomain) notes.dkim_domain = dkimDomain;

    // Validate every recipient and mint every reply token before queueing
    // anything, so a transient failure (token store) tempfails the message
    // without having delivered some copies — a retry would duplicate them.
    const targets = (await Promise.all(aliasData.recipients.map(recipient =>
        prepareTarget(plugin, { recipient, originalSender, aliasEmail })
    ))).filter(Boolean);
    if (targets.length === 0) {
        return next(DENY, 'No deliverable recipient for this alias');
    }

    // Build and queue the copies one at a time: each is a full copy of the
    // message (more with PGP armor), so this bounds memory per forward. Queueing
    // only fails on local queue errors (disk); tempfail on any — a retry may
    // duplicate the copies already queued, but no recipient silently misses it.
    let failed = 0;
    for (const [index, target] of targets.entries()) {
        try {
            const { encrypted, message } = await buildCopy(plugin, target, { raw, headers, fromFor });
            await queueRawMessage({ uuid: `${txn.uuid}-${index + 1}`, from, to: target.to, raw: message, notes });
            plugin.loginfo(`${encrypted ? 'PGP/MIME encrypted and sent' : 'Forwarded'} to ${target.to.address()}`);
        } catch (err) {
            failed++;
            plugin.logerror(`Queueing the copy of ${txn.uuid} for ${target.to.address()} failed: ${err.message}`);
        }
    }
    if (failed > 0) {
        return next(DENYSOFT, 'Forwarding error');
    }

    // Record stats — fire-and-forget, do not block delivery
    db.incrementAliasStats(aliasData.id, { forwarded: 1 })
        .catch(err => plugin.logerror(`Stats update failed: ${err.message}`));

    plugin.loginfo(`Forwarded ${txn.uuid} to ${targets.length}/${aliasData.recipients.length} recipient(s)`);
    return next(OK);
}

// Changed In-Reply-To / References values ([name, value] pairs) after passing
// their Message-IDs through `map` (one batched store lookup).
async function mapThreadingHeaders(txn, map) {
    const present = ['In-Reply-To', 'References']
        .map(name => [name, txn.header.get_all(name).map(v => v.replace(/\r?\n$/, '')).join(' ').trim()])
        .filter(([, value]) => value);
    if (present.length === 0) return [];

    const mapped = await map(present.map(([, value]) => value));
    return present
        .map(([name, value], i) => [name, mapped[i], value])
        .filter(([, newValue, value]) => newValue !== value)
        .map(([name, newValue]) => [name, newValue]);
}

function headerName(line) {
    const match = /^([^:\r\n]*):/.exec(line);
    return match ? match[1].trim().toLowerCase() : '';
}

// Removes every header not on the allowlist from what will be transmitted —
// including lines Haraka's parser did not index ("Name : value", no colon),
// which remove_header() cannot reach but the message stream still emits.
function sanitizeReplyHeaders(txn) {
    const header = txn.header;
    const lines = header.header_list;
    for (let i = lines.length - 1; i >= 0; i--) {
        const name = headerName(lines[i]);
        if (REPLY_HEADER_ALLOWLIST.has(name)) continue;
        lines.splice(i, 1);
        if (name) {
            delete header.headers[name];
            delete header.headers_decoded[name];
        }
    }
    txn.reset_headers();
}

// == REPLY MODE == the user's reply goes to the original sender as the alias.
async function sendReply(plugin, txn, next) {
    const replyData = txn.notes.reply;
    const recipient = replyData.originalSender;

    // The user's client Message-ID names their host: send a derived one, and
    // rewrite the IDs of their earlier replies listed in the threading headers.
    const clientId = messageIds.firstId(txn.header.get('Message-ID'));
    const threading = await mapThreadingHeaders(txn, messageIds.toPublic);
    if (clientId) await messageIds.remember(clientId, replyData.aliasEmail);

    sanitizeReplyHeaders(txn);
    for (const [name, value] of threading) {
        txn.remove_header(name);
        txn.add_header(name, value);
    }
    if (clientId) txn.add_header('Message-ID', messageIds.publicId(clientId));
    txn.add_header('From', replyData.aliasEmail);
    txn.add_header('To', recipient);

    // Sign with the alias's custom domain (SRS rewrites the envelope to @anon.li)
    const aliasDomain = domainOf(replyData.aliasEmail);
    if (aliasDomain !== OWN_DOMAIN) txn.notes.dkim_domain = aliasDomain;

    // The envelope is a relayable bounce token leading back to the alias, so a
    // bounced reply reaches the user — through the alias, with all of its
    // checks (a disabled alias receives nothing, not even bounces).
    txn.mail_from = await relayEnvelope(replyData.aliasEmail);
    try {
        txn.rcpt_to = [new Address(recipient)];
    } catch (_err) {
        return next(DENY, 'The original sender cannot receive replies');
    }

    plugin.loginfo(`Forwarding ${txn.uuid} (reply)`);
    outbound.send_trans_email(txn, next);
}

// == BOUNCE MODE == mail to one of our SRS / BNC= return paths.
async function relayBounce(plugin, txn, next) {
    const bounceData = txn.notes.bounce;

    // Bounces and auto-replies for forwarded mail come from the alias owner's
    // mailbox provider and name their real address (Final-Recipient,
    // Diagnostic-Code, Received "for <...>", an out-of-office From). Relaying
    // them to the external sender would de-anonymize the alias, so they are
    // accepted and dropped. Only reply return paths, which lead back to one of
    // our own aliases, are relayed.
    if (!bounceData.relay) {
        plugin.loginfo(`Dropping ${txn.uuid}: bounce for forwarded mail is not relayed to protect the recipient`);
        return next(OK);
    }

    txn.mail_from = new Address('<>');
    txn.rcpt_to = [new Address(bounceData.originalSender)];
    plugin.loginfo(`Forwarding ${txn.uuid} (bounce)`);
    outbound.send_trans_email(txn, next);
}

// == PURELYMAIL RELAY == reserved anon.li addresses go to the team mailbox.
async function relayToPurelymail(plugin, txn, next) {
    txn.notes.purelymail_mx = true;
    txn.rcpt_to = [new Address(txn.notes.purelymail_recipient)]; // a repeated RCPT is delivered once
    const sender = txn.mail_from?.address() || null;
    if (sender) {
        // A stateless SRS return path: anyone can mail a reserved address, so
        // nothing is stored per message. A rejection by Purelymail is reported
        // to the sender directly (handle_bounce); later asynchronous bounces to
        // the SRS address are not relayed.
        txn.notes.purelymail_original_sender = sender;
        txn.mail_from = new Address(await buildEnvelopeSender(sender, process.env.MAIL_API_SECRET));
    }
    plugin.loginfo(`Purelymail relay: ${txn.notes.purelymail_recipient}`);
    outbound.send_trans_email(txn, next);
}

exports.register = function () {
    outbound = this.haraka_require('outbound');
    const transaction = this.haraka_require('transaction');
    const cfg = this.config.get('connection.ini') || {};
    createTransaction = (uuid) => transaction.createTransaction(uuid || null, cfg);

    this.register_hook('queue', 'process_forward');
    this.register_hook('get_mx', 'route_mx');
    this.register_hook('bounce', 'handle_bounce');
};

// Whether a domain's mail exchanger is this host: domain -> { local, expires }.
// Answers (including "no MX") are cached, transient errors are not; the map is
// bounded.
const mxCache = new Map();
const MX_CACHE_TTL = 300000;
const MX_CACHE_MAX = 10000;

async function deliversToUs(domain, ourHost) {
    const key = String(domain || '').toLowerCase();
    if (key === OWN_DOMAIN || key === REPLY_DOMAIN) return true;

    const cached = mxCache.get(key);
    if (cached && cached.expires > Date.now()) return cached.local;

    let local;
    try {
        const mxs = await dns.resolveMx(key);
        local = mxs.some(mx => mx.exchange.toLowerCase().replace(/\.$/, '') === ourHost);
    } catch (err) {
        // No MX: not ours (cached). Transient failures are left to outbound.
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') return false;
        local = false;
    }
    if (mxCache.size >= MX_CACHE_MAX) mxCache.delete(mxCache.keys().next().value);
    mxCache.set(key, { local, expires: Date.now() + MX_CACHE_TTL });
    return local;
}

exports.route_mx = async function (next, hmail, domain) {
    if (hmail?.todo?.notes?.purelymail_mx) {
        return next(OK, [{ priority: 50, exchange: 'mailserver.purelymail.com' }]);
    }
    const ourHost = String(this.config.get('me') || '').trim().toLowerCase();
    if (await deliversToUs(domain, ourHost)) {
        return next(OK, [{ priority: 10, exchange: '127.0.0.1', port: 25 }]);
    }
    return next();
};

// Outbound delivery failed permanently. Haraka's default DSN goes to the
// envelope sender and quotes the final recipient — for a forwarded copy that is
// the alias owner's real address, so it would come straight back to the
// original sender (via SRS). Suppress it. Other DSNs carry nothing private and
// are addressed directly instead of looping through the return path: a bounced
// reply to the alias, a Purelymail relay to its original sender.
exports.handle_bounce = function (next, hmail, err) {
    const notes = hmail?.todo?.notes || {};
    if (notes.forward) {
        this.loginfo(`Suppressing DSN for failed forward from ${notes.forward.aliasEmail}: ${err?.message || err}`);
        return next(OK);
    }

    let returnTo = null;
    if (notes.reply) returnTo = notes.reply.aliasEmail;
    else if (notes.purelymail_relay) returnTo = notes.purelymail_original_sender;
    else return next();

    if (!returnTo) return next(OK);
    try {
        hmail.todo.mail_from = new Address(returnTo);
    } catch (_err) {
        return next(OK);
    }
    return next();
};

exports.process_forward = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    try {
        if (txn.notes.purelymail_relay) return await relayToPurelymail(plugin, txn, next);
        if (txn.notes.alias) return await forwardToRecipients(plugin, txn, next);
        if (txn.notes.reply) return await sendReply(plugin, txn, next);
        if (txn.notes.bounce) return await relayBounce(plugin, txn, next);
        return next();
    } catch (err) {
        plugin.logerror(`Forwarding ${txn.uuid} failed: ${err.stack || err}`);
        return next(DENYSOFT, 'Forwarding error');
    }
};

exports.getOriginalSenderAddress = getOriginalSenderAddress;
exports.setRawHeaders = setRawHeaders;
exports.replaceHeaderInBlock = replaceHeaderInBlock;
exports.encodeFromDisplayName = encodeFromDisplayName;
exports.shouldMungeFrom = shouldMungeFrom;
exports.buildMungedFrom = buildMungedFrom;
exports.buildEnvelopeSender = buildEnvelopeSender;
exports.sanitizeReplyHeaders = sanitizeReplyHeaders;
