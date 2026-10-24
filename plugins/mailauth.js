'use strict';

// SPF, DKIM, ARC, DMARC and BIMI verification (results in txn.notes.mailauth).
//
// Vendored from haraka-plugin-mailauth 1.1.1, unmaintained since 2024. Its MAIL
// hook read the envelope sender with address-rfc2821's address() method; since
// Haraka 3.2 envelope addresses are @haraka/email-address objects, whose
// `address` is a getter, so that call threw on every message. The only change
// from upstream is reading that getter.
//
// MIT License
//
// Copyright (c) 2022 Postal Systems
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const dns = require('node:dns');

const { PassThrough } = require('node:stream');
const { arc } = require('mailauth/lib/arc');
const { dmarc } = require('mailauth/lib/dmarc');
const { spf: checkSpf } = require('mailauth/lib/spf');
const { dkimVerify } = require('mailauth/lib/dkim/verify');
const { bimi } = require('mailauth/lib/bimi');

exports.register = function () {
    this.load_config();

    this.resolver = async (name, rr) => await dns.promises.resolve(name, rr);

    this.register_hook('helo', 'mailauth_helo');
    this.register_hook('ehlo', 'mailauth_helo');
};

exports.load_config = function () {
    this.cfg = this.config.get('mailauth.yaml', {}, () => this.load_config());
};

exports.mailauth_helo = function (next, connection, helo) {
    connection.notes.mailauth_helo = helo;
    next();
};

exports.mailauth_add_result = function (txn, key, domain, result) {
    const resultName = `${key}[${domain}]`;

    switch (result) {
        case 'pass':
            txn.results.add(this, { pass: resultName });
            break;
        case 'fail':
            txn.results.add(this, { fail: resultName });
            break;
        case 'neutral':
        case 'policy':
            txn.results.add(this, { skip: resultName });
            break;
        case 'permerror':
        case 'temperror':
            txn.results.add(this, { fail: resultName });
            break;
        case 'none':
        default:
            // ignore;
            break;
    }
};

exports.hook_mail = function (next, connection, params) {
    const plugin = this;

    const txn = connection?.transaction;
    if (!txn) {
        return next();
    }

    // Step 1. SPF

    const sender = params[0]?.address || '';
    txn.notes.mailauth = {
        sender
    };

    checkSpf({
        resolver: plugin.resolver,
        ip: connection.remote.ip, // SMTP client IP
        helo: connection.hello.host, // EHLO/HELO hostname
        sender, // MAIL FROM address
        mta: connection.local.host, // MX hostname
        maxResolveCount: plugin.cfg.dns?.maxLookups
    })
        .then(spfResult => {
            txn.notes.mailauth.spf = spfResult;
            plugin.mailauth_add_result(txn, 'spf', spfResult?.domain, spfResult?.status?.result);

            if (spfResult.header) {
                txn.add_leading_header('Received-SPF', spfResult.header.substring(spfResult.header.indexOf(':') + 1).trim());
            }

            if (spfResult.info) {
                connection.auth_results(spfResult.info);
            }

            next();
        })
        .catch(err => {
            txn.notes.mailauth.spf = { error: err };
            txn.results.add(plugin, { err: 'spf' });
            plugin.logerror(err, plugin, connection);
            next();
        });
};

async function hookDataPostAsync(stream, plugin, connection) {
    const txn = connection.transaction;

    // Step 2. DKIM
    let dkimResult;
    try {
        dkimResult = await dkimVerify(stream, {
            resolver: plugin.resolver,
            sender: txn.notes.mailauth.sender,
            seal: null,
            minBitLength: plugin.cfg.minBitLength
        });
        txn.notes.mailauth.dkim = dkimResult;
        for (let result of dkimResult?.results || []) {
            plugin.mailauth_add_result(txn, 'dkim', result?.signingDomain, result?.status?.result);

            if (result.info) {
                connection.auth_results(result.info);
            }
        }
    } catch (err) {
        txn.notes.mailauth.dkim = { error: err };
        txn.results.add(plugin, { err: 'dkim' });
        plugin.logerror(err, plugin, connection);
    }

    // Step 3. ARC
    let arcResult;
    if (dkimResult?.arc) {
        try {
            arcResult = await arc(dkimResult.arc, {
                resolver: plugin.resolver,
                minBitLength: plugin.cfg.minBitLength
            });
            txn.notes.mailauth.arc = arcResult;
            plugin.mailauth_add_result(txn, 'arc', arcResult?.signature?.signingDomain, arcResult?.status?.result);

            if (arcResult.info) {
                connection.auth_results(arcResult.info);
            }
        } catch (err) {
            txn.notes.mailauth.arc = { error: err };
            txn.results.add(plugin, { err: 'arc' });
            plugin.logerror(err, plugin, connection);
        }
    }

    // Step 4. DMARC
    let dmarcResult;
    let spfResult = txn.notes.mailauth.spf;
    if (dkimResult?.headerFrom) {
        try {
            dmarcResult = await dmarc({
                resolver: plugin.resolver,
                headerFrom: dkimResult.headerFrom,
                spfDomains: [].concat((spfResult?.status?.result === 'pass' && spfResult?.domain) || []),
                dkimDomains: (dkimResult.results || []).filter(r => r.status.result === 'pass').map(r => r.signingDomain),
                arcResult
            });
            txn.notes.mailauth.dmarc = dmarcResult;
            plugin.mailauth_add_result(txn, 'dmarc', dmarcResult?.domain, dmarcResult?.status?.result);

            if (dmarcResult.info) {
                connection.auth_results(dmarcResult.info);
            }
        } catch (err) {
            txn.notes.mailauth.dmarc = { error: err };
            txn.results.add(plugin, { err: 'dmarc' });
            plugin.logerror(err, plugin, connection);
        }
    }

    // Step 5. BIMI
    let bimiResult;
    if (dmarcResult) {
        try {
            bimiResult = await bimi({
                resolver: plugin.resolver,
                dmarc: dmarcResult,
                headers: dkimResult.headers
            });
            txn.notes.mailauth.bimi = bimiResult;
            plugin.mailauth_add_result(txn, 'bimi', bimiResult?.status?.header?.d, bimiResult?.status?.result);

            if (bimiResult.info) {
                connection.auth_results(bimiResult.info);
            }

            txn.remove_header('bimi-location');
            txn.remove_header('bimi-indicator');
        } catch (err) {
            txn.notes.mailauth.bimi = { error: err };
            txn.results.add(plugin, { err: 'bimi' });
            plugin.logerror(err, plugin, connection);
        }
    }
}

exports.hook_data_post = function (next, connection) {
    const plugin = this;

    const txn = connection?.transaction;
    if (!txn) {
        return next();
    }

    const stream = new PassThrough();
    hookDataPostAsync(stream, plugin, connection)
        .then(() => {
            next();
        })
        .catch(err => {
            plugin.logerror(err, plugin, connection);
            next();
        });

    txn.message_stream.pipe(stream, { line_endings: '\r\n' });
};
