'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// History: on Jun 20 2026 (commit 136d56d "Fix Haraka bug") production was rolled
// back from Haraka 3.3.x to 3.1.7 after a Tuta user saw verification mail arrive
// with "a major missing part". Re-examined Oct 2026: both versions re-emit
// multipart messages byte-identically; the likely cause was outbound dot-stuffing
// — forwarded copies went through send_email's stream path, which stores lines
// unstuffed, so a body line of "." ended DATA early on either version (fixed in
// lib/raw-message.js).
//
// Oct 2026: moved to 3.3.5 (package renamed to lowercase "haraka") for the retry
// timing fix for deferrals reloaded at startup and the SMTP smuggling / bounce
// injection fixes. Since 3.2, envelope addresses are @haraka/email-address objects
// whose `address` is a getter, not address-rfc2821's method — plugins and the
// vendored plugins/mailauth.js read it as a property. The pin stays on a tilde
// range: bump deliberately, after the full suite (with TEST_DATABASE_URL) and a
// live smoke test.
describe('package.json dependency pins', () => {
    const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8')
    );

    it('keeps Haraka pinned to the 3.3.x line (no caret)', () => {
        const version = pkg.dependencies?.haraka;
        assert.ok(version, 'haraka dependency must be present in package.json');
        assert.equal(pkg.dependencies?.Haraka, undefined, 'the old "Haraka" package name must not be installed alongside');
        // Accept "~3.3.x" or an exact "3.3.x"; reject "^3.3.x" (allows any 3.x).
        assert.match(
            version,
            /^~?3\.3\.\d+$/,
            `Haraka must stay on the 3.3.x line (got "${version}") — bump deliberately, see the note above`
        );
    });

    it('uses the same address library as Haraka core', () => {
        // Addresses we assign to txn.mail_from / rcpt_to / hmail.todo are read
        // by Haraka core; a second address library there breaks outbound.
        assert.equal(pkg.dependencies?.['address-rfc2821'], undefined);
        assert.ok(pkg.dependencies?.['@haraka/email-address']);
    });
});
