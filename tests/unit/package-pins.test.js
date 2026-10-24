'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Guard for the Jun 20 2026 "Fix Haraka bug" rollback (commit 136d56d), made after a
// Tuta user saw verification mail arrive with "a major missing part" on Haraka 3.3.x.
// Re-examined Oct 2026: Haraka 3.1.7 and 3.3.5 re-emit multipart messages
// byte-identically, and the likely cause was outbound dot-stuffing — forwarded copies
// went through send_email's stream path, which stores lines unstuffed, so a body line
// of "." ended DATA early on either version (fixed in lib/raw-message.js). 3.3.5 passes
// this test suite. The pin stays so production runs the version validated end to end;
// bump deliberately, after the full suite (with TEST_DATABASE_URL) and a live smoke test.
describe('package.json dependency pins', () => {
    const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8')
    );

    it('keeps Haraka pinned to the 3.1.x line (no caret, no 3.2+/3.3)', () => {
        const version = pkg.dependencies?.Haraka;
        assert.ok(version, 'Haraka dependency must be present in package.json');
        // Accept "~3.1.x" or an exact "3.1.x"; reject "^3.1.x" (allows 3.x) and any 3.2+/3.3.
        assert.match(
            version,
            /^~?3\.1\.\d+$/,
            `Haraka must stay on the 3.1.x line (got "${version}") — see commit 136d56d "Fix Haraka bug"`
        );
    });
});
