'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { splitAddress, domainOf, sameMailbox, firstMailbox } = require('../../lib/address');

describe('address helpers', () => {
    it('splits at the last @ and lowercases the domain', () => {
        assert.deepEqual(splitAddress('"a@b" Me@Example.COM'.split(' ')[1]), { local: 'Me', domain: 'example.com' });
        assert.equal(splitAddress('no-at'), null);
        assert.equal(splitAddress('@x.y'), null);
        assert.equal(domainOf('a@Sub.Example.org'), 'sub.example.org');
    });

    it('matches a sender to a registered address without case, its +tag and Gmail dots', () => {
        assert.equal(sameMailbox('Bob@X.example', 'bob@x.example'), true);
        assert.equal(sameMailbox('bob@x.example', 'bob+anon@x.example'), true);
        assert.equal(sameMailbox('johndoe@gmail.com', 'John.Doe+anon@GoogleMail.com'), true);
        assert.equal(sameMailbox('bob+x@x.example', 'bob@x.example'), false, 'a sender tag is never ignored');
        assert.equal(sameMailbox('first.last@example.net', 'firstlast@example.net'), false, 'dots matter outside Gmail');
        assert.equal(sameMailbox('', 'bob@x.example'), false);
    });

    it('returns the first mailbox of a header with its unquoted display name', () => {
        assert.deepEqual(firstMailbox('"Doe, John" <j@x.example>, other@y.example'), { address: 'j@x.example', name: 'Doe, John' });
        assert.deepEqual(firstMailbox('plain@x.example'), { address: 'plain@x.example', name: '' });
        assert.equal(firstMailbox('not an address'), null);
        assert.equal(firstMailbox(''), null);
    });
});
