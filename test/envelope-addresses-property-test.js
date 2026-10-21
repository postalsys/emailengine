'use strict';

// Property tests for the SMTP envelope getRawEmail() builds from a raw message's headers, over
// generated To/Cc/Bcc headers mixing plain mailboxes, display names (plain and encoded), groups,
// IDN domains in punycode, and addresses hiding an encoded word. Whatever the mix, the envelope
// lists exactly the plain addresses, in ASCII form, each once, and never an empty one or one an
// encoded word produced.

const test = require('node:test');
const assert = require('node:assert').strict;

const { getRawEmail } = require('../lib/get-raw-email');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { forAll, gen } = require('./helpers/property');

registerRedisTeardown(redis);

const b64word = text => `=?utf-8?B?${Buffer.from(text).toString('base64')}?=`;

const local = gen.oneOf(['alice', 'bob', 'carol', 'd.ave', 'e+tag']);
const domain = gen.oneOf(['example.com', 'example.org', 'xn--mnchen-3ya.de', 'xn--bcher-kva.example']);
const name = gen.oneOf(['', 'Plain Name', '"Doe, John"', b64word('Jõe'), b64word('Team: x@evil.example;')]);

// One generated entry: the header text and the envelope addresses it must contribute
const mailbox = random => {
    const address = `${local(random)}@${domain(random)}`;
    const display = name(random);
    return { text: display ? `${display} <${address}>` : address, addresses: [address] };
};
const hiddenAddress = random => ({
    // an encoded word in the address part names some other address; it must not become a recipient
    text: `${b64word('ceo@bank.example')}@${domain(random)}`,
    addresses: []
});
const group = random => {
    const members = gen.array(mailbox, 0, 3)(random);
    return { text: `Team ${gen.integer(1, 9)(random)}: ${members.map(member => member.text).join(', ')};`, addresses: members.flatMap(m => m.addresses) };
};
const entry = random => {
    const pick = random();
    return pick < 0.6 ? mailbox(random) : pick < 0.8 ? group(random) : hiddenAddress(random);
};
const header = gen.array(entry, 0, 4);

test('the envelope lists exactly the plain addresses of To, Cc and Bcc', async () => {
    await forAll(gen.record({ to: header, cc: header, bcc: header }), async ({ to, cc, bcc }) => {
        const lines = ['From: Sender <sender@example.com>'];
        for (const [key, entries] of [
            ['To', to],
            ['Cc', cc],
            ['Bcc', bcc]
        ]) {
            if (entries.length) {
                lines.push(`${key}: ${entries.map(e => e.text).join(', ')}`);
            }
        }
        const raw = Buffer.from([...lines, 'Subject: property', '', 'Body'].join('\r\n'));
        const { envelope } = await getRawEmail({ raw }, null);

        const expected = [...new Set([...to, ...cc, ...bcc].flatMap(e => e.addresses))];
        assert.deepStrictEqual(envelope.to, expected, lines.join('\n'));
        assert.strictEqual(envelope.from, 'sender@example.com');
        for (const address of envelope.to) {
            assert.match(address, /^[\x21-\x7e]+@[a-z0-9.-]+$/, 'ASCII, no encoded word, not empty');
        }
    });
});
