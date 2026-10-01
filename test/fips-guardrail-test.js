'use strict';

// A host whose OpenSSL runs in FIPS mode offers no MD5, no scrypt and no Ed25519. EmailEngine does
// not detect that mode; it stops using those primitives for every installation. Two of them are
// library defaults (ImapFlow's fallback message id, mailparser's attachment checksum), so each of
// those libraries is reached through one module that overrides the default, and this pins that
// nothing goes around it. The third is the passkey registration algorithm list.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const { listFiles } = require('./helpers/list-files');

const ROOT = path.join(__dirname, '..');

// Where production code lives. The IMAP proxy core carries a test client of its own under lib
const SOURCE_FILES = [...['lib', 'workers'].flatMap(dir => listFiles(path.join(ROOT, dir), '.js')), path.join(ROOT, 'server.js')]
    .map(file => path.relative(ROOT, file))
    .filter(rel => !rel.startsWith('lib/imapproxy/imap-core/test/'));

const sources = new Map(SOURCE_FILES.map(rel => [rel, fs.readFileSync(path.join(ROOT, rel), 'utf-8')]));

const filesMatching = pattern => SOURCE_FILES.filter(rel => pattern.test(sources.get(rel)));

test('FIPS guardrails', async t => {
    await t.test('every ImapFlow client is created by lib/create-imap-client.js', () => {
        assert.deepStrictEqual(filesMatching(/\bnew ImapFlow\s*\(/), ['lib/create-imap-client.js']);
    });

    await t.test('every message is parsed through lib/parse-message.js', () => {
        assert.deepStrictEqual(filesMatching(/\b(simpleParser|new MailParser)\s*\(/), ['lib/parse-message.js']);
    });

    await t.test('passkeys are registered without EdDSA', () => {
        const source = sources.get('lib/ui-routes/auth-routes.js');
        assert.match(source, /const PASSKEY_ALGORITHMS = \[-7, -257\];/);
        for (const call of ['generateRegistrationOptions({', 'verifyRegistrationResponse({']) {
            const index = source.indexOf(call);
            assert.ok(index >= 0, call);
            const block = source.substring(index, source.indexOf('});', index));
            assert.ok(block.includes('supportedAlgorithmIDs: PASSKEY_ALGORITHMS'), `${call} does not pass PASSKEY_ALGORITHMS`);
        }
    });
});
