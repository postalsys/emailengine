'use strict';

// Guardrail for how the Let's Encrypt certificate handler is built.
//
// Three workers need one: the API worker, which is the only one that provisions, and the SMTP
// server and the IMAP proxy, which read what it stored. They used to construct it separately with
// the same twenty lines each, and two of the three passed `environment` at the top level of the
// options, where the constructor never reads it - so those two silently ran with the default
// environment and the Let's Encrypt staging directory. Nothing failed, because they never
// provision, and nothing would have until one of them did.
//
// lib/cert-handler.js is now the one place that builds it. This keeps it that way.
//
// Pure: reads the sources, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { ACME_DIRECTORY_URL } = require('../lib/consts');

const ROOT = pathlib.join(__dirname, '..');
const FACTORY = 'lib/cert-handler.js';

// Where production code lives. node_modules and the test tree are not ours to police.
const SOURCE_DIRS = ['lib', 'workers'];

test('only lib/cert-handler.js constructs the certificate handler', () => {
    const offenders = [];

    for (const dir of SOURCE_DIRS) {
        for (const file of listFiles(pathlib.join(ROOT, dir), '.js')) {
            const rel = pathlib.relative(ROOT, file);
            if (rel === FACTORY) {
                continue;
            }
            const source = fs.readFileSync(file, 'utf-8');
            if (/\bnew Certs\s*\(/.test(source) || /require\(['"]@postalsys\/certs['"]\)/.test(source)) {
                offenders.push(rel);
            }
        }
    }

    assert.deepEqual(
        offenders,
        [],
        `these files reach for @postalsys/certs directly; call createCertHandler() from ${FACTORY} instead, ` +
            'so every worker gets the same ACME account, directory and encryption'
    );
});

test('every caller goes through the factory', () => {
    // The inverse of the check above: the three workers that need a handler still get one.
    for (const file of ['workers/api.js', 'workers/smtp.js', 'lib/imapproxy/imap-server.js']) {
        const source = fs.readFileSync(pathlib.join(ROOT, file), 'utf-8');
        assert.match(source, /createCertHandler\(/, `${file} builds its certificate handler through the factory`);
    }
});

test('the shared ACME directory is the production one', () => {
    // The staging directory is the one to point at while testing issuance, and it is easy to leave
    // behind. Staging certificates are signed by an untrusted root, so shipping one means every
    // client that reaches this instance over TLS refuses the certificate.
    assert.equal(ACME_DIRECTORY_URL, 'https://acme-v02.api.letsencrypt.org/directory');
});

test('the renewal check asks the CA rather than deciding on its own', () => {
    // checkRenewalDue() consults ACME Renewal Information and falls back to the lifetime rule. The
    // exported isRenewalDue() answers from the stored record alone, so it never learns that Let's
    // Encrypt has asked for an early renewal, which is what a mass revocation produces. Asserted on
    // the import rather than on the call, because a function that is not imported cannot be called.
    const source = fs.readFileSync(pathlib.join(ROOT, 'workers', 'api.js'), 'utf-8');

    assert.match(source, /certHandler\.checkRenewalDue\(/, 'the renewal timer asks the CA');
    assert.doesNotMatch(source, /require\(['"]@postalsys\/certs['"]\)/, 'nothing is imported from the library directly');
});
