'use strict';

// What every connection EmailEngine opens is held to, whichever code path opens it:
//
//   - lib/create-imap-client.js passes explicit response-size caps to ImapFlow and turns the
//     account-level `requireTLS` into ImapFlow's `doSTARTTLS`, so a cleartext IMAP connection must
//     upgrade and a server (or an attacker on the path) that offers no STARTTLS cannot get the
//     password in cleartext
//   - lib/utils/require-tls.js does the same for every SMTP transport (an account's server, a
//     gateway, the verification probe)
//   - lib/email-client/imap/response-metrics.js keeps server-chosen atoms out of Prometheus labels

const test = require('node:test');
const assert = require('node:assert').strict;

const { imapClientOptions } = require('../lib/create-imap-client');
const { applyRequireTls } = require('../lib/utils/require-tls');
const { imapResponseLabels } = require('../lib/email-client/imap/response-metrics');
const { IMAP_MAX_LINE_LENGTH, IMAP_MAX_LITERAL_SIZE, IMAP_MAX_RESPONSE_SIZE, MAX_ALLOWED_DOWNLOAD_SIZE } = require('../lib/consts');

test('ImapFlow options', async t => {
    await t.test('every connection carries the response-size caps', () => {
        const options = imapClientOptions({ host: 'imap.example.com', port: 993, secure: true });
        assert.equal(options.maxLineLength, IMAP_MAX_LINE_LENGTH);
        assert.equal(options.maxLiteralSize, IMAP_MAX_LITERAL_SIZE);
        assert.equal(options.maxResponseSize, IMAP_MAX_RESPONSE_SIZE);
        assert.equal(options.idHashAlgorithm, 'sha256');
        // a whole-message download is one literal, and the response cap sits above the literal
        // cap the way ImapFlow documents it
        assert.ok(IMAP_MAX_LITERAL_SIZE > MAX_ALLOWED_DOWNLOAD_SIZE);
        assert.ok(IMAP_MAX_RESPONSE_SIZE > IMAP_MAX_LITERAL_SIZE);
    });

    await t.test('a cleartext connection requires STARTTLS unless the account opts out', () => {
        assert.equal(imapClientOptions({ host: 'h', port: 143, secure: false }).doSTARTTLS, true);
        assert.equal(imapClientOptions({ host: 'h', port: 143 }).doSTARTTLS, true, 'secure left unset');
        assert.equal(imapClientOptions({ host: 'h', port: 143, secure: false, requireTLS: true }).doSTARTTLS, true);
    });

    // Opting out makes the upgrade opportunistic, as it is for SMTP, rather than switching
    // STARTTLS off: a server that offers it is still used encrypted
    await t.test('the opt-out leaves STARTTLS opportunistic', () => {
        assert.equal('doSTARTTLS' in imapClientOptions({ host: 'h', port: 143, secure: false, requireTLS: false }), false);
    });

    await t.test('a connection that is TLS from the start is left alone', () => {
        // doSTARTTLS and secure together are a misconfiguration ImapFlow refuses
        const options = imapClientOptions({ host: 'h', port: 993, secure: true, requireTLS: true });
        assert.equal('doSTARTTLS' in options, false);
    });

    await t.test("requireTLS is EmailEngine's field and does not reach ImapFlow", () => {
        assert.equal('requireTLS' in imapClientOptions({ host: 'h', port: 143, requireTLS: false }), false);
    });

    await t.test('an explicit doSTARTTLS and explicit caps win', () => {
        const options = imapClientOptions({ host: 'h', port: 143, doSTARTTLS: false, maxLiteralSize: 1024 });
        assert.equal(options.doSTARTTLS, false);
        assert.equal(options.maxLiteralSize, 1024);
    });
});

test('SMTP transports require STARTTLS unless the configuration opts out', async t => {
    await t.test('a cleartext transport asks for the upgrade', () => {
        assert.equal(applyRequireTls({ host: 'h', port: 587, secure: false }).requireTLS, true);
        assert.equal(applyRequireTls({ host: 'h', port: 25 }).requireTLS, true);
        assert.equal(applyRequireTls({ host: 'h', port: 25, requireTLS: true }).requireTLS, true);
    });

    await t.test('the stored opt-out is honoured', () => {
        assert.equal(applyRequireTls({ host: 'h', port: 25, requireTLS: false }).requireTLS, false);
    });

    await t.test('a direct TLS transport needs no upgrade', () => {
        assert.equal('requireTLS' in applyRequireTls({ host: 'h', port: 465, secure: true, requireTLS: true }), false);
    });

    await t.test('tolerates no configuration at all', () => {
        assert.equal(applyRequireTls(null), null);
    });
});

test('IMAP response metrics only carry the known vocabulary as labels', async t => {
    await t.test('known statuses and codes pass through', () => {
        assert.deepEqual(imapResponseLabels({ response: 'OK' }), { response: 'OK' });
        assert.deepEqual(imapResponseLabels({ response: 'NO', code: 'AUTHENTICATIONFAILED' }), { response: 'NO', code: 'AUTHENTICATIONFAILED' });
        assert.deepEqual(imapResponseLabels({ response: 'ok', code: 'alert' }), { response: 'OK', code: 'ALERT' });
    });

    await t.test('anything the server made up is counted as other', () => {
        // each distinct label value would be a new series held for the life of the process
        assert.deepEqual(imapResponseLabels({ response: 'OK', code: 'X-RANDOM-' + Date.now() }), { response: 'OK', code: 'other' });
        assert.deepEqual(imapResponseLabels({ response: 'WHATEVER' }), { response: 'other' });
        assert.deepEqual(imapResponseLabels({ response: 'OK', code: 42 }), { response: 'OK', code: 'other' });
        assert.deepEqual(imapResponseLabels(null), { response: 'other' });
    });
});
