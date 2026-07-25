'use strict';

// Wire-level tests for the Microsoft Graph `/sendMail` request that outlook-client.js issues.
//
// This file used to assert only that Node's own Buffer.toString('base64') round-trips, so it
// could not fail no matter how the Outlook send path broke. It now drives the real
// OutlookOauth.request() against a local HTTP server and asserts what the raw-MIME send path in
// lib/email-client/outlook-client.js actually puts on the wire:
//
//   await this.request(`/${this.oauth2UserPath}/sendMail`, 'post', Buffer.from(raw.toString('base64')), {
//       contentType: 'text/plain',
//       returnText: true
//   });
//
// test/oauth-request-dispatch-test.js already covers that a Buffer body is not JSON-quoted; the
// cases here are the ones it does not: the content type Graph requires, payload integrity for
// large and binary messages, the structured-format branch, and how a rejection surfaces.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookOauth } = require('../lib/oauth/outlook');
const { buildRawSendMailRequest, buildStructuredSendMailRequest } = require('../lib/email-client/outlook/send-request');
const { withCapturingServer } = require('./helpers/capture-http-server');

function createOutlook() {
    return new OutlookOauth({
        clientId: 'test-id',
        clientSecret: 'test-secret',
        redirectUrl: 'http://localhost/callback',
        authority: 'common',
        setFlag: async () => {}
    });
}

// Issues the raw-MIME send through the REAL request builder that outlook-client.js calls, so the
// path, the base64 body and the content type all come from production code. Hand-copying them
// here (as this file used to) meant the assertions below were checking the test's own constants,
// and lib/email-client/outlook-client.js could stop base64-encoding the message entirely without
// anything failing.
async function sendRaw(baseUrl, raw) {
    const sendRequest = buildRawSendMailRequest(raw, 'me');
    return await createOutlook().request('fake-token', `${baseUrl}${sendRequest.path}`, 'post', sendRequest.body, sendRequest.options);
}

test('Outlook sendMail base64 encoding tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('the request targets the sendMail endpoint of the configured user path', async () => {
        // A shared mailbox sends as /users/<id>/sendMail, a normal account as /me/sendMail.
        assert.equal(buildRawSendMailRequest(Buffer.from('x'), 'me').path, '/me/sendMail');
        assert.equal(buildRawSendMailRequest(Buffer.from('x'), 'users/shared@example.com').path, '/users/shared@example.com/sendMail');
        assert.equal(buildStructuredSendMailRequest({ subject: 'x' }, 'me').path, '/me/sendMail');
    });

    await t.test('the raw MIME message reaches Graph base64 encoded as text/plain', async () => {
        await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
            const raw = Buffer.from(
                'From: sender@example.com\r\n' +
                    'To: recipient@example.com\r\n' +
                    'Subject: Test Message\r\n' +
                    'Content-Type: text/plain\r\n' +
                    '\r\n' +
                    'This is the message body.'
            );

            await sendRaw(baseUrl, raw);

            const captured = getCaptured();
            assert.equal(captured.method, 'POST');
            assert.equal(captured.headers['content-type'], 'text/plain', 'Graph rejects sendMail bodies sent as application/json');
            assert.deepEqual(Buffer.from(captured.body.toString(), 'base64'), raw, 'the decoded body must be the original MIME message byte for byte');
        });
    });

    // A truncated, re-chunked or utf-8 round-tripped body would show up in the decode. The large
    // case crosses several socket writes; the binary case covers every byte value 0x00-0xFF.
    const binary = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) {
        binary[i] = i;
    }

    for (const [label, raw] of [
        ['a large message', Buffer.from('From: sender@example.com\r\nSubject: Large Test\r\n\r\n' + 'A'.repeat(100000))],
        ['binary attachment bytes', Buffer.concat([Buffer.from('From: sender@example.com\r\nSubject: Binary\r\n\r\n'), binary])]
    ]) {
        await t.test(`${label} survives the round trip to Graph intact`, async () => {
            await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
                await sendRaw(baseUrl, raw);
                assert.deepEqual(Buffer.from(getCaptured().body.toString(), 'base64'), raw);
            });
        });
    }

    await t.test('the structured-format send posts JSON, not base64', async () => {
        // The useStructuredFormat branch sends a plain object so Graph honours an explicit
        // "from" address (Graph ignores the From header of a raw MIME body).
        await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
            const messagePayload = { subject: 'Structured', from: { emailAddress: { address: 'sender@example.com' } } };
            const sendRequest = buildStructuredSendMailRequest(messagePayload, 'me');

            await createOutlook().request('fake-token', `${baseUrl}${sendRequest.path}`, 'post', sendRequest.body, sendRequest.options);

            const captured = getCaptured();
            assert.equal(captured.headers['content-type'], 'application/json');
            assert.deepEqual(JSON.parse(captured.body.toString()), { message: messagePayload });
        });
    });

    await t.test('a Graph rejection surfaces the provider status for delivery classification', async () => {
        const respondWith400 = res => {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { code: 'ErrorInvalidRecipients', message: 'Invalid message format' } }));
        };

        await withCapturingServer(respondWith400, async ({ baseUrl }) => {
            await assert.rejects(
                () => sendRaw(baseUrl, Buffer.from('Subject: x\r\n\r\nbody')),
                err => {
                    // outlook-client.js switches on err.oauthRequest.status to build the submit error
                    assert.equal(err.oauthRequest.status, 400);
                    assert.equal(err.oauthRequest.response.error.code, 'ErrorInvalidRecipients');
                    // No SMTP reply code is forged here - lib/delivery-error.js must not read this as a hard bounce
                    assert.equal(err.responseCode, undefined);
                    return true;
                }
            );
        });
    });
});
