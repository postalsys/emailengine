'use strict';

// ImapFlow flags every failed AUTHENTICATE as `authenticationFailed`, and the IMAP client used to
// report the flag as a refused credential - including Exchange Online's "User is authenticated but
// not connected.", which is its front end failing to reach the mailbox behind a token it had just
// accepted. One 17 minute outage (Seedlink, 2026-09-10) cost eight `authenticationError` webhooks
// and an `authenticationSuccess` for a single account. isRefusedImapLogin() is the line between the
// server's problem and the credential's.
//
// Pure: no Redis, no lib/tools - the module under test is dependency-free so that the subconnection
// tests can stay that way too.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const path = require('path');

const { isRefusedImapLogin, imapResponseText } = require('../lib/email-client/imap/login-failure');

// What ImapFlow throws for a failed AUTHENTICATE: the flag, the response line and its text, and the
// bracketed code when the server sent one
const loginError = fields => Object.assign(new Error('Command failed'), { authenticationFailed: true }, fields);

test('isRefusedImapLogin', async t => {
    await t.test('a rejected credential is a refusal', () => {
        // Gmail and Yahoo answer with the RFC 5530 code
        assert.equal(
            isRefusedImapLogin(
                loginError({
                    serverResponseCode: 'AUTHENTICATIONFAILED',
                    response: '3 NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)',
                    responseText: 'Invalid credentials (Failure)'
                })
            ),
            true
        );
        for (const code of ['AUTHORIZATIONFAILED', 'EXPIRED', 'PRIVACYREQUIRED']) {
            assert.equal(
                isRefusedImapLogin(loginError({ serverResponseCode: code, response: `3 NO [${code}] Login failed` })),
                true,
                `${code} is a verdict on the credential`
            );
        }
        // Exchange Online answers a rejected token with no code at all
        assert.equal(isRefusedImapLogin(loginError({ response: '3 NO AUTHENTICATE failed.', responseText: 'AUTHENTICATE failed.' })), true);
    });

    await t.test('a server that could not serve the login is not', () => {
        for (const code of ['UNAVAILABLE', 'SERVERBUG', 'INUSE', 'LIMIT']) {
            assert.equal(
                isRefusedImapLogin(loginError({ serverResponseCode: code, response: `3 NO [${code}] Temporary authentication failure` })),
                false,
                `${code} is the server's problem`
            );
        }
        // The code decides on its own, whatever the text next to it says
        assert.equal(isRefusedImapLogin(loginError({ serverResponseCode: 'UNAVAILABLE', response: '3 NO [UNAVAILABLE] Invalid credentials' })), false);
    });

    await t.test('Exchange Online failing behind an accepted token is not', () => {
        // The attached log: eight of these in nine minutes, then a login with the same token
        assert.equal(
            isRefusedImapLogin(
                loginError({ response: '3 NO User is authenticated but not connected.', responseText: 'User is authenticated but not connected.' })
            ),
            false
        );
        // ImapFlow reports the same condition off a failed NAMESPACE, with the bare text as the response
        assert.equal(isRefusedImapLogin(loginError({ response: 'User is authenticated but not connected.' })), false);
    });

    await t.test('a failure ImapFlow did not flag is not a refusal either', () => {
        assert.equal(isRefusedImapLogin(Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' })), false);
        assert.equal(isRefusedImapLogin(Object.assign(new Error('Command failed'), { response: '3 NO AUTHENTICATE failed.' })), false);
        assert.equal(isRefusedImapLogin(null), false);
    });

    await t.test('a flagged failure nothing more is known about stays a refusal', () => {
        // Only text or a code can clear the flag; a parsed response object is neither
        assert.equal(isRefusedImapLogin(loginError({ response: { status: 'NO', text: 'User is authenticated but not connected.' } })), true);
    });
});

test('imapResponseText', () => {
    // The response line when ImapFlow rewrote it for a login failure, the text field for any other
    // command (where response is the parsed object), nothing when the error carries neither
    assert.equal(imapResponseText({ response: '3 NO AUTHENTICATE failed.', responseText: 'AUTHENTICATE failed.' }), '3 NO AUTHENTICATE failed.');
    assert.equal(imapResponseText({ response: { status: 'NO' }, responseText: 'Server error' }), 'Server error');
    assert.equal(imapResponseText(new Error('read ECONNRESET')), undefined);
    assert.equal(imapResponseText(null), undefined);
});

test('the IMAP clients decide a failed login through isRefusedImapLogin()', () => {
    // A bare `if (err.authenticationFailed)` is the shape that reported an Exchange outage as a
    // refused credential. Asserted against the source, because the next login-failure branch would
    // reach for the flag again and no test short of a live Exchange outage would notice.
    for (const file of ['lib/email-client/imap-client.js', 'lib/email-client/imap/subconnection.js']) {
        const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        // A line with a slash before the branch is a comment
        assert.doesNotMatch(
            source,
            /^[^/\n]*\bif\s*\(\s*!?err\.authenticationFailed\b/m,
            `${file}: branch on isRefusedImapLogin(err) instead of the bare flag`
        );
        assert.match(source, /isRefusedImapLogin\(err\)/, `${file} must consult isRefusedImapLogin()`);
    }
});
