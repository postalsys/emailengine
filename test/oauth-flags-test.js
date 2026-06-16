'use strict';

// Unit tests for the OAuth error-to-flag mapping in the Gmail and Outlook
// providers (lib/oauth/gmail.js, lib/oauth/outlook.js). checkForFlags classifies
// app-configuration errors (bad client id/secret, API not enabled, ...) and
// checkForUserFlags classifies per-user errors (revoked/expired grant); both
// drive admin remediation guidance and re-auth prompts. They were previously
// only exercised indirectly.

const test = require('node:test');
const assert = require('node:assert').strict;

const gmail = require('../lib/oauth/gmail');
const outlook = require('../lib/oauth/outlook');
const { redis } = require('../lib/db');

test.after(async () => {
    try {
        await redis.quit();
    } catch (err) {
        // ignore
    }
});

test('Gmail checkForFlags', async t => {
    await t.test('returns false for non-object input', () => {
        assert.strictEqual(gmail.checkForFlags(null), false);
        assert.strictEqual(gmail.checkForFlags('nope'), false);
    });

    await t.test('flags Gmail API not enabled with activation link', () => {
        const err = {
            error: {
                message: 'Gmail API has not been used in project 123 before or it is disabled',
                details: [{ links: [{ description: 'Google developers console API activation', url: 'https://console.developers.google.com/apis/api/gmail' }] }]
            }
        };
        const flag = gmail.checkForFlags(err);
        assert.strictEqual(flag.code, 'GMAIL_API_NOT_ENABLED');
        assert.match(flag.url, /console\.developers\.google\.com/);
    });

    await t.test('flags insufficient authentication scopes', () => {
        const flag = gmail.checkForFlags({ error: { message: 'Request had insufficient authentication scopes.' } });
        assert.strictEqual(flag.code, 'INSUFFICIENT_AUTH_SCOPES');
    });

    await t.test('flags Pub/Sub topic mismatch', () => {
        const flag = gmail.checkForFlags({ error: { message: 'Invalid topicName does not match the project' } });
        assert.strictEqual(flag.code, 'PROJECT_MISMATCH');
    });

    await t.test('flags invalid client id', () => {
        const flag = gmail.checkForFlags({ error: 'invalid_client', error_description: 'The OAuth client was not found.' });
        assert.strictEqual(flag.code, 'INVALID_CLIENT_ID');
    });

    await t.test('flags invalid client secret', () => {
        const flag = gmail.checkForFlags({ error: 'invalid_client', error_description: 'Unauthorized' });
        assert.strictEqual(flag.code, 'INVALID_CLIENT_SECRET');
    });

    await t.test('flags unauthorized client (domain-wide delegation)', () => {
        const flag = gmail.checkForFlags({
            error: 'unauthorized_client',
            error_description: 'Client is unauthorized to retrieve access tokens using this method'
        });
        assert.strictEqual(flag.code, 'UNAUTHORIZED_CLIENT');
    });

    await t.test('flags invalid client email (principal)', () => {
        const flag = gmail.checkForFlags({ error: 'invalid_request', error_description: 'Invalid principal value' });
        assert.strictEqual(flag.code, 'INVALID_CLIENT_EMAIL');
    });

    await t.test('flags invalid service client email only when isPrincipal', () => {
        const err = { error: 'invalid_grant', error_description: 'Requested entity was not found - account not found' };
        assert.strictEqual(gmail.checkForFlags(err, true).code, 'INVALID_SERVICE_CLIENT_EMAIL');
        // Without isPrincipal this specific mapping must not fire.
        assert.strictEqual(gmail.checkForFlags(err, false), false);
    });

    await t.test('returns false for an unrecognized error', () => {
        assert.strictEqual(gmail.checkForFlags({ error: 'some_other_error', error_description: 'whatever' }), false);
    });
});

test('Gmail checkForUserFlags', async t => {
    await t.test('flags invalid_grant', () => {
        const flag = gmail.checkForUserFlags({ error: 'invalid_grant', error_description: 'Bad Request' });
        assert.ok(flag);
        assert.match(flag.message, /Failed to renew the access token/);
    });

    await t.test('rewrites the description for an expired/revoked refresh token', () => {
        const flag = gmail.checkForUserFlags({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
        assert.ok(flag);
        assert.match(flag.description, /Refresh token has expired or been revoked/);
    });

    await t.test('returns false for non-grant errors and bad input', () => {
        assert.strictEqual(gmail.checkForUserFlags({ error: 'invalid_client', error_description: 'x' }), false);
        assert.strictEqual(gmail.checkForUserFlags(null), false);
    });
});

test('Outlook checkForFlags', async t => {
    await t.test('returns false for non-object input', () => {
        assert.strictEqual(outlook.checkForFlags(null), false);
        assert.strictEqual(outlook.checkForFlags(42), false);
    });

    await t.test('flags expired/not-yet-valid client secret (AADSTS7000222)', () => {
        const flag = outlook.checkForFlags({ error: 'invalid_client', error_description: 'AADSTS7000222: The provided client secret keys are expired.' });
        assert.strictEqual(flag.code, 'OUTLOOK_CLIENT_SECRET_EXPIRED_OR_NOT_VALID');
    });

    await t.test('flags invalid application id (AADSTS700016)', () => {
        const flag = outlook.checkForFlags({ error: 'invalid_client', error_description: 'AADSTS700016: Application not found in directory.' });
        assert.strictEqual(flag.code, 'OUTLOOK_APP_ID_INVALID');
    });

    await t.test('flags invalid client secret (AADSTS7000215)', () => {
        const flag = outlook.checkForFlags({ error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided.' });
        assert.strictEqual(flag.code, 'OUTLOOK_CLIENT_SECRET_INVALID');
    });

    await t.test('returns false for an unrelated invalid_client error', () => {
        assert.strictEqual(outlook.checkForFlags({ error: 'invalid_client', error_description: 'AADSTS99999: Something else' }), false);
    });
});

test('Outlook checkForUserFlags', async t => {
    await t.test('flags a password change/reset', () => {
        const flag = outlook.checkForUserFlags({
            error: 'invalid_grant',
            error_description: 'AADSTS50173: The user might have changed or reset their password.'
        });
        assert.strictEqual(flag.code, 'OUTLOOK_USER_PASSWORD_CHANGED');
    });

    await t.test('flags a generic grant renewal failure', () => {
        const flag = outlook.checkForUserFlags({ error: 'invalid_grant', error_description: 'AADSTS70000: token expired' });
        assert.strictEqual(flag.code, 'OUTLOOK_TOKEN_RENEWAL_FAILED');
    });

    await t.test('returns false for non-grant errors and bad input', () => {
        assert.strictEqual(outlook.checkForUserFlags({ error: 'invalid_client', error_description: 'x' }), false);
        assert.strictEqual(outlook.checkForUserFlags(null), false);
    });
});
