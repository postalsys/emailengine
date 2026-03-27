'use strict';

const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert').strict;

test('OAuth integration tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    const { GmailOauth, OPENID_SCOPES } = require('../lib/oauth/gmail');
    const { OutlookOauth } = require('../lib/oauth/outlook');
    const { MailRuOauth } = require('../lib/oauth/mail-ru');

    const baseOpts = {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUrl: 'http://localhost/callback',
        setFlag: async () => {}
    };

    await t.test('Gmail OAuth module exports expected members', async () => {
        const gmailModule = require('../lib/oauth/gmail');
        assert.ok(gmailModule.GmailOauth);
        assert.ok(gmailModule.GMAIL_SCOPES);
    });

    await t.test('Outlook OAuth module exports expected members', async () => {
        const outlookModule = require('../lib/oauth/outlook');
        assert.ok(outlookModule.OutlookOauth);
        assert.ok(outlookModule.outlookScopes);
    });

    await t.test('Mail.ru OAuth module exports expected members', async () => {
        const mailruModule = require('../lib/oauth/mail-ru');
        assert.ok(mailruModule.MailRuOauth);
    });

    await t.test('GmailOauth.getTokenRequest returns URL-encoded string body', async () => {
        const gmail = new GmailOauth(baseOpts);

        const tokenRequest = gmail.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('client_secret'), 'test-client-secret');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('OutlookOauth.getTokenRequest returns URL-encoded string body', async () => {
        const outlook = new OutlookOauth({ ...baseOpts, authority: 'common' });

        const tokenRequest = outlook.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('MailRuOauth.getTokenRequest returns URL-encoded string body', async () => {
        const mailru = new MailRuOauth(baseOpts);

        const tokenRequest = mailru.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('Token request body properly encodes special characters', async () => {
        const gmail = new GmailOauth({
            ...baseOpts,
            clientSecret: 'test-secret-with-special-chars!@#',
            redirectUrl: 'http://localhost/callback?param=value'
        });

        const tokenRequest = gmail.getTokenRequest({ code: 'test-code' });

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('client_secret'), 'test-secret-with-special-chars!@#');
        assert.strictEqual(params.get('redirect_uri'), 'http://localhost/callback?param=value');
    });

    await t.test('Error response falls back when responseJson is undefined or null', async () => {
        const buildErrorResponse = responseJson => {
            return responseJson || { error: 'Failed to parse response' };
        };

        assert.deepStrictEqual(buildErrorResponse(undefined), { error: 'Failed to parse response' });
        assert.deepStrictEqual(buildErrorResponse(null), { error: 'Failed to parse response' });
        assert.strictEqual(buildErrorResponse({ error: 'invalid_grant' }).error, 'invalid_grant');
    });

    await t.test('Optional chaining prevents error on null error_description', async () => {
        const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Unauthorized/i;

        const testCases = [null, undefined, {}, { error: 'some_error' }, { error_description: null }, { error_description: undefined }];

        for (const response of testCases) {
            const result = EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(response?.error_description);
            assert.strictEqual(typeof result, 'boolean');
        }

        assert.ok(EXPOSE_PARTIAL_SECRET_KEY_REGEX.test({ error_description: 'Unauthorized access' }?.error_description));
    });

    await t.test('GmailOauth generates valid auth URL', async () => {
        const gmail = new GmailOauth(baseOpts);

        const authUrl = gmail.generateAuthUrl({ state: 'test-state' });

        assert.ok(authUrl.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));
        assert.ok(authUrl.includes('client_id=test-client-id'));
        assert.ok(authUrl.includes('state=test-state'));
    });

    await t.test('OutlookOauth generates valid auth URL', async () => {
        const outlook = new OutlookOauth({ ...baseOpts, authority: 'common' });

        const authUrl = outlook.generateAuthUrl({ state: 'test-state' });

        assert.ok(authUrl.includes('login.microsoftonline.com'));
        assert.ok(authUrl.includes('client_id=test-client-id'));
        assert.ok(authUrl.includes('state=test-state'));
    });

    await t.test('OutlookOauth instantiates with different cloud configurations', async () => {
        const clouds = ['global', 'gcc-high', 'dod', 'china'];

        for (const cloud of clouds) {
            const outlook = new OutlookOauth({ ...baseOpts, authority: 'common', cloud });

            assert.strictEqual(outlook.cloud, cloud);
            assert.ok(outlook.entraEndpoint, `Should have entraEndpoint for ${cloud}`);
            assert.ok(outlook.apiBase, `Should have apiBase for ${cloud}`);
        }
    });

    await t.test('GmailOauth has default scopes', async () => {
        const gmail = new GmailOauth(baseOpts);

        assert.ok(gmail.scopes.length > 0);
    });

    await t.test('GmailOauth.revokeToken sends correct revocation request', async () => {
        let capturedBody = null;
        let capturedHeaders = null;
        let capturedMethod = null;

        const server = http.createServer((req, res) => {
            capturedMethod = req.method;
            capturedHeaders = req.headers;
            const chunks = [];
            req.on('data', chunk => chunks.push(chunk));
            req.on('end', () => {
                capturedBody = Buffer.concat(chunks).toString();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end('{}');
            });
        });

        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const { port } = server.address();

        try {
            const gmail = new GmailOauth(baseOpts);
            gmail.revokeUrl = `http://127.0.0.1:${port}/revoke`;

            await gmail.revokeToken('test-access-token-123');

            assert.strictEqual(capturedMethod, 'POST');
            assert.ok(capturedHeaders['content-type'].includes('application/x-www-form-urlencoded'));
            assert.strictEqual(capturedBody, 'token=test-access-token-123');
        } finally {
            await new Promise(resolve => server.close(resolve));
        }
    });

    await t.test('GmailOauth.revokeToken does not throw on HTTP error', async () => {
        const server = http.createServer((req, res) => {
            req.on('data', () => {});
            req.on('end', () => {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'invalid_token' }));
            });
        });

        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const { port } = server.address();

        try {
            const gmail = new GmailOauth(baseOpts);
            gmail.revokeUrl = `http://127.0.0.1:${port}/revoke`;

            await gmail.revokeToken('bad-token');
        } finally {
            await new Promise(resolve => server.close(resolve));
        }
    });

    await t.test('GmailOauth.revokeToken does not throw on network error', async () => {
        const gmail = new GmailOauth(baseOpts);
        gmail.revokeUrl = 'http://127.0.0.1:1/revoke';

        await gmail.revokeToken('any-token');
    });

    await t.test('Scope comparison detects missing functional scopes', async () => {
        const requested = ['openid', 'email', 'profile', 'https://mail.google.com/'];
        const granted = ['openid', 'email', 'profile'];

        const requiredFunctional = requested.filter(s => !OPENID_SCOPES.includes(s));
        const missing = requiredFunctional.filter(s => !granted.includes(s));

        assert.deepStrictEqual(requiredFunctional, ['https://mail.google.com/']);
        assert.deepStrictEqual(missing, ['https://mail.google.com/']);
    });

    await t.test('Scope comparison returns empty when all functional scopes granted', async () => {
        const requested = ['openid', 'email', 'profile', 'https://mail.google.com/'];
        const granted = ['openid', 'email', 'profile', 'https://mail.google.com/'];

        const requiredFunctional = requested.filter(s => !OPENID_SCOPES.includes(s));
        const missing = requiredFunctional.filter(s => !granted.includes(s));

        assert.deepStrictEqual(missing, []);
    });

    await t.test('Scope comparison handles multiple missing scopes', async () => {
        const requested = ['openid', 'email', 'profile', 'https://mail.google.com/', 'https://www.googleapis.com/auth/pubsub'];
        const granted = ['openid', 'email', 'profile'];

        const requiredFunctional = requested.filter(s => !OPENID_SCOPES.includes(s));
        const missing = requiredFunctional.filter(s => !granted.includes(s));

        assert.deepStrictEqual(missing, ['https://mail.google.com/', 'https://www.googleapis.com/auth/pubsub']);
    });
});
