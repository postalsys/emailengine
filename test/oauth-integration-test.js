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

    await t.test('GmailOauth uses LocalKeySigner by default for service account configs', async () => {
        const { LocalKeySigner } = require('../lib/oauth/gmail');
        const gmail = new GmailOauth({
            ...baseOpts,
            serviceClient: '7103296518315821565203',
            serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
            serviceKey: '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'
        });
        assert.strictEqual(gmail.authMethod, 'serviceKey');
        assert.ok(gmail.signer instanceof LocalKeySigner);
    });

    await t.test('GmailOauth uses ExternalAccountSigner when authMethod is externalAccount', async () => {
        const { ExternalAccountSigner } = require('../lib/oauth/external-account-signer');
        const externalAccount = JSON.stringify({
            type: 'external_account',
            audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/p',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            token_url: 'https://sts.googleapis.com/v1/token',
            service_account_impersonation_url:
                'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken',
            credential_source: { file: '/tmp/oidc-token' }
        });
        const gmail = new GmailOauth({
            ...baseOpts,
            serviceClient: '7103296518315821565203',
            serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
            authMethod: 'externalAccount',
            externalAccount
        });
        assert.strictEqual(gmail.authMethod, 'externalAccount');
        assert.ok(gmail.signer instanceof ExternalAccountSigner);
    });

    await t.test('GmailOauth.parseExternalAccountConfig rejects empty input', () => {
        const { parseExternalAccountConfig } = require('../lib/oauth/gmail');
        assert.throws(
            () => parseExternalAccountConfig(''),
            err => err.code === 'EExternalAccountConfig'
        );
        assert.throws(
            () => parseExternalAccountConfig('not-json'),
            err => err.code === 'EExternalAccountConfig'
        );
        const parsed = parseExternalAccountConfig('{"type":"external_account"}');
        assert.strictEqual(parsed.type, 'external_account');
    });

    await t.test('generateServiceRequest throws when no signer is configured', async () => {
        // No serviceClient -> no signer is built.
        const gmail = new GmailOauth(baseOpts);
        await assert.rejects(
            () => gmail.generateServiceRequest('user@example.com', false),
            err => err.code === 'EServiceCredentialsMissing'
        );
    });

    await t.test('generateServiceRequest issues WIF assertions as the signing service account', async () => {
        // Deterministic timestamp so both signers see the same iat/exp.
        const fixedNow = 1700000000000;
        const origNow = Date.now;
        Date.now = () => fixedNow;
        try {
            const localGmail = new GmailOauth({
                ...baseOpts,
                serviceClient: '7103296518315821565203',
                serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
                serviceKey: '-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----'
            });
            // Replace the local signer with a fake that just returns its inputs, so we can compare payloads.
            localGmail.signer = {
                async sign(payload) {
                    return JSON.stringify(payload);
                }
            };

            const wifGmail = new GmailOauth({
                ...baseOpts,
                serviceClient: '7103296518315821565203',
                serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
                authMethod: 'externalAccount',
                externalAccount: JSON.stringify({
                    type: 'external_account',
                    audience: '//iam.googleapis.com/projects/x/locations/global/workloadIdentityPools/p/providers/q',
                    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
                    token_url: 'https://sts.googleapis.com/v1/token',
                    service_account_impersonation_url:
                        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken',
                    credential_source: { file: '/tmp/x' }
                })
            });
            wifGmail.signer = Object.assign(wifGmail.signer, {
                async sign(payload) {
                    return JSON.stringify(payload);
                }
            });

            const localReq = await localGmail.generateServiceRequest('user@example.com', false);
            const wifReq = await wifGmail.generateServiceRequest('user@example.com', false);

            // In delegation mode the local key issues as the numeric client ID, while the WIF
            // assertion MUST be issued as the impersonated service account email so Google can
            // verify the signature (made by that account via signJwt) against the issuer.
            assert.strictEqual(localReq.tokenData.iss, '7103296518315821565203');
            assert.strictEqual(wifReq.tokenData.iss, 'svc@proj.iam.gserviceaccount.com');

            // Every other claim stays identical between the two signers.
            for (let key of ['scope', 'sub', 'aud', 'iat', 'exp']) {
                assert.strictEqual(localReq.tokenData[key], wifReq.tokenData[key]);
            }
            assert.strictEqual(localReq.payload.grant_type, wifReq.payload.grant_type);

            // In principal mode the local key already issues as the service account email,
            // so the issuer (and the entire payload) matches the WIF assertion.
            const localPrincipal = await localGmail.generateServiceRequest(null, true);
            const wifPrincipal = await wifGmail.generateServiceRequest(null, true);
            assert.strictEqual(localPrincipal.tokenData.iss, 'svc@proj.iam.gserviceaccount.com');
            assert.deepStrictEqual(localPrincipal.tokenData, wifPrincipal.tokenData);
        } finally {
            Date.now = origNow;
        }
    });

    await t.test('GmailOauth rejects external account whose service account differs from serviceClientEmail', () => {
        assert.throws(
            () =>
                new GmailOauth({
                    ...baseOpts,
                    serviceClient: '7103296518315821565203',
                    serviceClientEmail: 'wrong@proj.iam.gserviceaccount.com',
                    authMethod: 'externalAccount',
                    externalAccount: JSON.stringify({
                        type: 'external_account',
                        audience: '//iam.googleapis.com/projects/x/locations/global/workloadIdentityPools/p/providers/q',
                        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
                        token_url: 'https://sts.googleapis.com/v1/token',
                        service_account_impersonation_url:
                            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken',
                        credential_source: { file: '/tmp/x' }
                    })
                }),
            err => err.code === 'EServiceAccountMismatch'
        );
    });

    await t.test('refreshToken drives the WIF signer through the jwt-bearer grant end to end', async () => {
        const { ExternalAccountSigner } = require('../lib/oauth/external-account-signer');
        const fs = require('node:fs');
        const path = require('node:path');
        const os = require('node:os');

        let tokenRequestBodies = [];
        let server = http.createServer((req, res) => {
            let chunks = [];
            req.on('data', chunk => chunks.push(chunk));
            req.on('end', () => {
                let body = Buffer.concat(chunks).toString();
                if (req.url === '/sts' && req.method === 'POST') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ access_token: 'fed-tok', expires_in: 3600, token_type: 'Bearer' }));
                }
                if (/:signJwt$/.test(req.url) && req.method === 'POST') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ signedJwt: 'signed.jwt.assertion' }));
                }
                if (req.url === '/token' && req.method === 'POST') {
                    tokenRequestBodies.push(body);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ access_token: 'ya29.real-token', expires_in: 3599, token_type: 'Bearer' }));
                }
                res.writeHead(404).end();
            });
        });

        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        let { port } = server.address();
        let base = `http://127.0.0.1:${port}`;

        let tokenDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'wif-rt-'));
        let tokenPath = path.join(tokenDir, 'token');
        await fs.promises.writeFile(tokenPath, 'subject-token', 'utf8');

        try {
            let externalAccount = JSON.stringify({
                type: 'external_account',
                audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q',
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
                token_url: `${base}/sts`,
                service_account_impersonation_url: `${base}/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken`,
                credential_source: { file: tokenPath }
            });

            let gmail = new GmailOauth({
                ...baseOpts,
                serviceClient: '7103296518315821565203',
                serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
                authMethod: 'externalAccount',
                externalAccount
            });

            // Redirect the Google token endpoint and the signer's iamcredentials base to the mock.
            gmail.tokenUrl = `${base}/token`;
            gmail.signer = new ExternalAccountSigner({ config: JSON.parse(externalAccount), iamCredentialsBaseUrl: base });

            let result = await gmail.refreshToken({ user: 'user@example.com' });

            assert.strictEqual(result.access_token, 'ya29.real-token');

            assert.strictEqual(tokenRequestBodies.length, 1);
            let params = new URLSearchParams(tokenRequestBodies[0]);
            assert.strictEqual(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
            assert.strictEqual(params.get('assertion'), 'signed.jwt.assertion');
        } finally {
            await new Promise(resolve => server.close(resolve));
            await fs.promises.rm(tokenDir, { recursive: true, force: true });
        }
    });

    await t.test('LocalKeySigner.sign includes kid in header only when kid option is set', async () => {
        const crypto = require('node:crypto');
        const { generateKeyPairSync } = crypto;
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        const { LocalKeySigner } = require('../lib/oauth/gmail');
        const signer = new LocalKeySigner({ serviceKey: pem });

        const withKid = await signer.sign({ iss: 'a' }, { kid: 'key-id-123' });
        const withoutKid = await signer.sign({ iss: 'a' }, {});

        const decodeHeader = jwt => JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
        assert.strictEqual(decodeHeader(withKid).kid, 'key-id-123');
        assert.strictEqual(decodeHeader(withoutKid).kid, undefined);
        assert.strictEqual(decodeHeader(withKid).alg, 'RS256');
        assert.strictEqual(decodeHeader(withKid).typ, 'JWT');
    });

    await t.test('LocalKeySigner throws if serviceKey is missing', async () => {
        const { LocalKeySigner } = require('../lib/oauth/gmail');
        const signer = new LocalKeySigner({});
        await assert.rejects(
            () => signer.sign({ iss: 'a' }, {}),
            err => err.code === 'EServiceKeyMissing'
        );
    });

    await t.test('oauthCreateSchema rejects a structurally invalid external_account config', () => {
        const Joi = require('joi');
        const { oauthCreateSchema } = require('../lib/schemas');
        const schema = Joi.object(oauthCreateSchema);

        const base = {
            provider: 'gmailService',
            name: 'WIF app',
            authMethod: 'externalAccount',
            serviceClient: '7103296518315821565203',
            serviceClientEmail: 'svc@proj.iam.gserviceaccount.com'
        };

        // type is correct but the impersonation URL is malformed - this must be caught
        // at save time rather than on the first token refresh.
        const badConfig = {
            type: 'external_account',
            audience: '//iam.googleapis.com/x',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            token_url: 'https://sts.googleapis.com/v1/token',
            service_account_impersonation_url: 'https://example.com/not-a-valid-endpoint',
            credential_source: { file: '/var/run/secrets/token' }
        };
        const badResult = schema.validate({ ...base, externalAccount: JSON.stringify(badConfig) }, { abortEarly: false });
        assert.ok(badResult.error, 'malformed external_account config must be rejected');
        assert.ok(/service_account_impersonation_url/.test(badResult.error.message), 'error should point at the bad field');

        // A well-formed config validates cleanly.
        const goodConfig = {
            type: 'external_account',
            audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            token_url: 'https://sts.googleapis.com/v1/token',
            service_account_impersonation_url:
                'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken',
            credential_source: { file: '/var/run/secrets/token' }
        };
        const goodResult = schema.validate({ ...base, externalAccount: JSON.stringify(goodConfig) }, { abortEarly: false });
        assert.ok(!goodResult.error, goodResult.error && goodResult.error.message);
    });

    await t.test('GmailOauth constructor rejects unknown authMethod', () => {
        assert.throws(
            () =>
                new GmailOauth({
                    ...baseOpts,
                    serviceClient: 'sc',
                    authMethod: 'magic'
                }),
            err => err.code === 'EUnknownAuthMethod'
        );
    });
});
