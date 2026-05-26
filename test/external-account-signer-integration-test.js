'use strict';

// Integration tests for ExternalAccountSigner against a local node:http mock
// server that emulates the two Google endpoints the signer talks to:
//   - sts.googleapis.com/v1/token            (token exchange)
//   - iamcredentials.googleapis.com /
//     v1/projects/-/serviceAccounts/{e}:signJwt
//                                            (JWT signing)
//
// The signer uses a single hop: it exchanges the subject token at STS for a
// federated access token and calls signJwt directly with it (the workload
// principal holds serviceAccountTokenCreator on the target service account).
//
// These tests do NOT inject a fake fetch - the signer's production undici
// fetch path executes end-to-end against the mock server. The iamcredentials
// base URL is redirected to the mock via the constructor option, mirroring
// what a forward-proxy deployment would do.

const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { ExternalAccountSigner } = require('../lib/oauth/external-account-signer');

const TARGET_SA = 'integration@proj.iam.gserviceaccount.com';

function readBody(req) {
    return new Promise((resolve, reject) => {
        let chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

function send(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
}

// State store that backs the mock server. Tests mutate this to simulate
// different upstream behaviours without rebuilding the server.
function createState() {
    return {
        expectedSubjectToken: null, // assert what the signer sent (optional)
        stsResponse: { ok: true, status: 200, body: { access_token: 'fed-default', token_type: 'Bearer', expires_in: 3600 } },
        signJwtResponse: { ok: true, status: 200, body: { signedJwt: 'header.payload.signature' } },
        calls: { sts: [], signJwt: [] }
    };
}

async function startMockServer(state) {
    let server = http.createServer(async (req, res) => {
        try {
            let body = await readBody(req);
            let url = req.url;

            if (url === '/v1/token' && req.method === 'POST') {
                let parsed = new URLSearchParams(body);
                state.calls.sts.push({ params: Object.fromEntries(parsed) });
                if (state.expectedSubjectToken !== null) {
                    assert.strictEqual(parsed.get('subject_token'), state.expectedSubjectToken);
                }
                return send(res, state.stsResponse.status, state.stsResponse.body);
            }

            if (/:signJwt$/.test(url) && req.method === 'POST') {
                state.calls.signJwt.push({ url, authorization: req.headers.authorization, body: JSON.parse(body || '{}') });
                return send(res, state.signJwtResponse.status, state.signJwtResponse.body);
            }

            if (url === '/oidc-token' && req.method === 'GET') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ access_token: 'oidc-from-idp' }));
            }

            res.writeHead(404).end();
        } catch (err) {
            res.writeHead(500).end(String(err && err.message));
        }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let { port } = server.address();
    let baseUrl = `http://127.0.0.1:${port}`;

    return {
        baseUrl,
        async stop() {
            await new Promise(resolve => server.close(resolve));
        }
    };
}

function buildFileConfig(baseUrl, tokenPath) {
    return {
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: `${baseUrl}/v1/token`,
        service_account_impersonation_url: `${baseUrl}/v1/projects/-/serviceAccounts/${TARGET_SA}:generateAccessToken`,
        credential_source: {
            file: tokenPath,
            format: { type: 'text' }
        }
    };
}

function buildUrlConfig(baseUrl) {
    return {
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov',
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        token_url: `${baseUrl}/v1/token`,
        service_account_impersonation_url: `${baseUrl}/v1/projects/-/serviceAccounts/${TARGET_SA}:generateAccessToken`,
        credential_source: {
            url: `${baseUrl}/oidc-token`,
            format: { type: 'json', subject_token_field_name: 'access_token' }
        }
    };
}

test('ExternalAccountSigner integration (mock server)', async t => {
    t.after(() => {
        // Ensure no stray timers keep the process alive after the suite is done.
        setTimeout(() => process.exit(), 500).unref();
    });

    await t.test('end-to-end file source: file -> STS -> signJwt', async () => {
        let state = createState();
        let server = await startMockServer(state);
        try {
            let tokenDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'wif-int-'));
            let tokenPath = path.join(tokenDir, 'token');
            await fs.promises.writeFile(tokenPath, 'k8s-projected-token-v1', 'utf8');

            state.expectedSubjectToken = 'k8s-projected-token-v1';
            state.stsResponse = { status: 200, body: { access_token: 'fed-abc', expires_in: 3600, token_type: 'Bearer' } };
            state.signJwtResponse = { status: 200, body: { signedJwt: 'a.b.c' } };

            let signer = new ExternalAccountSigner({
                config: buildFileConfig(server.baseUrl, tokenPath),
                iamCredentialsBaseUrl: server.baseUrl
            });

            let now = Math.floor(Date.now() / 1000);
            let signed = await signer.sign({
                iss: TARGET_SA,
                sub: 'user@example.com',
                scope: 'https://mail.google.com/',
                aud: 'https://oauth2.googleapis.com/token',
                iat: now,
                exp: now + 3600
            });

            assert.strictEqual(signed, 'a.b.c');

            assert.strictEqual(state.calls.sts.length, 1);
            assert.strictEqual(state.calls.sts[0].params.grant_type, 'urn:ietf:params:oauth:grant-type:token-exchange');
            assert.strictEqual(state.calls.sts[0].params.subject_token, 'k8s-projected-token-v1');
            assert.strictEqual(state.calls.sts[0].params.scope, 'https://www.googleapis.com/auth/cloud-platform');

            // signJwt is authorized with the federated token directly - no impersonation hop.
            assert.strictEqual(state.calls.signJwt.length, 1);
            assert.strictEqual(state.calls.signJwt[0].authorization, 'Bearer fed-abc');
            let signJwtPayload = JSON.parse(state.calls.signJwt[0].body.payload);
            assert.strictEqual(signJwtPayload.iss, TARGET_SA);
            assert.strictEqual(signJwtPayload.sub, 'user@example.com');

            await fs.promises.rm(tokenDir, { recursive: true, force: true });
        } finally {
            await server.stop();
        }
    });

    await t.test('end-to-end url source: fetches subject token from local IDP endpoint', async () => {
        let state = createState();
        let server = await startMockServer(state);
        try {
            state.expectedSubjectToken = 'oidc-from-idp';
            state.signJwtResponse = { status: 200, body: { signedJwt: 'url.path.ok' } };

            let signer = new ExternalAccountSigner({
                config: buildUrlConfig(server.baseUrl),
                iamCredentialsBaseUrl: server.baseUrl
            });

            let result = await signer.sign({ iss: TARGET_SA });
            assert.strictEqual(result, 'url.path.ok');

            assert.strictEqual(state.calls.sts.length, 1);
            assert.strictEqual(state.calls.sts[0].params.subject_token, 'oidc-from-idp');
        } finally {
            await server.stop();
        }
    });

    await t.test('STS error surfaces as ESTSExchange with response body', async () => {
        let state = createState();
        let server = await startMockServer(state);
        try {
            let tokenDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'wif-int-'));
            let tokenPath = path.join(tokenDir, 'token');
            await fs.promises.writeFile(tokenPath, 'a-token', 'utf8');

            state.stsResponse = { status: 400, body: { error: 'invalid_request', error_description: 'Invalid audience' } };

            let signer = new ExternalAccountSigner({
                config: buildFileConfig(server.baseUrl, tokenPath),
                iamCredentialsBaseUrl: server.baseUrl
            });

            await assert.rejects(
                () => signer.sign({ iss: TARGET_SA }),
                err => err.code === 'ESTSExchange' && err.statusCode === 400 && err.response && err.response.error === 'invalid_request'
            );

            // No signJwt fired after STS failed.
            assert.strictEqual(state.calls.signJwt.length, 0);

            await fs.promises.rm(tokenDir, { recursive: true, force: true });
        } finally {
            await server.stop();
        }
    });

    await t.test('subject-token file rotation is observed after cache expiry', async () => {
        let state = createState();
        let server = await startMockServer(state);
        try {
            let tokenDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'wif-int-'));
            let tokenPath = path.join(tokenDir, 'token');
            await fs.promises.writeFile(tokenPath, 'token-v1', 'utf8');

            // Federated token expires almost immediately so the next sign() refreshes.
            state.stsResponse = { status: 200, body: { access_token: 'fed-1', expires_in: 1 } };
            state.signJwtResponse = { status: 200, body: { signedJwt: 'one' } };

            let signer = new ExternalAccountSigner({
                config: buildFileConfig(server.baseUrl, tokenPath),
                iamCredentialsBaseUrl: server.baseUrl
            });

            await signer.sign({ iss: TARGET_SA });
            assert.strictEqual(state.calls.sts[0].params.subject_token, 'token-v1');

            // Rotate the projected K8s SA token on disk.
            await fs.promises.writeFile(tokenPath, 'token-v2-rotated', 'utf8');
            state.signJwtResponse = { status: 200, body: { signedJwt: 'two' } };

            await signer.sign({ iss: TARGET_SA });
            // STS was called a second time with the rotated token value.
            assert.strictEqual(state.calls.sts.length, 2);
            assert.strictEqual(state.calls.sts[1].params.subject_token, 'token-v2-rotated');

            await fs.promises.rm(tokenDir, { recursive: true, force: true });
        } finally {
            await server.stop();
        }
    });

    await t.test('concurrent sign() invocations share one upstream exchange on cold cache', async () => {
        let state = createState();
        let server = await startMockServer(state);
        try {
            let tokenDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'wif-int-'));
            let tokenPath = path.join(tokenDir, 'token');
            await fs.promises.writeFile(tokenPath, 'concurrent-tok', 'utf8');

            state.stsResponse = { status: 200, body: { access_token: 'fed-shared', expires_in: 3600 } };
            state.signJwtResponse = { status: 200, body: { signedJwt: 'shared.sig.value' } };

            let signer = new ExternalAccountSigner({
                config: buildFileConfig(server.baseUrl, tokenPath),
                iamCredentialsBaseUrl: server.baseUrl
            });

            let results = await Promise.all(Array.from({ length: 8 }, (_, i) => signer.sign({ iss: TARGET_SA, sub: `u${i}@example.com` })));
            assert.strictEqual(results.length, 8);
            assert.ok(results.every(r => r === 'shared.sig.value'));

            // Cache dedup: STS ran once across 8 concurrent callers; signJwt ran per-caller.
            assert.strictEqual(state.calls.sts.length, 1);
            assert.strictEqual(state.calls.signJwt.length, 8);
            assert.ok(state.calls.signJwt.every(c => c.authorization === 'Bearer fed-shared'));

            await fs.promises.rm(tokenDir, { recursive: true, force: true });
        } finally {
            await server.stop();
        }
    });

    await t.test('signature returned by signer is verifiable with a Google-issued key', async () => {
        // Validates the full content-to-signature flow: the mock generates a
        // valid RSA-SHA256 signature over the same encodedHeader.encodedPayload
        // string the signer would have produced, and we verify it with the
        // matching public key. This catches bugs where the signer mangles the
        // payload between handing it to signJwt and returning the result.
        let state = createState();
        let server = await startMockServer(state);
        try {
            let { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

            let signer = new ExternalAccountSigner({
                config: {
                    type: 'external_account',
                    audience: '//iam.googleapis.com/projects/x/locations/global/workloadIdentityPools/p/providers/q',
                    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
                    token_url: `${server.baseUrl}/v1/token`,
                    service_account_impersonation_url: `${server.baseUrl}/v1/projects/-/serviceAccounts/${TARGET_SA}:generateAccessToken`,
                    credential_source: { url: `${server.baseUrl}/oidc-token`, format: { type: 'json', subject_token_field_name: 'access_token' } }
                },
                iamCredentialsBaseUrl: server.baseUrl
            });

            // Intercept the signJwt call: read the payload, sign it locally with
            // the test private key, and return a real JWT in the signedJwt field.
            let signedJwtCapture = null;
            state.signJwtResponse = {
                status: 200,
                get body() {
                    let payloadStr = state.calls.signJwt[state.calls.signJwt.length - 1].body.payload;
                    let header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
                    let body = Buffer.from(payloadStr).toString('base64url');
                    let signature = crypto.createSign('RSA-SHA256').update(`${header}.${body}`).sign(privateKey).toString('base64url');
                    signedJwtCapture = `${header}.${body}.${signature}`;
                    return { signedJwt: signedJwtCapture };
                }
            };

            let now = Math.floor(Date.now() / 1000);
            let signed = await signer.sign({ iss: TARGET_SA, sub: 'verify@example.com', aud: 'aud-test', iat: now, exp: now + 60 });

            // Verify the JWT signature with the public key.
            let [headerB64, payloadB64, sigB64] = signed.split('.');
            let isValid = crypto.createVerify('RSA-SHA256').update(`${headerB64}.${payloadB64}`).verify(publicKey, Buffer.from(sigB64, 'base64url'));
            assert.ok(isValid, 'JWT signature must verify against the test public key');

            let decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
            assert.strictEqual(decoded.sub, 'verify@example.com');
            assert.strictEqual(decoded.iss, TARGET_SA);
        } finally {
            await server.stop();
        }
    });
});
