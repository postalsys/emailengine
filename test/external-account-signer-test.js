'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { ExternalAccountSigner, __test__ } = require('../lib/oauth/external-account-signer');
const { validateConfig, extractFromFormat } = __test__;

const VALID_FILE_CONFIG = {
    type: 'external_account',
    audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider',
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: 'https://sts.googleapis.com/v1/token',
    service_account_impersonation_url:
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken',
    credential_source: {
        file: '/var/run/secrets/tokens/gcp-ksa/token',
        format: { type: 'text' }
    }
};

const VALID_URL_CONFIG = {
    type: 'external_account',
    audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider',
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    token_url: 'https://sts.googleapis.com/v1/token',
    service_account_impersonation_url:
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken',
    credential_source: {
        url: 'http://169.254.169.254/metadata/identity/oauth2/token',
        headers: { Metadata: 'true' },
        format: { type: 'json', subject_token_field_name: 'access_token' }
    }
};

function makeFakeFetch(routes) {
    let calls = [];
    let fetchImpl = async (url, options) => {
        let entry = { url, options };
        calls.push(entry);
        let handler = routes[url];
        if (!handler) {
            for (let key of Object.keys(routes)) {
                if (url.startsWith(key)) {
                    handler = routes[key];
                    break;
                }
            }
        }
        if (!handler) {
            throw new Error(`No fake route configured for ${url}`);
        }
        return handler(entry);
    };
    return { fetchImpl, calls };
}

function makeResponse({ status = 200, json, text, headers } = {}) {
    let h = new Map();
    if (headers) {
        for (let key of Object.keys(headers)) {
            h.set(key.toLowerCase(), headers[key]);
        }
    }
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: name => h.get(String(name).toLowerCase()) || null },
        json: async () => (typeof json !== 'undefined' ? json : null),
        text: async () => (typeof text !== 'undefined' ? text : '')
    };
}

test('ExternalAccountSigner', async t => {
    t.after(() => {
        // Loading lib/oauth/external-account-signer transitively pulls in lib/settings -> lib/db,
        // which opens Redis sockets that keep the event loop alive after tests finish. Force-exit
        // the test process so node:test's runner does not hang waiting for the loop to drain.
        setTimeout(() => process.exit(), 500).unref();
    });

    await t.test('validateConfig accepts a valid file-source config', () => {
        let { targetServiceAccountEmail } = validateConfig(VALID_FILE_CONFIG);
        assert.strictEqual(targetServiceAccountEmail, 'svc@proj.iam.gserviceaccount.com');
    });

    await t.test('validateConfig accepts a valid url-source config', () => {
        let { targetServiceAccountEmail } = validateConfig(VALID_URL_CONFIG);
        assert.strictEqual(targetServiceAccountEmail, 'svc@proj.iam.gserviceaccount.com');
    });

    await t.test('validateConfig rejects null', () => {
        assert.throws(
            () => validateConfig(null),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects wrong type', () => {
        assert.throws(
            () => validateConfig({ ...VALID_FILE_CONFIG, type: 'service_account' }),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects missing audience', () => {
        let bad = { ...VALID_FILE_CONFIG };
        delete bad.audience;
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects missing service_account_impersonation_url', () => {
        let bad = { ...VALID_FILE_CONFIG };
        delete bad.service_account_impersonation_url;
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects unsupported subject_token_type', () => {
        let bad = { ...VALID_FILE_CONFIG, subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request' };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects malformed impersonation URL', () => {
        let bad = { ...VALID_FILE_CONFIG, service_account_impersonation_url: 'https://example.com/whatever' };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects executable credential_source', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: { executable: { command: '/bin/true' } } };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects environment_id credential_source', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: { environment_id: 'aws1' } };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects both file and url present', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: { file: '/tmp/x', url: 'http://x' } };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects neither file nor url present', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: {} };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects invalid format.type', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: { file: '/tmp/x', format: { type: 'xml' } } };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('validateConfig rejects json format without subject_token_field_name', () => {
        let bad = { ...VALID_FILE_CONFIG, credential_source: { file: '/tmp/x', format: { type: 'json' } } };
        assert.throws(
            () => validateConfig(bad),
            err => err.code === 'EExternalAccountConfig'
        );
    });

    await t.test('extractFromFormat returns trimmed text', () => {
        assert.strictEqual(extractFromFormat('  hello-token\n', { type: 'text' }), 'hello-token');
    });

    await t.test('extractFromFormat rejects empty text', () => {
        assert.throws(
            () => extractFromFormat('   ', { type: 'text' }),
            err => err.code === 'ESubjectTokenRead'
        );
    });

    await t.test('extractFromFormat extracts json field', () => {
        let out = extractFromFormat('{"access_token":"  abc-123  "}', { type: 'json', subject_token_field_name: 'access_token' });
        assert.strictEqual(out, 'abc-123');
    });

    await t.test('extractFromFormat rejects invalid JSON', () => {
        assert.throws(
            () => extractFromFormat('{not-json', { type: 'json', subject_token_field_name: 'x' }),
            err => err.code === 'ESubjectTokenRead'
        );
    });

    await t.test('extractFromFormat rejects missing or non-string json field', () => {
        assert.throws(
            () => extractFromFormat('{}', { type: 'json', subject_token_field_name: 'x' }),
            err => err.code === 'ESubjectTokenRead'
        );
        assert.throws(
            () => extractFromFormat('{"x":123}', { type: 'json', subject_token_field_name: 'x' }),
            err => err.code === 'ESubjectTokenRead'
        );
    });

    await t.test('sign() drives full file -> STS -> impersonate -> signJwt chain', async () => {
        let { fetchImpl, calls } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'federated-tok' } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({
                    status: 200,
                    json: { accessToken: 'impersonated-tok', expireTime: new Date(Date.now() + 3600 * 1000).toISOString() }
                }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 200, json: { signedJwt: 'header.payload.sig' } })
        });

        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async path => {
                assert.strictEqual(path, '/var/run/secrets/tokens/gcp-ksa/token');
                return 'k8s-projected-token\n';
            }
        });

        let signed = await signer.sign({ iss: 'svc@proj.iam.gserviceaccount.com', aud: 'https://oauth2.googleapis.com/token' });
        assert.strictEqual(signed, 'header.payload.sig');

        assert.strictEqual(calls.length, 3);

        let stsCall = calls[0];
        assert.strictEqual(stsCall.options.method, 'POST');
        let stsParams = new URLSearchParams(stsCall.options.body);
        assert.strictEqual(stsParams.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
        assert.strictEqual(stsParams.get('audience'), VALID_FILE_CONFIG.audience);
        assert.strictEqual(stsParams.get('subject_token'), 'k8s-projected-token');
        assert.strictEqual(stsParams.get('subject_token_type'), VALID_FILE_CONFIG.subject_token_type);
        assert.strictEqual(stsParams.get('requested_token_type'), 'urn:ietf:params:oauth:token-type:access_token');
        assert.strictEqual(stsParams.get('scope'), 'https://www.googleapis.com/auth/cloud-platform');

        let impCall = calls[1];
        assert.strictEqual(impCall.options.method, 'POST');
        assert.strictEqual(impCall.options.headers.Authorization, 'Bearer federated-tok');
        let impBody = JSON.parse(impCall.options.body);
        assert.deepStrictEqual(impBody, { scope: ['https://www.googleapis.com/auth/cloud-platform'] });

        let signCall = calls[2];
        assert.strictEqual(signCall.options.method, 'POST');
        assert.strictEqual(signCall.options.headers.Authorization, 'Bearer impersonated-tok');
        let signBody = JSON.parse(signCall.options.body);
        assert.strictEqual(typeof signBody.payload, 'string');
        let parsedPayload = JSON.parse(signBody.payload);
        assert.strictEqual(parsedPayload.iss, 'svc@proj.iam.gserviceaccount.com');
    });

    await t.test('sign() uses url credential source with json format', async () => {
        let { fetchImpl, calls } = makeFakeFetch({
            'http://169.254.169.254': () => makeResponse({ status: 200, text: '{"access_token":"imds-token"}' }),
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'fed' } }),
            // Impersonation URL is taken from the config as-is.
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc@proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({ status: 200, json: { accessToken: 'imp', expireTime: new Date(Date.now() + 3600 * 1000).toISOString() } }),
            // signJwt URL is built by the signer with encodeURIComponent on the email.
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 200, json: { signedJwt: 'a.b.c' } })
        });

        let signer = new ExternalAccountSigner({ config: VALID_URL_CONFIG, fetchImpl });
        let signed = await signer.sign({ iss: 'svc@proj.iam.gserviceaccount.com' });
        assert.strictEqual(signed, 'a.b.c');

        let imdsCall = calls[0];
        assert.strictEqual(imdsCall.options.method, 'GET');
        assert.strictEqual(imdsCall.options.headers.Metadata, 'true');

        let stsCall = calls[1];
        let stsParams = new URLSearchParams(stsCall.options.body);
        assert.strictEqual(stsParams.get('subject_token'), 'imds-token');
    });

    await t.test('sign() caches impersonated token across calls within TTL', async () => {
        let now = 1700000000000;
        let { fetchImpl, calls } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'fed' } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({
                    status: 200,
                    json: { accessToken: 'imp', expireTime: new Date(now + 3600 * 1000).toISOString() }
                }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 200, json: { signedJwt: 'sig' } })
        });

        let readCount = 0;
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => {
                readCount++;
                return 'tok\n';
            },
            nowImpl: () => now
        });

        await signer.sign({ iss: 'a' });
        await signer.sign({ iss: 'b' });

        // Second call should NOT re-read file, NOT re-hit STS, NOT re-hit impersonate.
        // It only re-hits signJwt.
        assert.strictEqual(readCount, 1);
        let stsCalls = calls.filter(c => c.url === 'https://sts.googleapis.com/v1/token');
        let impCalls = calls.filter(c => c.url.includes(':generateAccessToken'));
        let signCalls = calls.filter(c => c.url.includes(':signJwt'));
        assert.strictEqual(stsCalls.length, 1);
        assert.strictEqual(impCalls.length, 1);
        assert.strictEqual(signCalls.length, 2);
    });

    await t.test('sign() re-acquires impersonated token after expiry', async () => {
        let now = 1700000000000;
        let impExpiry = now + 1000; // already near expiry
        let { fetchImpl, calls } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'fed' } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({ status: 200, json: { accessToken: 'imp', expireTime: new Date(impExpiry).toISOString() } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 200, json: { signedJwt: 'sig' } })
        });

        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => 'tok',
            nowImpl: () => now
        });

        await signer.sign({ iss: 'a' });
        // Advance past skew threshold
        now = impExpiry + 1000;
        await signer.sign({ iss: 'b' });

        let stsCalls = calls.filter(c => c.url === 'https://sts.googleapis.com/v1/token');
        assert.strictEqual(stsCalls.length, 2);
    });

    await t.test('sign() surfaces STS HTTP errors as ESTSExchange', async () => {
        let { fetchImpl } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 400, json: { error: 'invalid_request', error_description: 'wrong audience' } })
        });
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => 'tok'
        });
        await assert.rejects(
            () => signer.sign({ iss: 'a' }),
            err => err.code === 'ESTSExchange' && err.statusCode === 400
        );
    });

    await t.test('sign() surfaces impersonation HTTP errors as EImpersonate', async () => {
        let { fetchImpl } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'fed' } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({ status: 403, json: { error: { message: 'token-creator missing' } } })
        });
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => 'tok'
        });
        await assert.rejects(
            () => signer.sign({ iss: 'a' }),
            err => err.code === 'EImpersonate' && err.statusCode === 403
        );
    });

    await t.test('sign() surfaces signJwt 429 with retryAfter', async () => {
        let { fetchImpl } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': () => makeResponse({ status: 200, json: { access_token: 'fed' } }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({
                    status: 200,
                    json: { accessToken: 'imp', expireTime: new Date(Date.now() + 3600 * 1000).toISOString() }
                }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 429, headers: { 'retry-after': '17' }, json: { error: 'quota' } })
        });
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => 'tok'
        });
        await assert.rejects(
            () => signer.sign({ iss: 'a' }),
            err => err.code === 'ESignJwt' && err.statusCode === 429 && err.retryAfter === 17
        );
    });

    await t.test('sign() rejects when subject token file is empty', async () => {
        let { fetchImpl } = makeFakeFetch({});
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => '   \n'
        });
        await assert.rejects(
            () => signer.sign({ iss: 'a' }),
            err => err.code === 'ESubjectTokenRead'
        );
    });

    await t.test('sign() rejects when subject token url returns non-2xx', async () => {
        let { fetchImpl } = makeFakeFetch({
            'http://169.254.169.254': () => makeResponse({ status: 500, text: 'imds broken' })
        });
        let signer = new ExternalAccountSigner({ config: VALID_URL_CONFIG, fetchImpl });
        await assert.rejects(
            () => signer.sign({ iss: 'a' }),
            err => err.code === 'ESubjectTokenRead' && err.statusCode === 500
        );
    });

    await t.test('concurrent sign() on cold cache shares one STS/impersonate chain', async () => {
        let now = 1700000000000;
        // Gate the STS response so we can fire concurrent calls while the chain is in flight.
        let stsRelease;
        let stsGate = new Promise(resolve => {
            stsRelease = resolve;
        });
        let { fetchImpl, calls } = makeFakeFetch({
            'https://sts.googleapis.com/v1/token': async () => {
                await stsGate;
                return makeResponse({ status: 200, json: { access_token: 'fed' } });
            },
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken': () =>
                makeResponse({
                    status: 200,
                    json: { accessToken: 'imp', expireTime: new Date(now + 3600 * 1000).toISOString() }
                }),
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:signJwt': () =>
                makeResponse({ status: 200, json: { signedJwt: 'sig' } })
        });

        let readCount = 0;
        let signer = new ExternalAccountSigner({
            config: VALID_FILE_CONFIG,
            fetchImpl,
            readFileImpl: async () => {
                readCount++;
                return 'tok';
            },
            nowImpl: () => now
        });

        // Fire 10 concurrent signs against a cold cache.
        let inflight = Array.from({ length: 10 }, (_, i) => signer.sign({ iss: `iss-${i}` }));
        // Release the STS chain.
        stsRelease();
        let results = await Promise.all(inflight);

        assert.strictEqual(results.length, 10);
        // Even with 10 concurrent callers, only one chain ran:
        assert.strictEqual(readCount, 1);
        assert.strictEqual(calls.filter(c => c.url === 'https://sts.googleapis.com/v1/token').length, 1);
        assert.strictEqual(calls.filter(c => c.url.includes(':generateAccessToken')).length, 1);
        // signJwt fires once per caller.
        assert.strictEqual(calls.filter(c => c.url.includes(':signJwt')).length, 10);
    });

    await t.test('describeCredentialSource reports the active source type', () => {
        let signer = new ExternalAccountSigner({ config: VALID_FILE_CONFIG, fetchImpl: async () => makeResponse() });
        assert.deepStrictEqual(signer.describeCredentialSource(), { type: 'file', location: VALID_FILE_CONFIG.credential_source.file });

        let urlSigner = new ExternalAccountSigner({ config: VALID_URL_CONFIG, fetchImpl: async () => makeResponse() });
        assert.deepStrictEqual(urlSigner.describeCredentialSource(), { type: 'url', location: VALID_URL_CONFIG.credential_source.url });
    });
});
