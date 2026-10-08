'use strict';

// The Google Cloud metadata server client behind the `metadataServer` authentication method. The
// host can be moved from the environment only, and only the host: these tests pin both halves of
// that, the failure classification the verify report keys its hints on, and (against a real local
// HTTP server) the request EmailEngine actually sends.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');
const { Headers } = require('undici');

const { resolveMetadataOrigin, fetchAccessToken, describeAttachedIdentity, isTransientMetadataError } = require('../lib/oauth/gcp-metadata');
const { withInstantTimers } = require('./helpers/instant-timers');

const TOKEN_PATH = '/computeMetadata/v1/instance/service-accounts/default/token';

// A fetch() double answering with the given status, body and response headers, recording each call
function stubFetch(answers) {
    const calls = [];
    const queue = [].concat(answers);
    const fetchImpl = async (url, opts) => {
        calls.push({ url, opts });
        const answer = queue.length > 1 ? queue.shift() : queue[0];
        if (answer instanceof Error) {
            throw answer;
        }
        const headers = new Headers(answer.headers === undefined ? { 'Metadata-Flavor': 'Google' } : answer.headers);
        return {
            status: answer.status || 200,
            ok: (answer.status || 200) >= 200 && (answer.status || 200) < 300,
            headers,
            text: async () => (typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body))
        };
    };
    return { fetchImpl, calls };
}

const EMPTY_ENV = {};

test('resolveMetadataOrigin()', async t => {
    await t.test('defaults to the DNS name, never the link-local address', () => {
        assert.equal(resolveMetadataOrigin(EMPTY_ENV), 'http://metadata.google.internal');
    });

    await t.test('takes host, host:port and http://host[:port]', () => {
        assert.equal(resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: '127.0.0.1' }), 'http://127.0.0.1');
        assert.equal(resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: '127.0.0.1:8080' }), 'http://127.0.0.1:8080');
        assert.equal(resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: 'http://metadata.local:81/' }), 'http://metadata.local:81');
        assert.equal(resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: ' 169.254.169.254 ' }), 'http://169.254.169.254');
    });

    await t.test("reads Google's own variable when EmailEngine's is unset, and prefers EmailEngine's", () => {
        assert.equal(resolveMetadataOrigin({ GCE_METADATA_HOST: '10.0.0.2' }), 'http://10.0.0.2');
        assert.equal(resolveMetadataOrigin({ GCE_METADATA_HOST: '10.0.0.2', EENGINE_GCP_METADATA_HOST: '10.0.0.3' }), 'http://10.0.0.3');
        assert.equal(resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: '', GCE_METADATA_HOST: '10.0.0.2' }), 'http://10.0.0.2');
    });

    await t.test('reads the process environment through readEnvValue(), so the _FILE form works', async t => {
        const fs = require('node:fs');
        const os = require('node:os');
        const pathlib = require('node:path');
        const file = pathlib.join(fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-gcp-metadata-')), 'host');
        fs.writeFileSync(file, '10.0.0.9:8080\n');

        const saved = {};
        for (const key of ['EENGINE_GCP_METADATA_HOST', 'EENGINE_GCP_METADATA_HOST_FILE', 'GCE_METADATA_HOST']) {
            saved[key] = process.env[key];
            delete process.env[key];
        }
        t.after(() => {
            for (const [key, value] of Object.entries(saved)) {
                if (value === undefined) {
                    delete process.env[key];
                } else {
                    process.env[key] = value;
                }
            }
            fs.rmSync(pathlib.dirname(file), { recursive: true, force: true });
        });

        process.env.EENGINE_GCP_METADATA_HOST_FILE = file;
        assert.equal(resolveMetadataOrigin(), 'http://10.0.0.9:8080');
    });

    await t.test('refuses anything but a host, rather than falling back to the default', () => {
        // Only the host moves. A path, query, credentials or another scheme would let the override
        // reshape the request, and quietly ignoring it would send a test setup to the real server
        for (const value of [
            'https://metadata.google.internal',
            'http://127.0.0.1/computeMetadata/v1',
            'http://127.0.0.1/?x=1',
            'http://user:pass@127.0.0.1',
            'ftp://127.0.0.1',
            'http://',
            '127.0.0.1#frag',
            'host name with spaces'
        ]) {
            assert.throws(() => resolveMetadataOrigin({ EENGINE_GCP_METADATA_HOST: value }), { code: 'EMetadataConfig' }, value);
        }
        assert.throws(
            () => resolveMetadataOrigin({ GCE_METADATA_HOST: 'https://x' }),
            err => err.code === 'EMetadataConfig' && /GCE_METADATA_HOST/.test(err.message)
        );
    });
});

test('fetchAccessToken()', async t => {
    await t.test('returns the token the metadata server issues', async () => {
        const { fetchImpl, calls } = stubFetch({ body: { access_token: 'ya29.token', expires_in: 3599, token_type: 'Bearer' } });

        const token = await fetchAccessToken({ fetchImpl, env: EMPTY_ENV });

        assert.deepEqual(token, { access_token: 'ya29.token', expires_in: 3599, token_type: 'Bearer' });
        assert.equal(calls.length, 1);
        assert.equal(calls[0].url, `http://metadata.google.internal${TOKEN_PATH}`);
        assert.equal(calls[0].opts.method, 'GET');
        assert.equal(calls[0].opts.headers['Metadata-Flavor'], 'Google');
        // a redirect would carry the request somewhere the policy never vetted
        assert.equal(calls[0].opts.redirect, 'error');
        assert.ok(calls[0].opts.dispatcher, 'the direct agent, never the shared proxy dispatcher');
    });

    await t.test('leaves a missing or unusable expires_in to the caller default', async () => {
        for (const expiresIn of [undefined, 'soon', 0, -5]) {
            const { fetchImpl } = stubFetch({ body: { access_token: 'a', expires_in: expiresIn } });
            const token = await fetchAccessToken({ fetchImpl, env: EMPTY_ENV });
            assert.equal(token.expires_in, undefined, String(expiresIn));
            assert.equal(token.token_type, 'Bearer');
        }
    });

    await t.test('an answer without a token is EMetadataResponse', async () => {
        for (const body of ['not json', { expires_in: 3599 }, { access_token: '' }, { access_token: 12 }]) {
            const { fetchImpl } = stubFetch({ body });
            await assert.rejects(fetchAccessToken({ fetchImpl, env: EMPTY_ENV }), { code: 'EMetadataResponse' });
        }
    });

    await t.test('retries one maintenance 503 and succeeds', async () => {
        const { fetchImpl, calls } = stubFetch([{ status: 503, body: 'unavailable' }, { body: { access_token: 'after-503', expires_in: 100 } }]);

        const { result, error, delays } = await withInstantTimers(() => fetchAccessToken({ fetchImpl, env: EMPTY_ENV }));

        assert.equal(error, undefined);
        assert.equal(result.access_token, 'after-503');
        assert.equal(calls.length, 2);
        assert.deepEqual(delays, [500]);
    });

    await t.test('a second 503 is EMetadataServer, not another retry', async () => {
        const { fetchImpl, calls } = stubFetch({ status: 503, body: 'unavailable' });
        const { error } = await withInstantTimers(() => fetchAccessToken({ fetchImpl, env: EMPTY_ENV }));
        assert.equal(error.code, 'EMetadataServer');
        assert.equal(error.statusCode, 503);
        assert.equal(calls.length, 2);
    });

    await t.test('a 404 (no service account attached) is EMetadataServer with the status', async () => {
        const { fetchImpl, calls } = stubFetch({ status: 404, body: 'not found' });
        await assert.rejects(fetchAccessToken({ fetchImpl, env: EMPTY_ENV }), err => {
            assert.equal(err.code, 'EMetadataServer');
            assert.equal(err.statusCode, 404);
            assert.equal(err.wrongFlavor, undefined);
            assert.match(err.message, /http:\/\/metadata\.google\.internal/);
            return true;
        });
        assert.equal(calls.length, 1, 'only a 503 is retried');
    });

    await t.test('a 200 without the Metadata-Flavor answer is refused', async () => {
        // something else listening at the address: another cloud's metadata service, a captive proxy
        for (const headers of [{}, { 'Metadata-Flavor': 'Amazon' }]) {
            const { fetchImpl } = stubFetch({ body: { access_token: 'not-from-google' }, headers });
            await assert.rejects(fetchAccessToken({ fetchImpl, env: EMPTY_ENV }), err => {
                assert.equal(err.code, 'EMetadataServer');
                assert.equal(err.wrongFlavor, true);
                return true;
            });
        }
    });

    await t.test('an error answer without the Metadata-Flavor header is the wrong server, not a missing account', async () => {
        // a parking host or a cluster search domain answering metadata.google.internal with a 404
        const { fetchImpl } = stubFetch({ status: 404, body: 'not found', headers: {} });
        await assert.rejects(fetchAccessToken({ fetchImpl, env: EMPTY_ENV }), err => {
            assert.equal(err.code, 'EMetadataServer');
            assert.equal(err.wrongFlavor, true);
            assert.equal(err.statusCode, undefined);
            return true;
        });
    });

    await t.test('a network failure is EMetadataUnreachable naming the cause', async () => {
        const dnsError = Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }) });
        const { fetchImpl } = stubFetch(dnsError);
        await assert.rejects(fetchAccessToken({ fetchImpl, env: EMPTY_ENV }), err => {
            assert.equal(err.code, 'EMetadataUnreachable');
            assert.match(err.message, /ENOTFOUND/);
            assert.equal(err.cause, dnsError);
            return true;
        });

        const timeout = Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
        await assert.rejects(fetchAccessToken({ fetchImpl: stubFetch(timeout).fetchImpl, env: EMPTY_ENV }), err => {
            assert.equal(err.code, 'EMetadataUnreachable');
            assert.match(err.message, /no answer within/);
            return true;
        });
    });

    await t.test('an invalid override fails before any request', async () => {
        const { fetchImpl, calls } = stubFetch({ body: { access_token: 'a' } });
        await assert.rejects(fetchAccessToken({ fetchImpl, env: { EENGINE_GCP_METADATA_HOST: 'https://x' } }), { code: 'EMetadataConfig' });
        assert.equal(calls.length, 0);
    });
});

test('isTransientMetadataError() separates a blip from a misconfiguration', async () => {
    const failure = async answers => {
        const { fetchImpl } = stubFetch(answers);
        return (await withInstantTimers(() => fetchAccessToken({ fetchImpl, env: EMPTY_ENV }))).error;
    };
    const fetchFailed = code => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(code), { code }) });
    const timeout = Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });

    for (const answers of [
        { status: 503, body: 'x' },
        { status: 500, body: 'x' },
        timeout,
        fetchFailed('ECONNRESET'),
        fetchFailed('UND_ERR_HEADERS_TIMEOUT')
    ]) {
        const err = await failure(answers);
        assert.equal(isTransientMetadataError(err), true, err.message);
    }

    for (const answers of [
        { status: 404, body: 'x' },
        { status: 403, body: 'x' },
        { status: 503, body: 'x', headers: {} },
        fetchFailed('ENOTFOUND'),
        fetchFailed('ECONNREFUSED'),
        { body: 'not json' }
    ]) {
        const err = await failure(answers);
        assert.equal(isTransientMetadataError(err), false, err.message);
    }
    assert.equal(isTransientMetadataError(null), false);
});

test('describeAttachedIdentity() reads the service account and project', async () => {
    const { fetchImpl, calls } = stubFetch({ body: 'placeholder' });
    const answers = {
        '/computeMetadata/v1/instance/service-accounts/default/email': 'ee-pubsub@proj-1.iam.gserviceaccount.com\n',
        '/computeMetadata/v1/project/project-id': 'proj-1'
    };
    const routed = async (url, opts) => {
        const res = await fetchImpl(url, opts);
        const path = new URL(url).pathname;
        return Object.assign(res, { text: async () => answers[path] });
    };

    const identity = await describeAttachedIdentity({ fetchImpl: routed, env: { EENGINE_GCP_METADATA_HOST: '127.0.0.1:9' } });

    assert.deepEqual(identity, { serviceAccountEmail: 'ee-pubsub@proj-1.iam.gserviceaccount.com', projectId: 'proj-1' });
    assert.equal(calls.length, 2);
});

test('against a local metadata server double', async t => {
    // The real undici request, with no fetch() injected: what headers actually leave, and how the
    // direct agent behaves with a redirect and a closed port
    const seen = [];
    let mode = 'ok';
    const server = http.createServer((req, res) => {
        seen.push({ method: req.method, url: req.url, flavor: req.headers['metadata-flavor'], userAgent: req.headers['user-agent'] });
        if (mode === 'redirect') {
            res.writeHead(302, { Location: 'http://127.0.0.1:1/elsewhere', 'Metadata-Flavor': 'Google' });
            return res.end();
        }
        if (req.headers['metadata-flavor'] !== 'Google') {
            res.writeHead(403);
            return res.end('Missing Metadata-Flavor:Google header.');
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Metadata-Flavor': 'Google' });
        res.end(JSON.stringify({ access_token: 'local-token', expires_in: 1234, token_type: 'Bearer' }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const env = { EENGINE_GCP_METADATA_HOST: `127.0.0.1:${server.address().port}` };

    await t.test('sends the flavor header and identifies itself', async () => {
        const token = await fetchAccessToken({ env });
        assert.equal(token.access_token, 'local-token');
        assert.equal(token.expires_in, 1234);
        const last = seen[seen.length - 1];
        assert.equal(last.method, 'GET');
        assert.equal(last.url, TOKEN_PATH);
        assert.equal(last.flavor, 'Google');
        assert.match(last.userAgent, /^emailengine-app\//);
    });

    await t.test('does not follow a redirect', async () => {
        mode = 'redirect';
        try {
            await assert.rejects(fetchAccessToken({ env }), { code: 'EMetadataUnreachable' });
        } finally {
            mode = 'ok';
        }
    });

    await t.test('a closed port is EMetadataUnreachable', async () => {
        const probe = http.createServer();
        await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
        const port = probe.address().port;
        await new Promise(resolve => probe.close(resolve));

        await assert.rejects(fetchAccessToken({ env: { EENGINE_GCP_METADATA_HOST: `127.0.0.1:${port}` } }), err => {
            assert.equal(err.code, 'EMetadataUnreachable');
            assert.match(err.message, /ECONNREFUSED/);
            return true;
        });
    });
});
