'use strict';

// Hermetic unit tests for lib/api-routes/route-helpers.js. Pure functions, no DB or network.

const test = require('node:test');
const assert = require('node:assert').strict;
const Boom = require('@hapi/boom');
const Joi = require('joi');

const { handleError, maskCustomHeaders, maskUrlPassword, maskSecrets, MASKED } = require('../lib/api-routes/route-helpers');

// Minimal request stub - handleError logs at warn (4xx) or error (5xx)
const fakeRequest = { logger: { warn() {}, error() {} } };

// Request stub that records the level handleError logged at, so tests can assert severity
function recordingRequest() {
    const logged = [];
    return {
        logged,
        logger: {
            warn(data) {
                logged.push({ level: 'warn', data });
            },
            error(data) {
                logged.push({ level: 'error', data });
            }
        }
    };
}

test('handleError status mapping', async t => {
    await t.test('preserves an explicit statusCode', () => {
        let err = new Error('bad input');
        err.statusCode = 400;
        err.code = 'UnsupportedSearchTerm';
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 400);
            assert.equal(boomErr.output.payload.code, 'UnsupportedSearchTerm');
        }
    });

    await t.test('maps MissingServerExtension (no statusCode) to 422', () => {
        let err = new Error('Server does not support X-GM-EXT-1 extension required for label search');
        err.code = 'MissingServerExtension';
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 422);
            assert.equal(boomErr.output.payload.code, 'MissingServerExtension');
            // 4xx errors keep the original message (unlike 5xx, which Boom masks)
            assert.match(boomErr.output.payload.message, /label search/);
        }
    });

    await t.test('defaults an unknown error to 500', () => {
        let err = new Error('boom');
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 500);
        }
    });

    await t.test('passes Boom errors through unchanged', () => {
        let boom = Boom.notFound('nope');
        try {
            handleError(fakeRequest, boom);
            assert.fail('should have thrown');
        } catch (caught) {
            assert.equal(caught, boom);
            assert.equal(caught.output.statusCode, 404);
        }
    });
});

test('handleError log level', async t => {
    await t.test('logs an expected 4xx (Boom 404 existence probe) at warn', () => {
        let request = recordingRequest();
        try {
            handleError(request, Boom.notFound('Account record was not found for requested ID'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged.length, 1);
        assert.equal(request.logged[0].level, 'warn');
        assert.equal(request.logged[0].data.statusCode, 404);
    });

    await t.test('logs a plain 4xx (explicit statusCode) at warn', () => {
        let request = recordingRequest();
        let err = new Error('bad input');
        err.statusCode = 400;
        try {
            handleError(request, err);
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'warn');
        assert.equal(request.logged[0].data.statusCode, 400);
    });

    await t.test('logs a plain 5xx server fault at error', () => {
        let request = recordingRequest();
        try {
            handleError(request, new Error('boom'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'error');
        assert.equal(request.logged[0].data.statusCode, 500);
    });

    await t.test('logs a Boom 5xx server fault at error', () => {
        let request = recordingRequest();
        try {
            handleError(request, Boom.badImplementation('upstream blew up'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'error');
        assert.equal(request.logged[0].data.statusCode, 500);
    });
});

// Masking of credentials that belong to systems other than the mail server. These were returned in
// full by the account and webhook-route getters while the mail passwords beside them were masked,
// which mattered once a token could be narrowed to a group that reaches those reads.
test('secret masking in API responses', async t => {
    await t.test('maskCustomHeaders keeps the keys and blanks the values', () => {
        // The key carries no secret and is what makes the response useful - a reader can see THAT an
        // Authorization header is configured without being handed its value.
        assert.deepEqual(
            maskCustomHeaders([
                { key: 'Authorization', value: 'Bearer super-secret' },
                { key: 'X-Trace', value: '1' }
            ]),
            [
                { key: 'Authorization', value: MASKED },
                { key: 'X-Trace', value: MASKED }
            ]
        );
    });

    await t.test('maskCustomHeaders does not mutate its input', () => {
        const headers = [{ key: 'Authorization', value: 'Bearer super-secret' }];
        maskCustomHeaders(headers);
        assert.equal(headers[0].value, 'Bearer super-secret', 'the stored object was modified in place');
    });

    await t.test('maskCustomHeaders passes through anything that is not a header list', () => {
        assert.equal(maskCustomHeaders(undefined), undefined);
        assert.equal(maskCustomHeaders(null), null);
        assert.deepEqual(maskCustomHeaders([]), []);
        // An entry with no value at all is left alone rather than gaining one
        assert.deepEqual(maskCustomHeaders([{ key: 'X-Only' }]), [{ key: 'X-Only' }]);
    });

    await t.test('maskUrlPassword replaces inline credentials but keeps the host', () => {
        // proxyUrl accepts credentials inline, so returning it verbatim published them. Host and
        // port stay because they are operational information a client legitimately reads back.
        const masked = maskUrlPassword('socks5://user:secret@proxy.example.com:1080');
        assert.equal(masked, `socks5://user:${MASKED}@proxy.example.com:1080`);
        assert.ok(!masked.includes('secret'));
    });

    await t.test('maskUrlPassword returns a passwordless URL byte-identical', () => {
        // The early return matters: URL normalization would otherwise append a trailing slash and
        // change the value for every account that has a proxy without credentials.
        for (const url of ['socks5://proxy.example.com:1080', 'http://proxy.example.com:8080']) {
            assert.equal(maskUrlPassword(url), url);
        }
    });

    await t.test('maskUrlPassword masks a token carried in the username', () => {
        // Commercial proxies commonly key on a token in the username with no password at all, and
        // lib/tools.js reads exactly that shape. Gating only on the password let it straight through.
        const masked = maskUrlPassword('socks://tok3n@proxy.example.com:1080');
        assert.ok(!masked.includes('tok3n@'), `username token survived: ${masked}`);
        assert.ok(masked.includes(MASKED));
    });

    await t.test('maskUrlPassword replaces a value it cannot parse', () => {
        // An unparseable value could itself be the credential that made it unparseable, so it is
        // replaced rather than echoed - the same decision lib/tools.js documents for the log stream.
        // Empty rather than a placeholder because every schema carrying one of these allows it.
        assert.equal(maskUrlPassword('not a url'), '');
        // Falsy input has nothing to protect and stays as it was
        assert.equal(maskUrlPassword(''), '');
        assert.equal(maskUrlPassword(undefined), undefined);
        assert.equal(maskUrlPassword(null), null);
    });

    await t.test('the masked proxy URL still satisfies the response schema', () => {
        // Same constraint as settingsSchema.proxyUrl. A mask that failed response validation would
        // turn every account read with a credentialed proxy into a logged validation error.
        const proxyUrl = Joi.string()
            .uri({ scheme: ['http', 'https', 'socks', 'socks4', 'socks4a', 'socks5'], allowRelative: false })
            .allow('');

        for (const url of ['socks5://user:secret@proxy.example.com:1080', 'http://u:p@1.2.3.4:8080']) {
            assert.equal(proxyUrl.validate(maskUrlPassword(url)).error, undefined, `masked ${url} failed schema validation`);
        }
    });
});

// The leak these close is what made a per-field mask the wrong shape: a failed submission records
// the proxy it used, and that record is persisted onto the account, the gateway and the queue entry -
// so the same URL came back one field over from where it had just been masked.
test('maskSecrets covers every credential-bearing field of an entity', async t => {
    const credentialedProxy = 'socks5://puser:ppass@proxy.example.com:1080';
    const credentialedHook = 'https://huser:hpass@receiver.example.com/hook';

    await t.test('masks the proxy recorded inside a submission status or error', () => {
        // GET /v1/account/{account} masked `proxy` and then returned the same URL through
        // smtpStatus.networkRouting.proxy in the same response body
        const account = {
            proxy: credentialedProxy,
            smtpStatus: { networkRouting: { proxy: credentialedProxy } },
            lastError: { networkRouting: { proxy: credentialedProxy } }
        };
        maskSecrets(account);

        assert.ok(!JSON.stringify(account).includes('ppass'), `a proxy password survived: ${JSON.stringify(account)}`);
    });

    await t.test('masks the proxy inside a queue entry, including under progress.error', () => {
        const entry = { proxy: credentialedProxy, progress: { error: { networkRouting: { proxy: credentialedProxy } } } };
        maskSecrets(entry);
        assert.ok(!JSON.stringify(entry).includes('ppass'), `a proxy password survived: ${JSON.stringify(entry)}`);
    });

    await t.test('masks webhook destinations, which can embed basic auth', () => {
        // The codebase already treats these as credential carriers: workers/webhooks.js refuses to
        // log a raw target URL for this reason. Masking the headers while returning the URL in full
        // left both halves of the same authentication.
        const entities = [{ webhooks: credentialedHook }, { targetUrl: credentialedHook }];
        for (const entity of entities) {
            maskSecrets(entity);
            assert.ok(!JSON.stringify(entity).includes('hpass'), `a webhook password survived: ${JSON.stringify(entity)}`);
        }
    });

    await t.test('masks header values under both field names', () => {
        const entity = {
            customHeaders: [{ key: 'Authorization', value: 'Bearer route-secret' }],
            webhooksCustomHeaders: [{ key: 'Authorization', value: 'Bearer account-secret' }]
        };
        maskSecrets(entity);
        assert.ok(!JSON.stringify(entity).includes('secret'), `a header value survived: ${JSON.stringify(entity)}`);
    });

    await t.test('masks the global settings equivalents', () => {
        // GET /v1/settings returns these under different names, and none of them is in
        // settings.encryptedKeys, so they were disclosed in full
        const values = { proxyUrl: credentialedProxy, httpProxyUrl: credentialedProxy, webhooks: credentialedHook };
        maskSecrets(values);
        assert.ok(!JSON.stringify(values).includes('ppass'));
        assert.ok(!JSON.stringify(values).includes('hpass'));
    });

    await t.test('leaves everything that is not a credential alone', () => {
        const entity = {
            account: 'acct',
            host: 'imap.example.com',
            port: 993,
            smtpEhloName: 'mail.example.com',
            proxy: 'socks5://proxy.example.com:1080',
            lastError: { response: 'Invalid credentials' }
        };
        const before = JSON.stringify(entity);
        maskSecrets(entity);
        assert.equal(JSON.stringify(entity), before, 'a value with no credential in it was rewritten');
    });

    await t.test('does not walk into message content looking for secrets', () => {
        // An outbox entry carries the submitted message. Containers are enumerated rather than
        // scanned recursively, so a body that happens to contain the word proxy is untouched.
        const entry = { messageId: '<a@b>', envelope: { to: ['x@example.com'] }, text: { html: '<p>proxy: socks5://u:p@h</p>' } };
        const before = JSON.stringify(entry);
        maskSecrets(entry);
        assert.equal(JSON.stringify(entry), before);
    });

    await t.test('tolerates anything that is not an entity', () => {
        assert.equal(maskSecrets(undefined), undefined);
        assert.equal(maskSecrets(null), null);
        assert.equal(maskSecrets('str'), 'str');
        assert.deepEqual(maskSecrets({}), {});
    });
});
