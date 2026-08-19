'use strict';

// Hermetic unit tests for lib/api-routes/route-helpers.js. Pure functions, no DB or network.

const test = require('node:test');
const assert = require('node:assert').strict;
const Boom = require('@hapi/boom');
const Joi = require('joi');

const {
    handleError,
    maskCustomHeaders,
    maskUrlPassword,
    maskSecrets,
    containsMaskedSecret,
    isMaskedRoundTrip,
    assertNoNetworkOverride,
    MASKED
} = require('../lib/api-routes/route-helpers');

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
        // The username goes too: it is half of the same credential, and on a proxy that keys on a
        // token it is the whole of it.
        const masked = maskUrlPassword('socks5://user:secret@proxy.example.com:1080');
        assert.equal(masked, `socks5://${MASKED}:${MASKED}@proxy.example.com:1080`);
        assert.ok(!masked.includes('secret'));
        assert.ok(!masked.includes('user'));
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
        // lib/tools.js reads exactly that shape. Gating only on the password let it straight through:
        // the URL came back as `socks://tok3n:******@...`, which discloses the whole credential and
        // invents a password that was never stored. Asserted on the exact value rather than on the
        // absence of `tok3n@` - the substring passed while the token was intact, because a colon had
        // been inserted after it.
        assert.equal(maskUrlPassword('socks://tok3n@proxy.example.com:1080'), `socks://${MASKED}@proxy.example.com:1080`);

        // The mirror image: a password with no username keeps the empty username rather than
        // gaining one
        assert.equal(maskUrlPassword('https://:hookpass@receiver.example.com/hook'), `https://:${MASKED}@receiver.example.com/hook`);
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

    await t.test('masks the connection error state under the name the account actually stores', () => {
        // Account.unserializeAccountData() parses it as `lastErrorState`; only the getter renames it
        // to `lastError` on the way out, well after the mask runs. Masking one name and not the other
        // published the proxy of the failed connection from an endpoint whose mask call looked total.
        const account = { lastErrorState: { response: 'Connection refused', networkRouting: { proxy: credentialedProxy } } };
        maskSecrets(account);
        assert.ok(!JSON.stringify(account).includes('ppass'), `a proxy password survived: ${JSON.stringify(account)}`);
        assert.equal(account.lastErrorState.response, 'Connection refused', 'the error message itself is not a credential');
    });
});

// A route-level permission model does not inspect payloads, which is fine until a payload field
// decides where a credential is sent. `submit` is grantable, so this is the one place the narrowing
// has to do what the route grant cannot.
test('assertNoNetworkOverride keeps a narrowed token off the connection route', async t => {
    const narrowed = { permissions: { actions: ['send'], groups: ['submit'] } };
    const proxyPayload = { proxy: 'socks5://attacker.example.com:1080' };

    await t.test('refuses a submit-time proxy from a narrowed token', () => {
        assert.throws(
            () => assertNoNetworkOverride({ payload: proxyPayload, auth: { artifacts: narrowed } }),
            err => Boom.isBoom(err) && err.output.statusCode === 403,
            'a send-only token could redirect the SMTP session and collect the account credentials'
        );
    });

    await t.test('reads an unusable permissions record as narrowed', () => {
        // `{}` is malformed to lib/token-permissions.js, not absent, and both enforcement points
        // deny on it. This must not be the one reader that takes it for "no narrowing".
        for (const permissions of [{}, 'nonsense', ['read']]) {
            assert.throws(() => assertNoNetworkOverride({ payload: proxyPayload, auth: { artifacts: { permissions } } }));
        }
    });

    await t.test('leaves an unnarrowed token alone', () => {
        // It already reaches PUT /v1/account/{account} and can point the account's own proxy
        // anywhere, so refusing it here would cost a documented capability and buy nothing.
        assertNoNetworkOverride({ payload: proxyPayload, auth: { artifacts: {} } });
        assertNoNetworkOverride({ payload: proxyPayload, auth: { artifacts: { permissions: null } } });
        assertNoNetworkOverride({ payload: proxyPayload, auth: {} });
        assertNoNetworkOverride({ payload: proxyPayload });
    });

    await t.test('never refuses a submission that sets no proxy', () => {
        // Which is every ordinary send, including the draft variant with an empty body
        assertNoNetworkOverride({ payload: { to: [{ address: 'x@example.com' }] }, auth: { artifacts: narrowed } });
        assertNoNetworkOverride({ payload: {}, auth: { artifacts: narrowed } });
        assertNoNetworkOverride({ auth: { artifacts: narrowed } });
    });
});

test('write-side mask guards', async t => {
    await t.test('containsMaskedSecret spots the mask in URL credentials', () => {
        assert.equal(containsMaskedSecret('webhooks', `https://${MASKED}:${MASKED}@example.com/hook`), true);
        assert.equal(containsMaskedSecret('proxyUrl', `socks5://${MASKED}@proxy.example.com:1080`), true);
        assert.equal(containsMaskedSecret('httpProxyUrl', `http://user:${MASKED}@proxy.example.com:3128`), true);

        assert.equal(containsMaskedSecret('webhooks', 'https://user:real-secret@example.com/hook'), false);
        assert.equal(containsMaskedSecret('webhooks', 'https://example.com/hook'), false);
        assert.equal(containsMaskedSecret('webhooks', 'not a url'), false);
        assert.equal(containsMaskedSecret('webhooks', null), false);
    });

    await t.test('containsMaskedSecret spots the mask in header values', () => {
        assert.equal(containsMaskedSecret('webhooksCustomHeaders', [{ key: 'Authorization', value: MASKED }]), true);
        assert.equal(containsMaskedSecret('webhooksCustomHeaders', [{ key: 'Authorization', value: 'Bearer real' }]), false);
        assert.equal(containsMaskedSecret('webhooksCustomHeaders', []), false);
    });

    await t.test('containsMaskedSecret ignores keys that are never masked', () => {
        assert.equal(containsMaskedSecret('serviceUrl', `https://${MASKED}:${MASKED}@example.com/`), false);
        assert.equal(containsMaskedSecret('notifyText', true), false);
    });

    await t.test('isMaskedRoundTrip accepts exactly the masked echo of the stored value', () => {
        const stored = 'https://user:secret@example.com/hook';
        const echo = maskUrlPassword(stored);

        assert.equal(isMaskedRoundTrip('webhooks', echo, stored), true);
        // same mask, different destination - the credential cannot be carried over
        assert.equal(isMaskedRoundTrip('webhooks', `https://${MASKED}:${MASKED}@other.example.com/hook`, stored), false);
        // nothing stored to echo
        assert.equal(isMaskedRoundTrip('webhooks', echo, null), false);
    });

    await t.test('isMaskedRoundTrip compares header lists on key and value', () => {
        const stored = [
            { key: 'Authorization', value: 'Bearer real' },
            { key: 'X-Plain', value: '' }
        ];
        const echo = maskCustomHeaders(stored);

        assert.equal(isMaskedRoundTrip('webhooksCustomHeaders', echo, stored), true);
        assert.equal(isMaskedRoundTrip('webhooksCustomHeaders', [{ key: 'Authorization', value: MASKED }], stored), false);
        assert.equal(isMaskedRoundTrip('webhooksCustomHeaders', [{ key: 'Other', value: MASKED }], []), false);
    });
});
