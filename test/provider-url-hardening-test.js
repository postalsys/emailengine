'use strict';

// Hermetic tests for the places where caller-supplied values become part of a URL or of an
// internal command:
//
//   - Account.listSignatures() builds its RPC message from the account alone (the route used to
//     merge the query over it, so `?cmd=listMessages&account=other` ran any command against any
//     account)
//   - the Graph request layer only follows an absolute URL (@odata.nextLink, @odata.deltaLink)
//     on the origin the app is configured for, since the bearer token travels with it
//   - the request-side provider ids (a search by emailId or threadId) stay inside their path
//     segment
//   - the `tls` object of an IMAP or SMTP configuration names TLS options only, not the
//     connection keys that would reroute it (`path` to a Unix socket, `host`, `port`, `lookup`)

const test = require('node:test');
const assert = require('node:assert').strict;
const Joi = require('joi');

const { Account } = require('../lib/account');
const graphApi = require('../lib/email-client/outlook/graph-api');
const { imapSchema, smtpSchema, imapUpdateSchema, smtpUpdateSchema, searchSchema, messageReferenceSchema } = require('../lib/schemas');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

test('Account.listSignatures() takes no caller input', async t => {
    const calls = [];
    const accountObject = new Account({
        redis,
        account: 'own-account',
        call: async message => {
            calls.push(message);
            return { signatures: [] };
        },
        secret: 'secret',
        timeout: 1234
    });
    accountObject.loadAccountData = async () => ({ account: 'own-account' });

    await t.test('the message names the command and the account the object was built for', async () => {
        await accountObject.listSignatures();
        assert.deepEqual(calls, [{ cmd: 'listSignatures', account: 'own-account', timeout: 1234 }]);
    });

    await t.test('an argument does not reach the message', async () => {
        calls.length = 0;
        await accountObject.listSignatures({ cmd: 'listMessages', account: 'victim', path: 'INBOX' });
        assert.deepEqual(calls, [{ cmd: 'listSignatures', account: 'own-account', timeout: 1234 }]);
    });
});

test('Graph requests stay on the configured API origin', async t => {
    const requests = [];
    const context = {
        account: 'test-account',
        logger: noopLogger,
        getTokenData: async () => ({ accessToken: 'fake-token', cached: false }),
        invalidateAccessToken: async () => {},
        oAuth2Client: {
            apiBase: 'https://graph.microsoft.com',
            provider: 'outlook',
            request: async (accessToken, url) => {
                requests.push(url);
                return { ok: true };
            }
        }
    };

    await t.test('a relative path and an absolute Graph link are sent', async () => {
        await graphApi.request(context, '/me/messages', 'get');
        await graphApi.request(context, 'https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc', 'get');
        assert.deepEqual(requests, ['https://graph.microsoft.com/v1.0/me/messages', 'https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc']);
    });

    await t.test('an absolute link on another origin is refused before the token leaves', async () => {
        requests.length = 0;
        await assert.rejects(
            () => graphApi.request(context, 'https://graph.microsoft.com.attacker.example/v1.0/me/messages', 'get'),
            err => err.code === 'InvalidGraphUrl'
        );
        await assert.rejects(
            () => graphApi.request(context, 'https://evil.example/v1.0/me/messages', 'get'),
            err => err.code === 'InvalidGraphUrl'
        );
        assert.deepEqual(requests, []);
    });
});

test('request-side provider ids stay inside their path segment', async t => {
    const search = searchSchema;
    const reference = messageReferenceSchema;

    await t.test('the shapes the providers hand out validate', () => {
        for (const emailId of ['1278455344230334865', 'AAMkAGI2TG93AAA=', 'AQMkADAwATM3ZmYAZS1kNmQ4LTA0YjQtMDACLTAwCgBGAAAD-_=']) {
            const { error } = search.validate({ emailId });
            assert.equal(error, undefined, emailId);
        }
        assert.equal(search.validate({ emailIds: ['1278455344230334865', 'AAMkAGI2TG93AAA='] }).error, undefined);
        assert.equal(reference.validate({ threadId: '1694936993596975454', action: 'reply' }).error, undefined);
    });

    await t.test('a dot segment, a slash or a query is refused', () => {
        for (const emailId of ['..', '.', '../../users/victim@example.com/messages/x', 'a/b', 'a?format=raw', 'a#x', 'a%2Fb', 'a b']) {
            assert.ok(search.validate({ emailId }).error, emailId);
            assert.ok(search.validate({ emailIds: [emailId] }).error, emailId);
            assert.ok(search.validate({ threadId: emailId }).error, emailId);
            assert.ok(reference.validate({ threadId: emailId, action: 'reply' }).error, emailId);
        }
    });
});

test('the tls object of a connection configuration names TLS options only', async t => {
    const schemas = {
        imap: Joi.object(imapSchema),
        smtp: Joi.object(smtpSchema),
        imapUpdate: Joi.object(imapUpdateSchema),
        smtpUpdate: Joi.object(smtpUpdateSchema)
    };
    const base = {
        imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } },
        smtp: { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'u', pass: 'p' } },
        imapUpdate: { partial: true },
        smtpUpdate: { partial: true }
    };

    await t.test('the documented options validate', () => {
        const tls = {
            rejectUnauthorized: false,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            servername: 'mail.example.com',
            ciphers: 'HIGH:!aNULL',
            ca: ['-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'],
            cert: '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----',
            key: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
            passphrase: 'x',
            honorCipherOrder: true,
            ecdhCurve: 'auto',
            sigalgs: 'RSA-PSS+SHA256',
            secureOptions: 0
        };
        for (const [name, schema] of Object.entries(schemas)) {
            const { error } = schema.validate(Object.assign({}, base[name], { tls }));
            assert.equal(error, undefined, `${name}: ${error && error.message}`);
        }
    });

    await t.test('a connection key is refused', () => {
        // Each of these used to be merged into the connect options: `path` opens a Unix socket,
        // `host` and `port` replace the validated ones, `lookup` and `localAddress` reroute
        for (const tls of [
            { path: '/var/run/docker.sock' },
            { host: '10.0.0.1' },
            { port: 25 },
            { localAddress: '10.0.0.2' },
            { lookup: 'x' },
            { socket: {} }
        ]) {
            for (const [name, schema] of Object.entries(schemas)) {
                const { error } = schema.validate(Object.assign({}, base[name], { tls }));
                assert.ok(error, `${name} accepted tls ${JSON.stringify(tls)}`);
            }
        }
    });
});
