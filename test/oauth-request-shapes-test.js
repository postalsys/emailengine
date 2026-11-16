'use strict';

// What the request() method of each OAuth2 provider client (Gmail, Outlook, Mail.ru) sends, and the
// errors and log entries it produces. The three carried their own copy of the same request code with
// differences that matter: Gmail lowercases the method and Outlook uppercases it on the wire (Graph
// refuses a lowercase PATCH), Outlook merges caller headers and parses the body itself, Mail.ru puts
// the token in the query string and sets no status code on its errors. The error objects reach API
// callers and the log entries reach operators, so their fields and key order are pinned here.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');

const { GmailOauth } = require('../lib/oauth/gmail');
const { OutlookOauth } = require('../lib/oauth/outlook');
const { MailRuOauth } = require('../lib/oauth/mail-ru');
const { formatPartialSecretKey } = require('../lib/tools');
const exitWhenStandalone = require('./helpers/exit-standalone');

exitWhenStandalone();

let handler;
let received;

const server = http.createServer((req, res) => {
    let chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
        received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
        handler(req, res);
    });
});

let baseUrl;

test.before(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => new Promise(resolve => server.close(resolve)));

test.beforeEach(() => {
    received = [];
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
    };
});

function respond(status, body, headers) {
    handler = (req, res) => {
        res.writeHead(status, Object.assign({}, headers));
        res.end(body);
    };
}

const SECRET = 'client-secret-value-0123456789';

function createClients(extra) {
    const logs = [];
    const flags = [];
    const logger = {};
    for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = entry => logs.push([level, entry]);
    }
    logger.child = () => logger;
    const opts = Object.assign(
        {
            clientId: 'test-id',
            clientSecret: SECRET,
            redirectUrl: 'http://localhost/callback',
            setFlag: async flag => flags.push(flag),
            logger
        },
        extra
    );
    return {
        logs,
        flags,
        gmail: new GmailOauth(opts),
        outlook: new OutlookOauth(Object.assign({ authority: 'common' }, opts)),
        mailRu: new MailRuOauth(opts)
    };
}

// reqTime is a duration; everything else in an oauthRequest is fixed
function withoutTime(entry) {
    assert.strictEqual(typeof entry.reqTime, 'number');
    return Object.assign({}, entry, { reqTime: 'T' });
}

async function rejection(promise) {
    try {
        await promise;
    } catch (err) {
        return err;
    }
    assert.fail('expected a rejection');
}

test('Gmail request()', async t => {
    await t.test('lowercases the method, sends JSON and answers parsed JSON', async () => {
        const { gmail, logs, flags } = createClients();
        const result = await gmail.request('tok', `${baseUrl}/api`, ' POST ', { a: 1 });
        assert.deepStrictEqual(result, { ok: true });
        assert.strictEqual(received[0].method, 'POST');
        assert.strictEqual(received[0].headers.authorization, 'Bearer tok');
        assert.strictEqual(received[0].headers['content-type'], 'application/json');
        assert.strictEqual(received[0].headers.accept, 'application/json');
        assert.match(received[0].headers['user-agent'], /^emailengine-app\/\S+ \(\+https:\/\//);
        assert.strictEqual(received[0].body, '{"a":1}');
        // the success clears the flag
        assert.deepStrictEqual(flags, [undefined]);
        assert.deepStrictEqual(logs.length, 1);
        assert.strictEqual(logs[0][0], 'debug');
        assert.deepStrictEqual(Object.keys(logs[0][1]), [
            'msg',
            'url',
            'method',
            'provider',
            'status',
            'contentType',
            'clientId',
            'serviceClient',
            'googleProjectId',
            'serviceClientEmail',
            'reqTime'
        ]);
        assert.deepStrictEqual(withoutTime(logs[0][1]), {
            msg: 'External API request completed',
            url: `${baseUrl}/api`,
            method: 'post',
            provider: 'gmail',
            status: 200,
            contentType: 'application/json',
            clientId: 'test-id',
            serviceClient: undefined,
            googleProjectId: undefined,
            serviceClientEmail: undefined,
            reqTime: 'T'
        });
    });

    await t.test('puts a GET payload in the query string, skipping empty values', async () => {
        const { gmail } = createClients();
        await gmail.request('tok', `${baseUrl}/api?x=1`, null, { q: 'a b', n: 2, skip: null, none: undefined });
        assert.strictEqual(received[0].method, 'GET');
        assert.strictEqual(received[0].url, '/api?x=1&q=a+b&n=2');
        assert.strictEqual(received[0].body, '');
    });

    await t.test('sends a Buffer payload as is, with the content type asked for', async () => {
        const { gmail } = createClients();
        await gmail.request('tok', `${baseUrl}/api`, 'post', Buffer.from('raw-bytes'), { contentType: 'message/rfc822' });
        assert.strictEqual(received[0].headers['content-type'], 'message/rfc822');
        assert.strictEqual(received[0].headers.accept, '*/*');
        assert.strictEqual(received[0].body, 'raw-bytes');
    });

    await t.test('returnText answers the body as text', async () => {
        const { gmail } = createClients();
        respond(200, 'plain answer', { 'Content-Type': 'text/plain' });
        assert.strictEqual(await gmail.request('tok', `${baseUrl}/api`, 'get', null, { returnText: true }), 'plain answer');
    });

    await t.test('a failure carries the status, the Retry-After and the flag its body maps to', async () => {
        const { gmail, logs, flags } = createClients();
        respond(403, JSON.stringify({ error: { message: 'Request had insufficient authentication scopes.' } }), {
            'Content-Type': 'application/json; charset=UTF-8',
            'Retry-After': '7'
        });
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'GET'));
        const flag = flags[0];
        assert.strictEqual(flag.code, 'INSUFFICIENT_AUTH_SCOPES');
        assert.deepStrictEqual(Object.keys(err), ['statusCode', 'oauthRequest', 'retryAfter', 'code']);
        assert.strictEqual(err.message, 'OAuth2 request failed');
        assert.strictEqual(err.statusCode, 403);
        assert.strictEqual(err.retryAfter, 7);
        assert.strictEqual(err.code, 'INSUFFICIENT_AUTH_SCOPES');
        const expected = {
            url: `${baseUrl}/api`,
            method: 'get',
            provider: 'gmail',
            status: 403,
            contentType: 'application/json',
            clientId: 'test-id',
            serviceClient: undefined,
            googleProjectId: undefined,
            serviceClientEmail: undefined,
            scopes: gmail.scopes,
            reqTime: 'T',
            retryAfter: 7,
            response: { error: { message: 'Request had insufficient authentication scopes.' } },
            flag
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(withoutTime(err.oauthRequest), expected);
        assert.deepStrictEqual(logs, [['warn', Object.assign({ msg: 'API request failed' }, err.oauthRequest)]]);
        assert.deepStrictEqual(Object.keys(logs[0][1]), ['msg'].concat(Object.keys(expected)));
    });

    await t.test('a failure that blames the client secret shows part of it', async () => {
        const { gmail } = createClients();
        respond(401, JSON.stringify({ error: 'unauthorized_client', error_description: 'Unauthorized' }), { 'Content-Type': 'application/json' });
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'get'));
        assert.strictEqual(err.oauthRequest.clientSecret, formatPartialSecretKey(SECRET));
        assert.strictEqual(err.retryAfter, undefined);
        assert.strictEqual('retryAfter' in err.oauthRequest, false);
        assert.strictEqual(err.code, undefined);
    });

    await t.test('but not without a client secret, and the flag is still raised', async () => {
        const { gmail, flags } = createClients({ clientSecret: undefined });
        const body = { error: 'invalid_client', error_description: 'Unauthorized' };
        respond(401, JSON.stringify(body), { 'Content-Type': 'application/json' });
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'get'));
        assert.strictEqual('clientSecret' in err.oauthRequest, false);
        assert.deepStrictEqual(err.oauthRequest.response, body);
        assert.strictEqual(flags.length, 1);
        assert.strictEqual(err.code, 'INVALID_CLIENT_SECRET');
        assert.strictEqual(err.oauthRequest.flag, flags[0]);
    });

    await t.test('a failure with a body that is not JSON is still logged and thrown', async () => {
        const { gmail, logs, flags } = createClients();
        respond(502, '<html>bad gateway</html>', { 'Content-Type': 'text/html' });
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'get'));
        assert.strictEqual(err.statusCode, 502);
        assert.strictEqual('response' in err.oauthRequest, false);
        assert.strictEqual(err.oauthRequest.contentType, 'text/html');
        assert.deepStrictEqual(flags, []);
        assert.deepStrictEqual(logs, [['warn', Object.assign({ msg: 'API request failed' }, err.oauthRequest)]]);
    });

    await t.test('a success that is not JSON is "Expected JSON"', async () => {
        const { gmail, flags } = createClients();
        respond(200, 'x'.repeat(6000), { 'Content-Type': 'text/html; charset=utf-8' });
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(Object.keys(err), ['oauthRequest']);
        assert.strictEqual(err.message, 'Expected JSON response for OAuth2 request');
        const expected = {
            url: `${baseUrl}/api`,
            method: 'get',
            provider: 'gmail',
            status: 200,
            contentType: 'text/html',
            clientId: 'test-id',
            serviceClient: undefined,
            googleProjectId: undefined,
            serviceClientEmail: undefined,
            scopes: createClients().gmail.scopes,
            reqTime: 'T',
            response: { length: 6000, text: 'x'.repeat(5 * 1024) }
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(withoutTime(err.oauthRequest), expected);
        // the flag was cleared before the body was looked at
        assert.deepStrictEqual(flags, [undefined]);
    });

    await t.test('text/json counts as JSON', async () => {
        const { gmail } = createClients();
        respond(200, '{"v":2}', { 'Content-Type': 'text/json' });
        assert.deepStrictEqual(await gmail.request('tok', `${baseUrl}/api`, 'get'), { v: 2 });
    });

    await t.test('passes the abort signal on', async () => {
        const { gmail } = createClients();
        const controller = new AbortController();
        controller.abort();
        const err = await rejection(gmail.request('tok', `${baseUrl}/api`, 'get', null, { signal: controller.signal }));
        assert.strictEqual(err.name, 'AbortError');
        assert.strictEqual(received.length, 0);
    });
});

test('Outlook request()', async t => {
    await t.test('uppercases the method on the wire and merges caller headers under its own', async () => {
        const { outlook, logs } = createClients();
        const result = await outlook.request(
            'tok',
            `${baseUrl}/api`,
            'patch',
            { isRead: true },
            { headers: { Prefer: 'IdType="ImmutableId"', Authorization: 'nope' } }
        );
        assert.deepStrictEqual(result, { ok: true });
        assert.strictEqual(received[0].method, 'PATCH');
        assert.strictEqual(received[0].headers.authorization, 'Bearer tok');
        assert.strictEqual(received[0].headers.prefer, 'IdType="ImmutableId"');
        assert.strictEqual(received[0].body, '{"isRead":true}');
        assert.strictEqual(logs.length, 1);
        assert.deepStrictEqual(Object.keys(logs[0][1]), ['msg', 'url', 'method', 'provider', 'status', 'clientId', 'reqTime']);
        assert.deepStrictEqual(withoutTime(logs[0][1]), {
            msg: 'External API request completed',
            url: `${baseUrl}/api`,
            method: 'patch',
            provider: 'outlook',
            status: 200,
            clientId: 'test-id',
            reqTime: 'T'
        });
    });

    await t.test('an uppercase GET is not a GET for the payload, which goes in the body', async () => {
        const { outlook } = createClients();
        await outlook.request('tok', `${baseUrl}/api`, 'GET', { q: 1 }).catch(() => {});
        assert.strictEqual(received.length, 0, 'undici refuses a GET with a body');
    });

    await t.test('puts a lowercase get payload in the query string', async () => {
        const { outlook } = createClients();
        await outlook.request('tok', `${baseUrl}/api`, 'get', { $top: 5, skip: null });
        assert.strictEqual(received[0].method, 'GET');
        assert.strictEqual(received[0].url, '/api?%24top=5');
    });

    await t.test('returnBuffer answers the bytes untouched', async () => {
        const { outlook } = createClients();
        handler = (req, res) => {
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            res.end(Buffer.from([0xe4, 0x00, 0xff]));
        };
        const result = await outlook.request('tok', `${baseUrl}/api`, 'get', null, { returnBuffer: true });
        assert.ok(Buffer.isBuffer(result));
        assert.deepStrictEqual([...result], [0xe4, 0x00, 0xff]);
    });

    await t.test('returnText answers the body as text', async () => {
        const { outlook } = createClients();
        respond(200, 'some text', { 'Content-Type': 'text/plain' });
        assert.strictEqual(await outlook.request('tok', `${baseUrl}/api`, 'get', null, { returnText: true }), 'some text');
    });

    await t.test('parses JSON whatever the content type says', async () => {
        const { outlook } = createClients();
        respond(200, '{"v":1}', { 'Content-Type': 'text/plain' });
        assert.deepStrictEqual(await outlook.request('tok', `${baseUrl}/api`, 'get'), { v: 1 });
    });

    await t.test('an empty body is EmptyResponse', async () => {
        const { outlook, logs } = createClients();
        respond(200, '  \n', { 'Content-Type': 'application/json' });
        const err = await rejection(outlook.request('tok', `${baseUrl}/api`, 'post', { a: 1 }));
        assert.deepStrictEqual(Object.keys(err), ['code', 'statusCode', 'oauthRequest']);
        assert.strictEqual(err.message, 'Empty response from API');
        assert.strictEqual(err.code, 'EmptyResponse');
        assert.strictEqual(err.statusCode, 200);
        assert.deepStrictEqual(Object.keys(err.oauthRequest), ['url', 'method', 'provider', 'status', 'clientId', 'reqTime']);
        assert.deepStrictEqual(withoutTime(err.oauthRequest), {
            url: `${baseUrl}/api`,
            method: 'post',
            provider: 'outlook',
            status: 200,
            clientId: 'test-id',
            reqTime: 'T'
        });
        assert.deepStrictEqual(logs.slice(1), [['error', Object.assign({ msg: 'API returned empty response' }, err.oauthRequest)]]);
    });

    await t.test('a body that is not JSON is InvalidJSON', async () => {
        const { outlook, logs } = createClients();
        const body = 'a'.repeat(150) + 'b'.repeat(150);
        respond(202, body, { 'Content-Type': 'application/json' });
        const err = await rejection(outlook.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(Object.keys(err), ['code', 'statusCode', 'oauthRequest']);
        assert.strictEqual(err.message, 'Invalid JSON response from API');
        assert.strictEqual(err.code, 'InvalidJSON');
        assert.strictEqual(err.statusCode, 202);
        const expected = {
            url: `${baseUrl}/api`,
            method: 'get',
            provider: 'outlook',
            status: 202,
            clientId: 'test-id',
            reqTime: 'T',
            responseLength: 300,
            responseStart: body.slice(0, 200),
            responseEnd: body.slice(-200)
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(withoutTime(err.oauthRequest), expected);
        assert.strictEqual(logs[1][0], 'error');
        assert.deepStrictEqual(Object.keys(logs[1][1]), ['msg'].concat(Object.keys(expected), ['err']));
        assert.strictEqual(logs[1][1].msg, 'API returned invalid JSON');
        assert.ok(logs[1][1].err instanceof SyntaxError);
    });

    await t.test('a short body that is not JSON has no responseEnd', async () => {
        const { outlook } = createClients();
        respond(200, 'nope', { 'Content-Type': 'application/json' });
        const err = await rejection(outlook.request('tok', `${baseUrl}/api`, 'get'));
        assert.strictEqual(err.oauthRequest.responseEnd, undefined);
        assert.strictEqual(err.oauthRequest.responseStart, 'nope');
    });

    await t.test('a failure carries the status and Retry-After and raises the flag without recording it', async () => {
        const { outlook, logs, flags } = createClients();
        const body = { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret is provided.' };
        respond(401, JSON.stringify(body), { 'Content-Type': 'application/json', 'Retry-After': '3' });
        const err = await rejection(outlook.request('tok', `${baseUrl}/api`, 'delete'));
        assert.deepStrictEqual(Object.keys(err), ['statusCode', 'oauthRequest', 'retryAfter', 'code']);
        assert.strictEqual(err.message, 'OAuth2 request failed');
        assert.strictEqual(err.statusCode, 401);
        assert.strictEqual(err.retryAfter, 3);
        assert.strictEqual(err.code, 'OUTLOOK_CLIENT_SECRET_INVALID');
        assert.strictEqual(flags[0].code, 'OUTLOOK_CLIENT_SECRET_INVALID');
        const expected = {
            url: `${baseUrl}/api`,
            method: 'delete',
            provider: 'outlook',
            status: 401,
            clientId: 'test-id',
            scopes: outlook.scopes,
            reqTime: 'T',
            retryAfter: 3,
            response: body,
            clientSecret: formatPartialSecretKey(SECRET)
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(withoutTime(err.oauthRequest), expected);
        assert.deepStrictEqual(logs, [['warn', Object.assign({ msg: 'API request failed' }, err.oauthRequest)]]);
    });

    await t.test('a secret error without a client secret stops before the flag', async () => {
        // formatPartialSecretKey() throws on a missing secret and the error handling swallows it
        const { outlook, flags } = createClients({ clientSecret: undefined });
        const body = { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret is provided.' };
        respond(401, JSON.stringify(body), { 'Content-Type': 'application/json' });
        const err = await rejection(outlook.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(err.oauthRequest.response, body);
        assert.strictEqual('clientSecret' in err.oauthRequest, false);
        assert.strictEqual(err.code, undefined);
        assert.deepStrictEqual(flags, []);
    });
});

test('Mail.ru request()', async t => {
    await t.test('sends the token in the query string and the method as given', async () => {
        const { mailRu, logs, flags } = createClients();
        const result = await mailRu.request('tok', `${baseUrl}/api?x=1`, 'post', { a: 1 });
        assert.deepStrictEqual(result, { ok: true });
        assert.strictEqual(received[0].method, 'POST');
        assert.strictEqual(received[0].url, '/api?x=1&access_token=tok');
        assert.strictEqual(received[0].headers.authorization, undefined);
        assert.strictEqual(received[0].headers['content-type'], 'application/json');
        assert.strictEqual(received[0].body, '{"a":1}');
        assert.deepStrictEqual(flags, [undefined]);
        assert.deepStrictEqual(logs, []);
    });

    await t.test('a failure has no status code and is not logged', async () => {
        const { mailRu, logs } = createClients();
        respond(400, JSON.stringify({ error: 'invalid_request' }), { 'Content-Type': 'application/json', 'Retry-After': '5' });
        const err = await rejection(mailRu.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(Object.keys(err), ['oauthRequest']);
        assert.strictEqual(err.message, 'OAuth2 request failed');
        const expected = {
            url: `${baseUrl}/api`,
            method: 'get',
            provider: mailRu.provider,
            status: 400,
            clientId: 'test-id',
            scopes: mailRu.scopes,
            response: { error: 'invalid_request' }
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(err.oauthRequest, expected);
        assert.deepStrictEqual(logs, []);
    });

    await t.test('an empty body is EmptyResponse', async () => {
        const { mailRu } = createClients();
        respond(200, '', { 'Content-Type': 'application/json' });
        const err = await rejection(mailRu.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(Object.keys(err), ['code', 'oauthRequest']);
        assert.strictEqual(err.message, 'Empty response from API');
        assert.strictEqual(err.code, 'EmptyResponse');
        assert.deepStrictEqual(err.oauthRequest, { url: `${baseUrl}/api`, method: 'get', provider: mailRu.provider, status: 200, clientId: 'test-id' });
    });

    await t.test('a body that is not JSON is InvalidJSON', async () => {
        const { mailRu } = createClients();
        respond(200, 'nope', { 'Content-Type': 'application/json' });
        const err = await rejection(mailRu.request('tok', `${baseUrl}/api`, 'get'));
        assert.deepStrictEqual(Object.keys(err), ['code', 'oauthRequest']);
        assert.strictEqual(err.message, 'Invalid JSON response from API');
        assert.strictEqual(err.code, 'InvalidJSON');
        const expected = {
            url: `${baseUrl}/api`,
            method: 'get',
            provider: mailRu.provider,
            status: 200,
            clientId: 'test-id',
            responseLength: 4,
            responseStart: 'nope',
            responseEnd: undefined
        };
        assert.deepStrictEqual(Object.keys(err.oauthRequest), Object.keys(expected));
        assert.deepStrictEqual(err.oauthRequest, expected);
    });
});
