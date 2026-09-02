'use strict';

// fetchWithVettedRedirects (lib/egress-fetch.js): the redirect-following fetch the autodiscovery
// lookups use, where every hop has to pass the egress check before it is taken. Driven against
// throwaway localhost servers so the assertions are about what actually went on the wire: which
// URLs the validator saw, which server was reached, with what method and body.
//
// Pure: the module under test has no Redis dependency, so no teardown is needed.

const test = require('node:test');
const assert = require('node:assert').strict;
const { fetch: fetchCmd } = require('undici');

const { startCapturingServer, stopServer } = require('./helpers/capture-http-server');
const { fetchWithVettedRedirects, MAX_REDIRECTS } = require('../lib/egress-fetch');

// A capturing server that is shut down when the owning test ends
async function serverFor(t, responder) {
    const started = await startCapturingServer(responder);
    t.after(() => stopServer(started.server));
    return started;
}

const redirect = (res, status, location) => {
    res.writeHead(status, { Location: location });
    res.end();
};

const ok = (res, body) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(body);
};

// A validator that records what it was asked about and refuses anything aimed at `blockedBase`
function recordingValidator(blockedBase) {
    const seen = [];
    const validateTarget = async url => {
        seen.push(url);
        if (blockedBase && url.startsWith(blockedBase)) {
            let err = new Error(`Refusing ${url}`);
            err.code = 'EEGRESSBLOCKED';
            throw err;
        }
    };
    return { seen, validateTarget };
}

test('fetchWithVettedRedirects', async t => {
    await t.test('follows a redirect chain and validates every hop, the first request included', async t => {
        let baseUrl;
        ({ baseUrl } = await serverFor(t, (res, req) => {
            if (req.path === '/a') {
                return redirect(res, 302, '/b');
            }
            if (req.path === '/b') {
                return redirect(res, 301, `${baseUrl}/c`);
            }
            ok(res, `arrived at ${req.path}`);
        }));

        const { seen, validateTarget } = recordingValidator();
        const res = await fetchWithVettedRedirects(fetchCmd, `${baseUrl}/a`, { validateTarget });

        assert.equal(res.status, 200);
        assert.equal(await res.text(), 'arrived at /c');
        assert.deepEqual(seen, [`${baseUrl}/a`, `${baseUrl}/b`, `${baseUrl}/c`], 'every hop must be vetted, relative and absolute alike');
    });

    await t.test('refuses a hop the validator rejects and never reaches it', async t => {
        const target = await serverFor(t, res => ok(res, 'internal'));
        const front = await serverFor(t, res => redirect(res, 302, `${target.baseUrl}/secret`));

        const { validateTarget } = recordingValidator(target.baseUrl);

        await assert.rejects(fetchWithVettedRedirects(fetchCmd, `${front.baseUrl}/start`, { validateTarget }), err => err.code === 'EEGRESSBLOCKED');
        assert.equal(target.getRequests().length, 0, 'the blocked destination must not see a request');
        assert.equal(front.getRequests().length, 1);
    });

    await t.test('gives up after the hop budget', async t => {
        const { baseUrl, getRequests } = await serverFor(t, res => redirect(res, 302, '/loop'));

        await assert.rejects(fetchWithVettedRedirects(fetchCmd, `${baseUrl}/loop`), err => err.code === 'EMAXREDIRECTS');
        // the initial request plus one per allowed hop
        assert.equal(getRequests().length, MAX_REDIRECTS + 1);
    });

    await t.test('a 303 turns a POST into a bodyless GET, like fetch() would', async t => {
        const { baseUrl, getRequests } = await serverFor(t, (res, req) => (req.path === '/submit' ? redirect(res, 303, '/result') : ok(res, 'result')));

        const res = await fetchWithVettedRedirects(fetchCmd, `${baseUrl}/submit`, {
            method: 'post',
            headers: { 'Content-Type': 'application/xml', 'User-Agent': 'test' },
            body: '<xml/>'
        });
        assert.equal(res.status, 200);
        await res.text();

        const [first, second] = getRequests();
        assert.equal(first.method, 'POST');
        assert.equal(first.body.toString(), '<xml/>');
        assert.equal(second.method, 'GET');
        assert.equal(second.body.toString(), '');
        assert.equal(second.headers['content-type'], undefined, 'the body headers go with the body');
        assert.equal(second.headers['user-agent'], 'test', 'other headers survive the switch');
    });

    await t.test('a 307 replays the POST with its body', async t => {
        const { baseUrl, getRequests } = await serverFor(t, (res, req) => (req.path === '/submit' ? redirect(res, 307, '/again') : ok(res, 'again')));

        const res = await fetchWithVettedRedirects(fetchCmd, `${baseUrl}/submit`, {
            method: 'post',
            headers: { 'Content-Type': 'application/xml' },
            body: '<xml/>'
        });
        await res.text();

        const second = getRequests()[1];
        assert.equal(second.method, 'POST');
        assert.equal(second.body.toString(), '<xml/>');
        assert.equal(second.headers['content-type'], 'application/xml');
    });

    await t.test('refuses a redirect to a scheme that is not http or https', async t => {
        const { baseUrl } = await serverFor(t, res => redirect(res, 302, 'ftp://files.example.com/config.xml'));

        await assert.rejects(fetchWithVettedRedirects(fetchCmd, `${baseUrl}/x`), err => err.code === 'EREDIRECTSCHEME');
    });

    await t.test('returns a 3xx that names no Location as it is', async t => {
        const { baseUrl } = await serverFor(t, res => {
            res.writeHead(304);
            res.end();
        });

        const res = await fetchWithVettedRedirects(fetchCmd, `${baseUrl}/x`);
        assert.equal(res.status, 304);
    });

    await t.test('works without a validator, for the policy-off case', async t => {
        const { baseUrl } = await serverFor(t, (res, req) => (req.path === '/a' ? redirect(res, 302, '/b') : ok(res, 'b')));

        const res = await fetchWithVettedRedirects(fetchCmd, `${baseUrl}/a`);
        assert.equal(await res.text(), 'b');
    });
});
