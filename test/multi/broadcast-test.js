'use strict';

// What the main thread used to fan out to its own workers only now reaches every instance: the
// first admin password locks /admin on all of them, and the live change feed of one instance
// carries the events of accounts another instance serves.

const test = require('node:test');
const assert = require('node:assert').strict;
const { fetch } = require('undici');
const { startScenario, waitUntil } = require('./helpers');
const { ACCESS_TOKEN } = require('../helpers/instance-fleet');

function crumbFrom(res, html) {
    for (const cookie of res.headers.getSetCookie()) {
        const match = /(?:^|;\s*)crumb=([^;]+)/.exec(cookie);
        if (match) {
            return { cookie: `crumb=${match[1]}`, value: decodeURIComponent(match[1]) };
        }
    }
    const match = /name="crumb"[^>]*value="([^"]+)"/.exec(html || '');
    return match ? { cookie: '', value: match[1] } : null;
}

test('the first admin password secures every instance', async t => {
    const scenario = await startScenario({ instances: 2, accounts: 1 });
    t.after(() => scenario.stop());
    const [ee0, ee1] = scenario.fleet.instances;

    let res = await fetch(`${ee1.apiUrl}/admin`, { redirect: 'manual' });
    assert.equal(res.status, 200, 'open before any password is set');
    await res.arrayBuffer();

    res = await fetch(`${ee0.apiUrl}/admin/account/password`, { redirect: 'manual' });
    const html = await res.text();
    const crumb = crumbFrom(res, html);
    assert.ok(crumb, 'the form carries a crumb');

    res = await fetch(`${ee0.apiUrl}/admin/account/password`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: crumb.cookie },
        body: new URLSearchParams({ crumb: crumb.value, password: 'fleet-password-123', password2: 'fleet-password-123' }).toString()
    });
    await res.arrayBuffer();
    assert.equal(res.status, 302, 'password saved');

    const savedAt = Date.now();
    await waitUntil(
        async () => {
            const check = await fetch(`${ee1.apiUrl}/admin`, { redirect: 'manual' });
            await check.arrayBuffer();
            return check.status === 302 && /\/admin\/login/.test(check.headers.get('location') || '');
        },
        { timeout: 15000, interval: 100, label: 'the other instance to ask for a login' }
    );
    t.diagnostic(`the other instance asked for a login ${Date.now() - savedAt}ms after the password was saved`);
    // The broadcast is the fast path; the periodic check alone would take up to five seconds
    assert.ok(Date.now() - savedAt < 3000, 'carried by the broadcast');
});

test('the change feed of one instance carries the events of accounts another serves', async t => {
    const scenario = await startScenario({ instances: 2, accounts: 4 });
    t.after(() => scenario.stop());
    const [ee0, ee1] = scenario.fleet.instances;

    await scenario.waitConnected();
    const owners = await scenario.owners();
    const account = scenario.accounts.find(candidate => owners.get(candidate) === ee1.id);

    const controller = new AbortController();
    t.after(() => controller.abort());
    const feed = await fetch(`${ee0.apiUrl}/v1/changes`, { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` }, signal: controller.signal });
    assert.equal(feed.status, 200);

    const received = [];
    (async () => {
        const decoder = new TextDecoder();
        try {
            for await (const chunk of feed.body) {
                received.push(decoder.decode(chunk));
            }
        } catch (err) {
            // aborted at the end of the test
        }
    })();

    // A reconnect on the owner emits state changes there
    const res = await ee0.request('PUT', `/v1/account/${account}/reconnect`, { reconnect: true });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    await waitUntil(() => received.join('').includes(account), { timeout: 15000, label: `an event for ${account} on ${ee0.id}` });
});
