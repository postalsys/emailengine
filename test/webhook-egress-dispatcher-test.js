'use strict';

// Proves the egress policy is actually wired into the dispatcher webhook deliveries use, not just
// that a dedicated dispatcher exists. Without this, dropping `connect: { lookup }` from
// buildWebhookDispatcher - or pointing a delivery back at httpAgent.retry - leaves every other
// suite green while the guard is gone.
//
// The policy is read once, when lib/webhook-egress.js is first required, so it has to be set
// before anything pulls in lib/tools.js. `private` is what makes this testable at all: it blocks
// loopback, so a plain localhost server stands in for an internal target without needing control
// over DNS. Node runs each test file in its own process, so this does not leak into other suites.
process.env.EENGINE_WEBHOOK_EGRESS_POLICY = 'private';

const test = require('node:test');
const assert = require('node:assert').strict;
const { fetch: fetchCmd } = require('undici');

const { withCapturingServer } = require('./helpers/capture-http-server');
const { httpAgent } = require('../lib/tools');
const { validateWebhookTarget, WEBHOOK_EGRESS_POLICY } = require('../lib/webhook-egress');

test('webhook dispatcher enforces the egress policy', async t => {
    // lib/tools.js pulls in settings and its Redis client, which keeps the process alive
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('the policy under test is the one that was configured', () => {
        assert.strictEqual(WEBHOOK_EGRESS_POLICY, 'private');
        assert.strictEqual(typeof validateWebhookTarget, 'function', 'a policy other than off must produce a pre-check');
        assert.notStrictEqual(httpAgent.webhook, httpAgent.retry, 'webhook deliveries must not use the unfiltered dispatcher');
        assert.notStrictEqual(httpAgent.webhook, httpAgent.fetch, 'webhook deliveries must not use the unfiltered dispatcher');
    });

    await t.test('refuses a delivery to a blocked destination and reaches nothing', async () => {
        await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
            // Resolves to 127.0.0.1, which `private` blocks. Deliberately NOT an IP literal:
            // net.connect skips the lookup for literals, so a literal would prove nothing here.
            const url = `http://localhost:${new URL(baseUrl).port}/hook`;

            await assert.rejects(
                fetchCmd(url, { method: 'post', body: '{}', dispatcher: httpAgent.webhook }),
                err => (err.cause || err).code === 'EEGRESSBLOCKED',
                'the webhook dispatcher must refuse a blocked destination'
            );
            assert.strictEqual(getCaptured(), null, 'nothing may have reached the server');
        });
    });

    await t.test('the same destination is reachable on the unfiltered dispatcher', async () => {
        // Control: proves the refusal above comes from the policy and not from the URL, the
        // server, or the environment
        await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
            const url = `http://localhost:${new URL(baseUrl).port}/hook`;

            const res = await fetchCmd(url, { method: 'post', body: '{}', dispatcher: httpAgent.retry });
            await res.text();

            assert.strictEqual(res.status, 202);
            assert.ok(getCaptured(), 'the control request must have arrived');
        });
    });

    await t.test('the pre-check refuses the same destination', async () => {
        // The two halves of the guard have to agree; a pre-check that allowed what the dispatcher
        // blocks would mean the policy was resolved differently in the two places
        await assert.rejects(validateWebhookTarget('http://localhost:1234/hook'), err => err.code === 'EEGRESSBLOCKED');
    });
});
