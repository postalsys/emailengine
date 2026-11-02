'use strict';

// Redis refusing writes for a while, the way a Redis at maxmemory does: every instance's Redis goes
// through a proxy that answers a share of the commands a full Redis refuses (the ones that add
// data, and every script) with OOM, while mail keeps arriving. A cut connection would not test this,
// since ioredis sends a command again once it has reconnected; an error reply is how Redis trouble
// reaches the code. Every message still has to be announced exactly once, and no thread of any
// instance may die of an error nobody handled.
//
// The chaos runs (npm run test:chaos) do the same at a larger scale and with harsher faults; this
// is the version that runs on every push.

const test = require('node:test');
const assert = require('node:assert').strict;
const { startScenario, waitUntil, sleep, assertDeliveredOnce, IDLE_SETTLE } = require('./helpers');
const { REDIS_URL } = require('../helpers/instance-fleet');
const { startLatencyProxy } = require('../helpers/latency-proxy');
// Seeded, so a failure can be replayed with the same faults
const { createRandom } = require('../helpers/property');

test('Redis refusing writes for a while (OOM): every message is still announced exactly once', async t => {
    const proxies = [];
    const scenario = await startScenario({
        instances: 2,
        accounts: 8,
        fleet: {
            prepare: async fleet => {
                for (const instance of fleet.instances) {
                    const target = new URL(REDIS_URL);
                    const proxy = await startLatencyProxy({ port: Number(target.port) || 6379, resp: true });
                    proxies.push(proxy);
                    target.port = String(proxy.port);
                    instance.redisUrl = target.toString();
                }
            }
        }
    });
    t.after(async () => {
        await scenario.stop();
        for (const proxy of proxies) {
            await proxy.stop().catch(() => false);
        }
    });

    await scenario.waitConnected();
    await sleep(IDLE_SETTLE);

    const random = createRandom(Number(process.env.EE_FAULT_SEED) || 11);
    for (const proxy of proxies) {
        proxy.setFaults({ rate: 0.2, random });
    }
    const injections = [];
    for (let round = 0; round < 10; round++) {
        injections.push(...scenario.injectAll(scenario.accounts, `oom ${round}`));
        await sleep(1000);
    }
    let injected = 0;
    for (const proxy of proxies) {
        injected += proxy.setFaults({ rate: 0 });
    }
    t.diagnostic(`${injected} Redis commands refused with OOM while ${injections.length} messages arrived`);
    assert.ok(injected > 0, 'some commands were refused');

    // A sync that Redis refused runs again after a backoff of up to a minute
    await assertDeliveredOnce(scenario, injections, 150000);

    for (const instance of scenario.fleet.instances) {
        const fatal = [...instance.logEntries('uncaughtException'), ...instance.logEntries('unhandledRejection')];
        assert.deepEqual(
            fatal.map(entry => entry.err && entry.err.message),
            [],
            `no thread of ${instance.id} died of an unhandled error`
        );
    }

    // The fleet is whole afterwards: every account owned and connected
    await waitUntil(async () => [...(await scenario.owners()).values()].every(Boolean), { timeout: 60000, label: 'every account owned' });
    await scenario.waitConnected();
});
