'use strict';

// Losing an instance: a crash, a freeze longer than the heartbeat, a graceful stop. In each case the
// accounts move to the survivors, every message that arrives meanwhile is delivered exactly once,
// and no account is ever held by two instances.

const test = require('node:test');
const assert = require('node:assert').strict;
const { startScenario, waitUntil, sleep, assertDeliveredOnce, IDLE_SETTLE, SESSIONS_PER_OWNER } = require('./helpers');

// Matches the fleet default in test/helpers/instance-fleet.js
const TTL = 4000;

/** Waits until every account is owned by one of the given instances and reported connected */
async function waitRehomed(scenario, ownerIds, timeout = 60000) {
    await waitUntil(
        async () => {
            const owners = await scenario.owners();
            return [...owners.values()].every(owner => ownerIds.includes(owner));
        },
        { timeout, label: `accounts owned by ${ownerIds.join(', ')}` }
    );
    await scenario.waitConnected(scenario.accounts, { timeout });
}

test('a crashed instance: its accounts move to the survivors, nothing is lost or doubled', async t => {
    const scenario = await startScenario({ instances: 3, accounts: 12 });
    t.after(() => scenario.stop());
    const [, victim, ...rest] = scenario.fleet.instances;

    await scenario.waitConnected();
    await sleep(IDLE_SETTLE);

    const owned = [...(await scenario.owners()).entries()].filter(([, owner]) => owner === victim.id).map(([account]) => account);
    assert.ok(owned.length > 0, 'the victim owns something');

    await victim.kill();
    const killedAt = Date.now();

    // Mail keeps arriving while nobody serves the victim's accounts
    const duringOutage = scenario.injectAll(owned, 'during outage');

    await waitRehomed(scenario, ['ee-0', ...rest.map(instance => instance.id)]);
    const rehomedAfter = Date.now() - killedAt;
    t.diagnostic(`accounts re-homed ${rehomedAfter}ms after the crash`);
    assert.ok(rehomedAfter < TTL * 6, `re-homed after ${rehomedAfter}ms`);

    await assertDeliveredOnce(scenario, duringOutage, 90000);

    await sleep(IDLE_SETTLE);
    assert.deepEqual(scenario.overConnected(scenario.accounts, SESSIONS_PER_OWNER), []);
    await assertDeliveredOnce(scenario, scenario.injectAll(scenario.accounts, 'after recovery'));
});

test('a frozen instance: the others take over, and on thaw it fences itself instead of announcing twice', async t => {
    const scenario = await startScenario({ instances: 2, accounts: 10 });
    t.after(() => scenario.stop());
    const [survivor, victim] = scenario.fleet.instances;

    await scenario.waitConnected();
    await sleep(IDLE_SETTLE);

    const owned = [...(await scenario.owners()).entries()].filter(([, owner]) => owner === victim.id).map(([account]) => account);
    assert.ok(owned.length > 0, 'the victim owns something');

    victim.freeze();
    // The frozen process keeps its IMAP sessions open: the farm hears EXISTS for these on both the
    // frozen session and, once it takes over, the survivor's
    const duringFreeze = scenario.injectAll(owned, 'during freeze');

    await waitUntil(
        async () => {
            const owners = await scenario.owners(owned);
            return [...owners.values()].every(owner => owner === survivor.id);
        },
        { timeout: 60000, label: 'survivor takes over' }
    );
    await assertDeliveredOnce(scenario, duringFreeze, 60000);

    victim.thaw();
    await waitUntil(() => victim.logEntries('Lost cluster membership').length > 0, { timeout: 30000, label: 'the thawed instance fences' });

    // Whatever the thawed sessions saw while frozen must not come out as a second copy
    await sleep(5000);
    const { duplicates } = scenario.ledger.reconcile(duringFreeze);
    assert.deepEqual(duplicates, [], 'no second copy from the thawed instance');

    // It rejoins and takes its share back, one session per account throughout
    await waitUntil(
        async () => {
            const owners = await scenario.owners();
            return [...owners.values()].includes(victim.id);
        },
        { timeout: 60000, label: 'the thawed instance takes its share back' }
    );
    await scenario.waitConnected();
    await sleep(IDLE_SETTLE);
    assert.deepEqual(scenario.overConnected(scenario.accounts, SESSIONS_PER_OWNER), []);
    await assertDeliveredOnce(scenario, scenario.injectAll(scenario.accounts, 'after thaw'));
});

test('a graceful stop hands the accounts over before the process exits', async t => {
    const scenario = await startScenario({ instances: 2, accounts: 10 });
    t.after(() => scenario.stop());
    const [survivor, leaving] = scenario.fleet.instances;

    await scenario.waitConnected();
    await sleep(IDLE_SETTLE);

    const stoppedAt = Date.now();
    await leaving.stop();
    t.diagnostic(`SIGTERM took ${Date.now() - stoppedAt}ms`);
    assert.equal(leaving.lastExit.code, 0, 'clean exit');

    // Released on the way out, so the survivor does not wait for the heartbeat to expire
    await waitRehomed(scenario, [survivor.id], TTL * 3);
    const handedOverAfter = Date.now() - stoppedAt;
    t.diagnostic(`accounts handed over ${handedOverAfter}ms after SIGTERM`);
    assert.ok(leaving.logEntries('Left the cluster').length === 1, 'left the cluster');

    await sleep(IDLE_SETTLE);
    assert.deepEqual(scenario.overConnected(scenario.accounts, SESSIONS_PER_OWNER), []);
    await assertDeliveredOnce(scenario, scenario.injectAll());
});
