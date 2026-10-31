'use strict';

// Every account has exactly one live owner, whatever the fleet does: start, scale up, lose an
// instance to a crash or a freeze. The farm reports IMAP sessions per user, which is the direct
// detector for two instances holding one account, and the ledger reports every webhook, which is
// what a customer sees when that happens.

const test = require('node:test');
const assert = require('node:assert').strict;
const { startScenario, sleep, assertDeliveredOnce, IDLE_SETTLE, SESSIONS_PER_OWNER } = require('./helpers');

test('an instance started after the accounts exist does not connect them a second time', async t => {
    const scenario = await startScenario({ instances: 1, accounts: 8 });
    t.after(() => scenario.stop());

    await scenario.waitConnected();

    // Scale up: the new instance boots into a fleet that already serves every account
    const second = scenario.fleet.add();
    await second.start();
    await second.waitReady();

    await sleep(IDLE_SETTLE);

    assert.deepEqual(scenario.overConnected(scenario.accounts, SESSIONS_PER_OWNER), [], 'one IMAP session per account');

    await assertDeliveredOnce(scenario, scenario.injectAll());
});
