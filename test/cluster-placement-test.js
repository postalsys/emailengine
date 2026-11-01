'use strict';

// Placement and the ownership pass plan (lib/cluster/placement.js). Every instance runs the same
// plan against the same Redis view, so the rules here are what keeps an account from being served
// twice or by nobody.

const test = require('node:test');
const assert = require('node:assert').strict;

const { desiredOwner, planPass, placementScore } = require('../lib/cluster/placement');

const accounts = (count, prefix = 'acc') => Array.from({ length: count }, (_, i) => `${prefix}${i}`);

function placementMap(list, candidates) {
    return new Map(list.map(account => [account, desiredOwner(account, candidates)]));
}

function basePlan(overrides) {
    return Object.assign(
        {
            me: 'a',
            accounts: [],
            owners: new Map(),
            live: new Set(['a', 'b']),
            candidates: ['a', 'b'],
            held: new Set(),
            unownedSince: new Map(),
            now: 100000,
            orphanGrace: 10000,
            handoffLimit: 100
        },
        overrides
    );
}

test('desiredOwner()', async t => {
    await t.test('every instance computes the same owner whatever order it lists the candidates in', () => {
        for (const account of accounts(200)) {
            assert.equal(desiredOwner(account, ['a', 'b', 'c']), desiredOwner(account, ['c', 'a', 'b']));
        }
    });

    await t.test('spreads accounts evenly', () => {
        const list = accounts(6000);
        const counts = {};
        for (const owner of placementMap(list, ['a', 'b', 'c']).values()) {
            counts[owner] = (counts[owner] || 0) + 1;
        }
        for (const id of ['a', 'b', 'c']) {
            // within 10% of a third
            assert.ok(Math.abs(counts[id] - 2000) < 200, `${id} got ${counts[id]}`);
        }
    });

    await t.test('adding an instance moves only the accounts that now belong to it', () => {
        const list = accounts(5000);
        const before = placementMap(list, ['a', 'b', 'c', 'd']);
        const after = placementMap(list, ['a', 'b', 'c', 'd', 'e']);
        let moved = 0;
        for (const account of list) {
            if (before.get(account) !== after.get(account)) {
                moved++;
                assert.equal(after.get(account), 'e', 'an account only ever moves to the new instance');
            }
        }
        // about a fifth
        assert.ok(moved > 800 && moved < 1200, `moved ${moved}`);
    });

    await t.test('removing an instance moves only its own accounts', () => {
        const list = accounts(5000);
        const before = placementMap(list, ['a', 'b', 'c']);
        const after = placementMap(list, ['a', 'c']);
        for (const account of list) {
            if (before.get(account) !== 'b') {
                assert.equal(after.get(account), before.get(account));
            }
        }
    });

    await t.test('a single candidate takes everything, none takes nothing', () => {
        assert.equal(desiredOwner('x', ['only']), 'only');
        assert.equal(desiredOwner('x', []), null);
    });

    await t.test('the score depends on both the account and the instance', () => {
        assert.notEqual(placementScore('x', 'a'), placementScore('x', 'b'));
        assert.notEqual(placementScore('x', 'a'), placementScore('y', 'a'));
    });
});

test('planPass()', async t => {
    // Two accounts, one placed on each of a and b
    const mine = accounts(400).find(account => desiredOwner(account, ['a', 'b']) === 'a');
    const theirs = accounts(400).find(account => desiredOwner(account, ['a', 'b']) === 'b');

    await t.test('claims an unowned account placed here, with an empty expected owner', () => {
        const plan = planPass(basePlan({ accounts: [mine] }));
        assert.deepEqual(plan, { claim: [{ account: mine, expected: '' }], release: [], drop: [], deferred: 0 });
    });

    await t.test('claims an account placed here whose owner is dead, expecting that owner', () => {
        const plan = planPass(basePlan({ accounts: [mine], owners: new Map([[mine, 'gone']]) }));
        assert.deepEqual(plan.claim, [{ account: mine, expected: 'gone' }]);
    });

    await t.test('leaves an account placed elsewhere to that instance', () => {
        const unownedSince = new Map();
        const plan = planPass(basePlan({ accounts: [theirs], unownedSince }));
        assert.deepEqual(plan, { claim: [], release: [], drop: [], deferred: 0 });
        assert.equal(unownedSince.get(theirs), 100000, 'starts the grace clock');
    });

    await t.test('takes an account placed elsewhere once nobody claimed it within the grace period', () => {
        const unownedSince = new Map([[theirs, 100000 - 10000]]);
        const plan = planPass(basePlan({ accounts: [theirs], unownedSince }));
        assert.deepEqual(plan.claim, [{ account: theirs, expected: '' }]);
        assert.equal(unownedSince.has(theirs), false);
    });

    await t.test('never claims an account a live instance owns, even one placed here', () => {
        const plan = planPass(basePlan({ accounts: [mine], owners: new Map([[mine, 'b']]) }));
        assert.deepEqual(plan, { claim: [], release: [], drop: [], deferred: 0 });
    });

    await t.test('drops an account it serves that a live instance owns', () => {
        const plan = planPass(basePlan({ accounts: [mine], owners: new Map([[mine, 'b']]), held: new Set([mine]) }));
        assert.deepEqual(plan.drop, [mine]);
    });

    await t.test('drops an account it serves whose owner record was removed', () => {
        const plan = planPass(basePlan({ accounts: [mine], held: new Set([mine]) }));
        assert.deepEqual(plan, { claim: [], release: [], drop: [mine], deferred: 0 });
    });

    await t.test('hands an account over to the instance placement prefers, within the limit', () => {
        const plan = planPass(basePlan({ accounts: [theirs], owners: new Map([[theirs, 'a']]), held: new Set([theirs]) }));
        assert.deepEqual(plan.release, [{ account: theirs, to: 'b' }]);

        const limited = planPass(basePlan({ accounts: [theirs], owners: new Map([[theirs, 'a']]), held: new Set([theirs]), handoffLimit: 0 }));
        assert.deepEqual(limited.release, []);
    });

    await t.test('keeps an account it owns and serves when placement agrees', () => {
        const plan = planPass(basePlan({ accounts: [mine], owners: new Map([[mine, 'a']]), held: new Set([mine]) }));
        assert.deepEqual(plan, { claim: [], release: [], drop: [], deferred: 0 });
    });

    await t.test('claims again an account an earlier run with the same id owned', () => {
        const plan = planPass(basePlan({ accounts: [theirs], owners: new Map([[theirs, 'a']]) }));
        assert.deepEqual(plan.claim, [{ account: theirs, expected: 'a' }]);
    });

    await t.test('does not hand over to an instance that is live but not taking accounts', () => {
        const plan = planPass(
            basePlan({ accounts: [theirs], owners: new Map([[theirs, 'a']]), held: new Set([theirs]), live: new Set(['a', 'b']), candidates: ['a'] })
        );
        assert.deepEqual(plan.release, []);
    });

    await t.test('leaves an unowned account placed on a starting instance for it, until the grace runs out', () => {
        // Placed on c among a, b and c; c is registered but still starting
        const forC = accounts(600).find(account => desiredOwner(account, ['a', 'b', 'c']) === 'c' && desiredOwner(account, ['a', 'b']) === 'a');
        const unownedSince = new Map();
        const waiting = planPass(basePlan({ accounts: [forC], live: new Set(['a', 'b', 'c']), starting: ['c'], unownedSince }));
        assert.deepEqual(waiting.claim, [], 'a cold start does not hand the first ready instance every account');

        const late = planPass(basePlan({ accounts: [forC], live: new Set(['a', 'b', 'c']), starting: ['c'], unownedSince: new Map([[forC, 100000 - 10000]]) }));
        assert.deepEqual(late.claim, [{ account: forC, expected: '' }], 'an instance that never gets ready does not strand its share');
    });

    await t.test('never hands an account to an instance that is still starting', () => {
        const forC = accounts(600).find(account => desiredOwner(account, ['a', 'b', 'c']) === 'c' && desiredOwner(account, ['a', 'b']) === 'a');
        const plan = planPass(
            basePlan({ accounts: [forC], owners: new Map([[forC, 'a']]), held: new Set([forC]), live: new Set(['a', 'b', 'c']), starting: ['c'] })
        );
        assert.deepEqual(plan, { claim: [], release: [], drop: [], deferred: 0 });
    });

    await t.test('an instance that is not taking accounts claims nothing', () => {
        const plan = planPass(basePlan({ accounts: [mine, theirs], candidates: ['b'] }));
        assert.deepEqual(plan.claim, []);
    });

    await t.test('claims no more than the claim limit, and counts the rest as deferred', () => {
        const list = accounts(400).filter(account => desiredOwner(account, ['a', 'b']) === 'a');
        const owners = new Map(list.map(account => [account, 'gone']));
        const plan = planPass(basePlan({ accounts: list, owners, claimLimit: 5 }));
        assert.equal(plan.claim.length, 5);
        assert.equal(plan.deferred, list.length - 5);
    });

    await t.test('claims exempt accounts and its own earlier records whatever the claim limit', () => {
        const owners = new Map([[theirs, 'a']]);
        const plan = planPass(basePlan({ accounts: [mine, theirs], owners, claimLimit: 0, exempt: new Set([mine]) }));
        assert.deepEqual(plan.claim, [
            { account: mine, expected: '' },
            { account: theirs, expected: 'a' }
        ]);
        assert.equal(plan.deferred, 0);
    });

    await t.test('keeps the grace clock of an orphan the claim limit left over', () => {
        const unownedSince = new Map([[theirs, 100000 - 10000]]);
        const plan = planPass(basePlan({ accounts: [theirs], unownedSince, claimLimit: 0 }));
        assert.deepEqual(plan.claim, []);
        assert.equal(plan.deferred, 1);
        assert.equal(unownedSince.get(theirs), 100000 - 10000, 'claimed at the next pass with room');
    });

    await t.test('spares the accounts of dead owners, but still claims unowned ones', () => {
        const other = accounts(400).filter(account => desiredOwner(account, ['a', 'b']) === 'a')[1];
        const unownedSince = new Map();
        const plan = planPass(
            basePlan({
                accounts: [mine, other, theirs],
                owners: new Map([
                    [other, 'gone'],
                    [theirs, 'gone']
                ]),
                unownedSince,
                spareDeadOwners: true
            })
        );
        assert.deepEqual(plan.claim, [{ account: mine, expected: '' }]);
        assert.equal(plan.deferred, 2);
        assert.equal(unownedSince.has(theirs), false, 'no grace clock runs while sparing');
    });

    await t.test('drops a served account whose record names a dead owner even while sparing', () => {
        const plan = planPass(basePlan({ accounts: [mine], owners: new Map([[mine, 'gone']]), held: new Set([mine]), spareDeadOwners: true }));
        assert.deepEqual(plan.drop, [mine]);
    });

    await t.test('two instances planning from one view never both claim an account', () => {
        const list = accounts(300);
        const owners = new Map(list.map((account, i) => [account, i % 3 === 0 ? 'dead' : null]));
        const claimedBy = new Map();
        for (const me of ['a', 'b']) {
            const plan = planPass(basePlan({ me, accounts: list, owners, live: new Set(['a', 'b']) }));
            for (const { account } of plan.claim) {
                assert.equal(claimedBy.has(account), false, `${account} claimed twice`);
                claimedBy.set(account, me);
            }
        }
        assert.equal(claimedBy.size, list.length, 'every account is claimed by someone');
    });
});
