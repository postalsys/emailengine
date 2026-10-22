'use strict';

// lib/email-client/imap/adaptive-idle.js: learning the IDLE restart interval of a server from the
// idle sessions it drops. The two servers from the support case that asked for it are the
// scenarios: TransIP drops a session 30 seconds after the client last wrote, Vimexx ends every
// session after about six minutes whatever the client does.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    observe,
    observationFor,
    initialState,
    LEARN_CEILING,
    STABLE_SESSION,
    RELAX_AFTER,
    CAP_COOLDOWN,
    PENDING_WINDOW,
    SAME_EVENT_WINDOW
} = require('../lib/email-client/imap/adaptive-idle');
const { IMAP_MAX_IDLE_TIME_MIN } = require('../lib/consts');
const { forAll, gen } = require('./helpers/property');

const SECOND = 1000;
const MINUTE = 60 * SECOND;

const drop = (quietMs, ageMs, idling = true, ranInterval = null) => ({ type: 'drop', quietMs, ageMs, idling, ranInterval });
// RELAX_AFTER long sessions in a row, each run on `ranInterval` when given
const stableRun = (state, at, ranInterval = null) => {
    for (let i = 0; i < RELAX_AFTER; i++) {
        state = observe(state, { type: 'stable', ageMs: STABLE_SESSION, ranInterval }, at + i);
    }
    return state;
};
const run = (observations, start = 1e12) => observations.reduce((state, o, i) => observe(state, o, start + i * MINUTE), null);

test('adaptive IDLE interval', async t => {
    await t.test('TransIP: idle sessions dropped 30 s after the last write teach an 18 s restart', () => {
        const state = run([drop(30 * SECOND, 45 * SECOND), drop(31 * SECOND, 46 * SECOND)]);
        assert.strictEqual(state.interval, 18 * SECOND);
    });

    await t.test('one drop is not enough, and two different quiet times are not the same timer', () => {
        assert.strictEqual(run([drop(30 * SECOND, 45 * SECOND)]).interval, null);
        assert.strictEqual(run([drop(30 * SECOND, 45 * SECOND), drop(4 * MINUTE, 5 * MINUTE)]).interval, null);
    });

    await t.test('Vimexx: sessions that still end at the same age after learning are a session cap', () => {
        // IDLE restarted every 180 s, the session dies at about 355 s either way
        const learned = run([drop(175 * SECOND, 355 * SECOND), drop(172 * SECOND, 352 * SECOND)]);
        assert.strictEqual(learned.interval, Math.floor(172 * SECOND * 0.6));
        const now = 1e12 + 10 * MINUTE;
        // sessions that ran the learned interval and still ended at the same age: one is not enough
        const once = observe(learned, drop(40 * SECOND, 357 * SECOND, true, learned.interval), now);
        assert.strictEqual(once.interval, learned.interval, 'a single session may be a coincidence');
        const later = now + 6 * MINUTE;
        const capped = observe(once, drop(41 * SECOND, 356 * SECOND, true, learned.interval), later);
        assert.strictEqual(capped.interval, null, 'back to the default');
        assert.strictEqual(capped.cappedUntil, later + CAP_COOLDOWN);
        // and left alone for a day
        const ignored = observe(observe(capped, drop(30 * SECOND, 40 * SECOND), later + MINUTE), drop(30 * SECOND, 40 * SECOND), later + 2 * MINUTE);
        assert.strictEqual(ignored.interval, null);
    });

    await t.test('a session that never ran the learned interval is no evidence of a cap', () => {
        // Regression: a second account on the host, still on the session it opened before the
        // interval was learned, ended at the same age and wiped the interval for a day
        const learned = run([drop(30 * SECOND, 46 * SECOND), drop(30 * SECOND, 46 * SECOND)]);
        assert.strictEqual(learned.interval, 18 * SECOND);
        const now = 1e12 + 10 * MINUTE;
        for (const ranInterval of [null, 60 * SECOND]) {
            // no restarts at all (opened before, or read a cached value), or an account's own longer interval
            const after = observe(learned, drop(30 * SECOND, 46 * SECOND, true, ranInterval), now);
            assert.strictEqual(after.interval, 18 * SECOND, `ran ${ranInterval}`);
            assert.strictEqual(after.cappedUntil, 0);
        }
        // sessions that restarted IDLE more often than learned and still died at that age do count
        const shorter = drop(10 * SECOND, 46 * SECOND, true, 10 * SECOND);
        assert.strictEqual(observe(observe(learned, shorter, now), shorter, now + MINUTE).interval, null);
    });

    await t.test('a relaxed interval the server cuts goes back to the one that held, and relaxing stops there', () => {
        // Regression: relaxing 18 -> 27 -> 40.5 s past TransIP's 30 s, and the first cut session was
        // then read as a session cap, which dropped the interval for a day
        let state = run([drop(30 * SECOND, 46 * SECOND), drop(30 * SECOND, 46 * SECOND)]);
        state = stableRun(stableRun(state, 2e12), 3e12);
        assert.strictEqual(state.interval, 40.5 * SECOND);

        state = observe(state, drop(30 * SECOND, 46 * SECOND, true, 40.5 * SECOND), 4e12);
        assert.strictEqual(state.interval, 40.5 * SECOND, 'one cut session may be a coincidence');
        state = observe(state, drop(30 * SECOND, 46 * SECOND, true, 40.5 * SECOND), 4e12 + MINUTE);
        assert.strictEqual(state.interval, 27 * SECOND, 'back to the interval that held');
        assert.strictEqual(state.cappedUntil, 0, 'not taken for a session cap');

        state = stableRun(stableRun(state, 5e12), 6e12);
        assert.strictEqual(state.interval, 27 * SECOND, 'never relaxed to the cut interval again');
    });

    await t.test('a relaxed interval a long session ran is proven, and a later drop no longer reverts it', () => {
        let state = stableRun(run([drop(30 * SECOND, 46 * SECOND), drop(30 * SECOND, 46 * SECOND)]), 2e12, 18 * SECOND);
        assert.strictEqual(state.interval, 27 * SECOND);
        // a session opened before the relax, still on 18 s, proves nothing about 27 s
        state = observe(state, { type: 'stable', ageMs: STABLE_SESSION, ranInterval: 18 * SECOND }, 2e12 + 10);
        assert.strictEqual(state.relaxedFrom, 18 * SECOND);
        state = observe(state, { type: 'stable', ageMs: STABLE_SESSION, ranInterval: 27 * SECOND }, 2e12 + 20);
        assert.strictEqual(state.relaxedFrom, null);
        const cut = drop(20 * SECOND, 50 * MINUTE, true, 27 * SECOND);
        assert.strictEqual(observe(observe(state, cut, 3e12), cut, 3e12 + MINUTE).interval, 27 * SECOND);
    });

    await t.test('blips on a relaxed interval do not send it back or set a ceiling', () => {
        // Regression: any drop on the relaxed interval counted, so two blips within an hour reverted it
        // and left a permanent ceiling. A blip comes after IDLE was restarted on the interval; only a
        // cut before the first restart says the interval is too long
        let state = stableRun(run([drop(30 * SECOND, 46 * SECOND), drop(30 * SECOND, 46 * SECOND)]), 2e12);
        assert.strictEqual(state.interval, 27 * SECOND);
        const blip = drop(20 * SECOND, 20 * MINUTE, true, 27 * SECOND);
        state = observe(observe(state, blip, 3e12), blip, 3e12 + 5 * MINUTE);
        assert.strictEqual(state.interval, 27 * SECOND);
        assert.strictEqual(state.relaxLimit, null);
    });

    await t.test('network blips on a working interval do not walk it down', () => {
        // Regression: a connection running an interval is never quiet for longer than it, so any drop
        // looks like a shorter timer, and two blips with a similar quiet time lowered it
        const learned = run([drop(30 * SECOND, 46 * SECOND), drop(30 * SECOND, 46 * SECOND)]);
        const blips = [drop(8 * SECOND, 10 * MINUTE, true, 18 * SECOND), drop(9 * SECOND, 15 * MINUTE, true, 18 * SECOND)];
        // with nothing learned, two similar drops are enough (0.6 of 8 s, held at the floor)
        assert.strictEqual(run(blips, 2e12).interval, IMAP_MAX_IDLE_TIME_MIN);
        let state = learned;
        blips.forEach((blip, i) => {
            state = observe(state, blip, 2e12 + i * 5 * MINUTE);
        });
        assert.strictEqual(state.interval, 18 * SECOND, 'two blips do not lower a learned interval');
        // nor do three that agree only loosely: blips land anywhere up to the interval
        [12, 14, 13].forEach((quiet, i) => {
            state = observe(state, drop(quiet * SECOND, 10 * MINUTE, true, 18 * SECOND), 2e12 + (20 + i * 5) * MINUTE);
        });
        assert.strictEqual(state.interval, 18 * SECOND);
        // a timer that really got shorter cuts every session at the same quiet time, and three of them lower it
        // (cut 16 s into IDLE, before the first 18 s restart, at about the age the interval was learned at:
        // not a session cap, the session never restarted IDLE)
        [16, 16, 16.5].forEach((quiet, i) => {
            state = observe(state, drop(quiet * SECOND, (16 + quiet) * SECOND, true, 18 * SECOND), 2e12 + (40 + i) * MINUTE);
        });
        assert.strictEqual(state.interval, Math.max(IMAP_MAX_IDLE_TIME_MIN, Math.floor(16 * SECOND * 0.6)));
    });

    await t.test('a cut before the first IDLE restart is a shorter timer, never a session cap', () => {
        // the session never restarted IDLE: the last write was the IDLE that started 16 s in, so the
        // server's quiet timer is below the interval, whatever age the session ended at
        const learned = Object.assign(initialState(), { interval: 18 * SECOND, ageWhenLearned: 32 * SECOND });
        const cut = drop(16 * SECOND, 32 * SECOND, true, 18 * SECOND);
        const after = observe(observe(learned, cut, 1e12), cut, 1e12 + MINUTE);
        assert.strictEqual(after.cappedUntil, 0);
        assert.strictEqual(after.interval, 18 * SECOND, 'two drops are not yet enough to lower');
    });

    await t.test('cap evidence goes stale after an hour too', () => {
        const learned = run([drop(175 * SECOND, 355 * SECOND), drop(172 * SECOND, 352 * SECOND)]);
        const capLike = drop(40 * SECOND, 357 * SECOND, true, learned.interval);
        const once = observe(learned, capLike, 2e12);
        // a cap-looking session last week and one today are not a session cap
        assert.strictEqual(observe(once, capLike, 2e12 + PENDING_WINDOW).interval, learned.interval);
        assert.strictEqual(observe(once, capLike, 2e12 + 6 * MINUTE).interval, null);
    });

    await t.test('a run of drops goes stale after an hour', () => {
        const first = observe(null, drop(30 * SECOND, 46 * SECOND), 1e12);
        assert.strictEqual(observe(first, drop(30 * SECOND, 46 * SECOND), 1e12 + PENDING_WINDOW).interval, null, 'a drop an hour old confirms nothing');
        assert.strictEqual(observe(first, drop(30 * SECOND, 46 * SECOND), 1e12 + PENDING_WINDOW - 1).interval, 18 * SECOND);
    });

    await t.test('drops seen at the same moment by several accounts of a host are one event', () => {
        const now = 1e12;
        const first = observe(null, drop(30 * SECOND, 45 * SECOND), now);
        const sameEvent = observe(first, drop(30 * SECOND, 45 * SECOND), now + SAME_EVENT_WINDOW - 1);
        assert.strictEqual(sameEvent.interval, null, 'a second account seeing the same cut confirms nothing');
        const later = observe(sameEvent, drop(30 * SECOND, 45 * SECOND), now + MINUTE);
        assert.strictEqual(later.interval, 18 * SECOND);
    });

    await t.test('only a session dropped while idling counts', () => {
        assert.strictEqual(run([drop(30 * SECOND, 45 * SECOND, false), drop(30 * SECOND, 45 * SECOND, false)]).interval, null);
    });

    await t.test('a drop after as much quiet as a server may allow teaches nothing', () => {
        assert.strictEqual(run([drop(LEARN_CEILING, LEARN_CEILING + MINUTE), drop(LEARN_CEILING + SECOND, LEARN_CEILING + MINUTE)]).interval, null);
    });

    await t.test('never below the shortest interval an account may set', () => {
        assert.strictEqual(run([drop(5 * SECOND, 6 * SECOND), drop(5 * SECOND, 6 * SECOND)]).interval, IMAP_MAX_IDLE_TIME_MIN);
    });

    await t.test('relaxes after a run of long stable sessions, and forgets once back near the default', () => {
        let state = run([drop(30 * SECOND, 45 * SECOND), drop(30 * SECOND, 45 * SECOND)]);
        const learned = state.interval;
        state = stableRun(state, 2e12);
        assert.strictEqual(state.interval, Math.round(learned * 1.5));
        for (let round = 0; round < 20 && state.interval; round++) {
            state = stableRun(state, 3e12 + round * 10);
        }
        assert.strictEqual(state.interval, null);
    });

    await t.test('a short-lived clean close is not a stable session', () => {
        const state = run([drop(30 * SECOND, 45 * SECOND), drop(30 * SECOND, 45 * SECOND)]);
        assert.deepStrictEqual(observe(state, { type: 'stable', ageMs: MINUTE }, 2e12), Object.assign(initialState(), state));
    });

    await t.test('property: the interval stays inside the bounds and a drop never lengthens it', () => {
        const observation = gen.oneOf([
            random => drop(gen.integer(1, 40 * MINUTE)(random), gen.integer(1, 40 * MINUTE)(random), gen.boolean()(random)),
            random => ({ type: 'stable', ageMs: gen.integer(1, 2 * STABLE_SESSION)(random) })
        ]);
        forAll(
            gen.array(random => observation(random)(random), 1, 40),
            observations => {
                let state = null;
                observations.forEach((o, i) => {
                    const before = state && state.interval;
                    state = observe(state, o, 1e12 + i * MINUTE);
                    if (state.interval !== null) {
                        assert.ok(state.interval >= IMAP_MAX_IDLE_TIME_MIN && state.interval < LEARN_CEILING, `interval ${state.interval}`);
                    }
                    if (o.type === 'drop' && before && state.interval) {
                        assert.ok(state.interval <= before, 'a drop only shortens');
                    }
                });
            }
        );
    });
});

test('observationFor()', async t => {
    const now = 1e12;
    await t.test('a dropped idle session', () => {
        assert.deepStrictEqual(
            observationFor({ connectedAt: now - 45 * SECOND, lastClientWrite: now - 30 * SECOND, idlingAtClose: true, context: {} }, now),
            drop(30 * SECOND, 45 * SECOND)
        );
    });
    await t.test('a connection the application closed says nothing, whatever it was doing', () => {
        // ImapFlow's closedByClient: also the closes EmailEngine makes in order to reconnect (an empty
        // listing, a stale main view), which can not be marked disabled
        const client = { connectedAt: now - 45 * SECOND, lastClientWrite: now - 30 * SECOND, idlingAtClose: true, closedByClient: true, context: {} };
        assert.strictEqual(observationFor(client, now), null);
        assert.strictEqual(observationFor(Object.assign(client, { connectedAt: now - STABLE_SESSION }), now), null);
    });
    await t.test('a drop carries the IDLE restart interval the connection ran with', () => {
        const client = { connectedAt: now - 45 * SECOND, lastClientWrite: now - 30 * SECOND, idlingAtClose: true, context: {} };
        assert.strictEqual(observationFor(Object.assign({}, client, { maxIdleTime: 18 * SECOND }), now).ranInterval, 18 * SECOND);
        // ImapFlow keeps false for no restarts
        assert.strictEqual(observationFor(Object.assign({}, client, { maxIdleTime: false }), now).ranInterval, null);
    });
    await t.test('a long session is a stable one', () => {
        assert.deepStrictEqual(observationFor({ connectedAt: now - STABLE_SESSION, lastClientWrite: now, maxIdleTime: 18 * SECOND, context: {} }, now), {
            type: 'stable',
            ageMs: STABLE_SESSION,
            ranInterval: 18 * SECOND
        });
    });
    await t.test('a replaced client, or one that never connected, says nothing', () => {
        assert.strictEqual(observationFor({ connectedAt: now - MINUTE, lastClientWrite: now, context: { disabled: true } }, now), null);
        assert.strictEqual(observationFor({ connectedAt: null, context: {} }, now), null);
    });
});

test('applyIdleSettings() with a learned interval', async t => {
    const { applyIdleSettings } = require('../lib/email-client/imap/idle-settings');
    await t.test('applies a learned interval', () => {
        const config = { host: 'imap.transip.email' };
        applyIdleSettings(config, {}, 18 * SECOND);
        assert.strictEqual(config.maxIdleTime, 18 * SECOND);
    });
    await t.test('never lengthens a provider default', () => {
        const config = { host: 'imap.rambler.ru' };
        applyIdleSettings(config, {}, 90 * SECOND);
        assert.strictEqual(config.maxIdleTime, 55 * SECOND);
        applyIdleSettings(config, {}, 20 * SECOND);
        assert.strictEqual(config.maxIdleTime, 20 * SECOND);
    });
    await t.test('the account setting wins', () => {
        const config = { host: 'imap.transip.email' };
        applyIdleSettings(config, { maxIdleTime: 25 * SECOND }, 18 * SECOND);
        assert.strictEqual(config.maxIdleTime, 25 * SECOND);
    });
});
