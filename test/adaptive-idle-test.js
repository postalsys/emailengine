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
    SAME_EVENT_WINDOW
} = require('../lib/email-client/imap/adaptive-idle');
const { IMAP_MAX_IDLE_TIME_MIN } = require('../lib/consts');
const { forAll, gen } = require('./helpers/property');

const SECOND = 1000;
const MINUTE = 60 * SECOND;

const drop = (quietMs, ageMs, idling = true) => ({ type: 'drop', quietMs, ageMs, idling });
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
        const capped = observe(learned, drop(40 * SECOND, 357 * SECOND), now);
        assert.strictEqual(capped.interval, null, 'back to the default');
        assert.strictEqual(capped.cappedUntil, now + CAP_COOLDOWN);
        // and left alone for a day
        const ignored = observe(observe(capped, drop(30 * SECOND, 40 * SECOND), now + MINUTE), drop(30 * SECOND, 40 * SECOND), now + 2 * MINUTE);
        assert.strictEqual(ignored.interval, null);
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
        for (let i = 0; i < RELAX_AFTER; i++) {
            state = observe(state, { type: 'stable', ageMs: STABLE_SESSION }, 2e12 + i);
        }
        assert.strictEqual(state.interval, Math.round(learned * 1.5));
        for (let round = 0; round < 20 && state.interval; round++) {
            for (let i = 0; i < RELAX_AFTER; i++) {
                state = observe(state, { type: 'stable', ageMs: STABLE_SESSION }, 3e12 + round * 10 + i);
            }
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
    await t.test('a long session is a stable one', () => {
        assert.deepStrictEqual(observationFor({ connectedAt: now - STABLE_SESSION, lastClientWrite: now, context: {} }, now), {
            type: 'stable',
            ageMs: STABLE_SESSION
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
