'use strict';

// The learned IDLE interval end to end, as accounts on one host meet it: the real IMAPClient
// cache (getLearnedIdleInterval) and close recording (recordIdleClose), the store and
// applyIdleSettings(), driven by simulated servers on a fake clock. What is simulated here is only
// the server and the timing of connections: when a session ends for the restart interval it ran,
// and how long the reconnect backoff waits.
//
// Generated: one to four accounts connecting at random offsets, against a server that cuts a
// session after a random quiet time, or one that ends every session at a random age whatever the
// client does. A two-account host is what the first version of the cap rule got wrong: a session
// opened before the interval was learned ended at the learning age and was read as a session cap.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { ImapFlow } = require('imapflow');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { ReconnectBackoff } = require('../lib/email-client/reconnect-backoff');
const { STABLE_CONNECTION_TIME } = require('../lib/consts');
const { applyIdleSettings } = require('../lib/email-client/imap/idle-settings');
const { LEARNED_KEY } = require('../lib/email-client/imap/adaptive-idle-store');
const { createMockLogger } = require('./helpers/mock-logger');
const { forAll, gen } = require('./helpers/property');

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOST = 'imap.example.nl';
// login and SELECT, after which ImapFlow waits its auto-IDLE delay before the first IDLE is written
const SETUP = 1 * SECOND;

// The auto-IDLE delay ImapFlow itself picks for a connection config
const autoIdleDelayFor = config => new ImapFlow({ host: '127.0.0.1', port: 1, auth: { user: 'u', pass: 'p' }, logger: false, ...config }).autoIdleDelay;
// The close backoff a short-lived primary connection reconnects through, as IMAPClient builds it,
// without the jitter
const closeBackoff = () => new ReconnectBackoff({ baseDelay: 2000, maxDelay: 30000, jitter: 0 });

function fakeRedis() {
    const hash = new Map();
    return {
        hash,
        async hget(key, field) {
            assert.strictEqual(key, LEARNED_KEY);
            return hash.get(field) ?? null;
        },
        async hset(key, field, value) {
            hash.set(field, value);
        },
        async hdel(key, field) {
            hash.delete(field);
        }
    };
}

// When a session that ran `maxIdleTime` ends: `{ endsAt, lastWrite }` relative to connecting, or
// endsAt Infinity for one the server keeps
function sessionEnd(server, maxIdleTime, autoIdleDelay) {
    const idleStart = SETUP + autoIdleDelay;
    if (server.quietLimit) {
        if (maxIdleTime && maxIdleTime < server.quietLimit) {
            return { endsAt: Infinity };
        }
        return { endsAt: idleStart + server.quietLimit, lastWrite: idleStart };
    }
    // a session cap: the last write is the last IDLE restart before it
    let lastWrite = idleStart;
    while (maxIdleTime && lastWrite + maxIdleTime < server.sessionCap) {
        lastWrite += maxIdleTime;
    }
    return { endsAt: server.sessionCap, lastWrite };
}

async function simulate(t, { server, offsets, horizon, blips = [] }) {
    let clock = 1.8e12;
    t.mock.timers.enable({ apis: ['Date'], now: clock });
    const setClock = at => {
        clock = at;
        t.mock.timers.setTime(at);
    };
    try {
        const redis = fakeRedis();
        const accounts = offsets.map((offset, i) => {
            const client = Object.assign(Object.create(IMAPClient.prototype), { redis, account: `a${i}`, logger: createMockLogger() });
            return { client, backoff: closeBackoff(), connectAt: clock + offset, session: null };
        });
        const connect = async account => {
            const config = { host: HOST };
            applyIdleSettings(config, {}, await account.client.getLearnedIdleInterval(HOST));
            const autoIdleDelay = autoIdleDelayFor(config);
            const end = sessionEnd(server, config.maxIdleTime, autoIdleDelay);
            account.session = {
                connectedAt: clock,
                ran: config.maxIdleTime,
                endsAt: clock + end.endsAt,
                lastWrite: clock + (end.lastWrite || 0)
            };
            // a network blip the server had nothing to do with, on a session it would have kept: at
            // a random point of the IDLE restart cycle, so its quiet time is anything up to the interval
            const blip = account.session.endsAt === Infinity && blips.shift();
            if (blip) {
                account.session.endsAt = clock + blip.after;
                account.session.lastWrite = account.session.endsAt - Math.floor(blip.phase * (config.maxIdleTime || autoIdleDelay));
            }
            account.connectAt = Infinity;
        };
        const end = 1.8e12 + horizon;
        for (;;) {
            const next = accounts
                .flatMap(account => [
                    { at: account.connectAt, account, connect: true },
                    { at: account.session ? account.session.endsAt : Infinity, account }
                ])
                .sort((a, b) => a.at - b.at)[0];
            if (!(next.at < end)) {
                break;
            }
            setClock(next.at);
            if (next.connect) {
                await connect(next.account);
                continue;
            }
            const { session } = next.account;
            await next.account.client.recordIdleClose({
                options: { host: HOST },
                connectedAt: session.connectedAt,
                lastClientWrite: session.lastWrite,
                idlingAtClose: true,
                maxIdleTime: session.ran || false,
                context: {}
            });
            next.account.session = null;
            // a session that did not prove itself stable goes through the growing close backoff
            const age = clock - session.connectedAt;
            next.account.connectAt = clock + (age >= STABLE_CONNECTION_TIME ? 0 : next.account.backoff.nextDelay());
        }
        const stored = redis.hash.get(HOST);
        return { state: stored ? JSON.parse(stored) : null, accounts, now: clock };
    } finally {
        t.mock.timers.reset();
    }
}

const offsets = gen.array(gen.integer(0, 90 * SECOND), 1, 4);

test('a host that cuts quiet sessions ends with an interval every account runs and survives', async t => {
    await forAll(
        gen.record({ quietLimit: gen.integer(20, 120), offsets }),
        async ({ quietLimit, offsets }) => {
            const server = { quietLimit: quietLimit * SECOND };
            const { state, accounts } = await simulate(t, { server, offsets, horizon: 2 * 3600 * 1000 });
            assert.ok(state && state.interval, 'an interval was learned');
            assert.ok(!(state.cappedUntil > 0), 'never taken for a session cap');
            assert.ok(state.interval < server.quietLimit);
            for (const account of accounts) {
                assert.ok(account.session && account.session.endsAt === Infinity, 'every account ends on a session the server keeps');
                assert.strictEqual(account.session.ran, state.interval);
            }
        },
        { runs: 150 }
    );
});

test('network blips on a working interval never cap the host or lift the interval past its limit', async t => {
    const blip = gen.record({ after: gen.integer(31 * MINUTE, 6 * 3600 * 1000), phase: random => random() });
    await forAll(
        gen.record({ quietLimit: gen.integer(20, 120), offsets, blips: gen.array(blip, 1, 30) }),
        async ({ quietLimit, offsets, blips }) => {
            const server = { quietLimit: quietLimit * SECOND };
            // long enough for blipped sessions over 30 minutes to relax the interval too
            const { state } = await simulate(t, { server, offsets, blips, horizon: 48 * 3600 * 1000 });
            assert.ok(state && state.interval, 'an interval is still learned');
            assert.ok(!(state.cappedUntil > 0), 'never taken for a session cap');
            assert.ok(state.interval < server.quietLimit, `interval ${state.interval} below the limit ${server.quietLimit}`);
        },
        { runs: 100 }
    );
});

test('a host that caps session age is recognised and left alone', async t => {
    await forAll(
        gen.record({ sessionCap: gen.integer(3, 15), offsets }),
        async ({ sessionCap, offsets }) => {
            const server = { sessionCap: sessionCap * MINUTE };
            const { state, accounts, now } = await simulate(t, { server, offsets, horizon: 12 * server.sessionCap });
            assert.ok(state && state.cappedUntil > now, 'recognised as a session cap');
            assert.strictEqual(state.interval, null);
            for (const account of accounts) {
                // back on the default, and nothing learned during the cooldown
                assert.ok(!account.session || !account.session.ran || account.session.connectedAt < now - 2 * server.sessionCap);
            }
        },
        { runs: 150 }
    );
});
