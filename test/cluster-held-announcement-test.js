'use strict';

// An instance that may have lost an account (its heartbeat lapsed and another instance took the
// account over, or nothing was decided before the lease wait ran out) does not announce events for
// it. A new message is announced off a durable queue, so the entry has to stay queued for the
// instance that owns the account: removing it as if it had gone out lost the message for good.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the modules under test are required: they pull in lib/db
require('./helpers/mock-db').installDbMock();

const { BaseClient } = require('../lib/email-client/base-client');
const { keepsArrivalQueued } = require('../lib/email-client/imap/mailbox');
const { createLeaseBuffer, LeaseView, setWorkerLease, heldAnnouncementError, HELD_ANNOUNCEMENT } = require('../lib/cluster/lease');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

function client(overrides) {
    const delivered = [];
    const ctx = Object.assign(Object.create(BaseClient.prototype), {
        account: 'held',
        logger: createMockLogger(),
        notificationHandler: { notify: async (mailbox, event) => delivered.push(event) }
    });
    return { ctx: Object.assign(ctx, overrides), delivered };
}

test('announcements held back for the owner of the account', async t => {
    t.afterEach(() => setWorkerLease(null));

    await t.test('an owned account announces and says so', async () => {
        const { ctx, delivered } = client();
        assert.equal(await ctx.notify(false, 'messageNew', {}), true);
        assert.deepEqual(delivered, ['messageNew']);
    });

    await t.test('a connection retired as lost holds every event back', async () => {
        const { ctx, delivered } = client({ retired: 'lost' });
        assert.equal(await ctx.notify(false, 'messageNew', {}), false);
        assert.deepEqual(delivered, []);
    });

    await t.test('the outcome of a send is announced even by a connection retired as lost', async () => {
        // Only the instance that sent the message can report it
        const { ctx, delivered } = client({ retired: 'lost' });
        assert.equal(await ctx.notify(false, 'messageSent', {}), true);
        assert.equal(await ctx.notify(false, 'messageDeliveryError', {}), true);
        assert.deepEqual(delivered, ['messageSent', 'messageDeliveryError']);
    });

    await t.test('a new message is not fetched or enriched when it would be held back', async () => {
        const { ctx, delivered } = client({ retired: 'lost' });
        await assert.rejects(ctx.processNew({ id: 'm1' }, {}), err => err.code === HELD_ANNOUNCEMENT);
        assert.deepEqual(delivered, []);
    });

    await t.test('a lease revoked while waiting holds the event back', async () => {
        const buffer = createLeaseBuffer();
        const lease = new LeaseView(buffer);
        lease.suspend();
        setWorkerLease(buffer);
        const { ctx, delivered } = client();
        setTimeout(() => lease.revoke(), 100);
        assert.equal(await ctx.notify(false, 'messageNew', {}), false);
        assert.deepEqual(delivered, []);
    });

    await t.test('a state is announced only once it was recorded', async () => {
        // Outside a worker thread an emitted change cannot be posted anywhere, and says so
        const announced = ctx => ctx.logger.entries.some(entry => entry.msg === 'Failed to post state change to parent');
        const stateClient = (overrides, reply) => {
            const writes = [];
            const { ctx } = client(
                Object.assign(
                    {
                        state: 'disconnected',
                        runIndex: 7,
                        getAccountKey: () => 'iad:held',
                        redis: {
                            accountSetState: async (...args) => {
                                writes.push(args);
                                return reply;
                            }
                        }
                    },
                    overrides
                )
            );
            return { ctx, writes };
        };

        const owned = stateClient({}, [1, '1', 2]);
        await owned.ctx.setStateVal({ announce: true });
        assert.equal(owned.writes.length, 1);
        assert.equal(announced(owned.ctx), true);

        const quiet = stateClient({}, [1, '1', 2]);
        await quiet.ctx.setStateVal();
        assert.equal(announced(quiet.ctx), false, 'announce is opt-in');

        const moved = stateClient({ retired: 'moved' }, [1, '1', 2]);
        await moved.ctx.setStateVal({ announce: true });
        assert.deepEqual(moved.writes, [], 'the next owner records the state');
        assert.equal(announced(moved.ctx), false);

        const taken = stateClient({}, [-1]);
        await taken.ctx.setStateVal({ announce: true });
        assert.equal(announced(taken.ctx), false, 'refused: another instance owns the account');
    });

    await t.test('the IMAP queue keeps an arrival whose announcement was held back', () => {
        assert.equal(heldAnnouncementError().code, HELD_ANNOUNCEMENT);
        assert.equal(keepsArrivalQueued(heldAnnouncementError()), true);
        assert.equal(keepsArrivalQueued(new Error('parse failure')), false);
    });
});
