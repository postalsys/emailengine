'use strict';

// Drives SyncOperations.runFullSync() and runFastSync() against the real test Redis (the Lua scripts
// behind the message index are part of what is tested) and a scripted IMAP server. Every run gets
// keys of its own, so harnesses can run side by side and next to other test files.
//
// The server is a list of messages in UID order, its sequence numbers are the positions in that
// list. A message marked `partial` is answered without UID and FLAGS, the way some servers answer a
// FETCH for a message they are about to expunge.

const crypto = require('crypto');

const { redis } = require('../../lib/db');
const { Mailbox } = require('../../lib/email-client/imap/mailbox');
const { SyncOperations } = require('../../lib/email-client/imap/sync-operations');

const silentLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {}, child: () => silentLogger };

/**
 * Counts the Redis round trips a run makes: a command sent on its own is one, a pipeline or a
 * transaction is one however many commands it carries
 * @param {Object} client - ioredis client
 * @returns {{ client: Object, roundTrips: Function, reset: Function }}
 */
function countingRedis(client) {
    let trips = 0;
    const wrapBatch = batch =>
        new Proxy(batch, {
            get(target, name) {
                const value = target[name];
                if (name === 'exec') {
                    return (...args) => {
                        trips++;
                        return value.apply(target, args);
                    };
                }
                if (typeof value === 'function') {
                    return (...args) => {
                        const result = value.apply(target, args);
                        return result === target ? proxy : result;
                    };
                }
                return value;
            }
        });
    let proxy;
    const counted = new Proxy(client, {
        get(target, name) {
            const value = target[name];
            if (name === 'multi' || name === 'pipeline') {
                return (...args) => {
                    proxy = wrapBatch(value.apply(target, args));
                    return proxy;
                };
            }
            if (typeof value === 'function') {
                return (...args) => {
                    trips++;
                    return value.apply(target, args);
                };
            }
            return value;
        }
    });
    return { client: counted, roundTrips: () => trips, reset: () => (trips = 0) };
}

function parseRange(range) {
    return range.split(',').map(part => {
        const [start, end] = part.split(':');
        return [Number(start), end === undefined ? Number(start) : end === '*' ? Infinity : Number(end)];
    });
}

function createServer(messages) {
    return {
        messages,
        async *fetch(range, fields, opts) {
            const ranges = parseRange(range);
            for (let i = 0; i < this.messages.length; i++) {
                const message = this.messages[i];
                const seq = i + 1;
                const key = opts && opts.uid ? message.uid : seq;
                if (!ranges.some(([start, end]) => key >= start && key <= end)) {
                    continue;
                }
                if (message.partial) {
                    yield { seq, modseq: BigInt(message.modseq || 1) };
                    continue;
                }
                yield {
                    seq,
                    uid: message.uid,
                    flags: new Set(message.flags || []),
                    modseq: BigInt(message.modseq || 1),
                    emailId: message.emailId,
                    internalDate: new Date(Date.UTC(2026, 0, 1) + message.uid * 1000)
                };
            }
        },
        async search() {
            return this.messages.map(message => message.uid);
        }
    };
}

/**
 * @param {Object} opts
 * @param {Object[]} opts.server - Server messages, { uid, flags, partial }
 * @param {Object[]} [opts.stored] - Messages already in the index, { uid, flags }
 * @param {Object} [opts.storedStatus] - What getStoredStatus() answers (fast sync)
 * @param {Object} [opts.redisClient] - Client to use instead of the shared one, e.g. a counting one
 */
async function createSyncHarness({ server, stored = [], storedStatus = {}, redisClient = redis }) {
    const id = crypto.randomBytes(6).toString('hex');
    const keys = { messages: `sync-test:${id}:z`, notifications: `sync-test:${id}:n`, mailbox: `sync-test:${id}:h`, account: `sync-test:${id}:a` };

    const events = { deleted: [], changed: [] };
    const imapServer = createServer(server);

    const mailbox = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        logger: silentLogger,
        listingEntry: { path: 'INBOX' },
        getMessagesKey: () => keys.messages,
        getNotificationsKey: () => keys.notifications,
        getMailboxKey: () => keys.mailbox,
        getMailboxLock: async () => ({ release() {} }),
        getMailboxStatus: () => ({
            path: 'INBOX',
            messages: imapServer.messages.length,
            uidValidity: 1n,
            uidNext: (imapServer.messages.at(-1)?.uid || 0) + 1
        }),
        getStoredStatus: async () => Object.assign({ hasStoredState: true }, storedStatus),
        updateStoredStatus: async () => {},
        publishSyncedEvents: async () => {},
        processDeleted: async entry => events.deleted.push(entry.uid),
        processChanges: async (messageData, changes) => events.changed.push({ uid: messageData.uid, changes })
    });

    mailbox.connection = {
        redis: redisClient,
        imapClient: Object.assign(imapServer, { usable: true, mailbox: { path: 'INBOX' } }),
        getAccountKey: () => keys.account,
        notifyFrom: false
    };

    // the index is built through the same code the sync writes it with
    const seed = Object.assign(Object.create(Mailbox.prototype), { connection: { redis }, getMessagesKey: () => keys.messages });
    for (const message of stored) {
        await seed.entryListSet({ uid: message.uid, flags: new Set(message.flags || []), modseq: BigInt(message.modseq || 1) });
    }
    await redis.hset(keys.mailbox, 'messages', String(stored.length));

    const sync = new SyncOperations(mailbox);

    return {
        sync,
        mailbox,
        events,
        keys,
        async indexedUids() {
            const members = await redis.zrange(keys.messages, 0, -1, 'WITHSCORES');
            return members.filter((value, i) => i % 2 === 1).map(Number);
        },
        async queuedUids() {
            const members = await redis.zrange(keys.notifications, 0, -1, 'WITHSCORES');
            return members.filter((value, i) => i % 2 === 1).map(Number);
        },
        async cleanup() {
            await redis.del(...Object.values(keys));
        }
    };
}

module.exports = { createSyncHarness, countingRedis, silentLogger };
