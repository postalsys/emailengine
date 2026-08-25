'use strict';

// A stand-in for one account's Redis hash.
//
// The auth-failure disable lives in fields the code reads and writes directly - `imap` and the
// AUTH_FAILURE_DISABLED_FIELD marker beside it - rather than through serializeAccountData, so a
// unit test of those paths needs a hash that actually holds values instead of the blanket stubs a
// mock client is otherwise built from. Account.create() and Account.update() both drive them,
// hence the shared helper.
//
// Only the commands those paths issue are modelled; anything else replies 1 and changes nothing.

// Applies one command to the hash and returns the reply a real Redis would give for it.
function apply(hash, writes, command, args) {
    switch (command) {
        case 'hgetall':
            return Object.assign({}, hash);

        case 'hmset': {
            const [, values] = args;
            Object.assign(hash, values || {});
            return 'OK';
        }

        case 'hset':
        case 'hSetExists': {
            const [, field, value] = args;
            hash[field] = value;
            writes.push({ op: 'hset', field, value });
            return 1;
        }

        case 'hsetnx': {
            const [, field, value] = args;
            if (field in hash) {
                return 0;
            }
            hash[field] = value;
            return 1;
        }

        case 'hdel': {
            const [, ...removed] = args;
            for (let field of removed) {
                delete hash[field];
                writes.push({ op: 'hdel', field });
            }
            return 1;
        }

        default:
            return 1;
    }
}

// Commands the account paths queue on a transaction.
const MULTI_COMMANDS = ['hgetall', 'hmset', 'hsetnx', 'hset', 'hSetExists', 'hdel', 'sadd', 'srem'];

// AUTH_FAILURE_DISABLED_FIELD, spelled out rather than imported from lib/consts, so a rename of the
// stored field has to be acknowledged in the test tree too - it is the on-disk contract between the
// safety net that writes it (lib/email-client/base-client.js) and the recovery paths that read it.
module.exports.DISABLED_MARKER = '_authFailureDisabled';
module.exports.DISABLED_AT = '2026-08-01T09:00:00.000Z';

/**
 * @param {Object} [fields] - Initial hash contents, as Redis would hold them (strings)
 * @returns {{hash: Object, writes: Array, commands: Object}} The live hash, an ordered log of the
 *   single-field writes made against it (hmset is applied but not logged - it is the bulk write
 *   every account save makes, and logging it would drown the flag changes the log exists for), and
 *   the client surface to Object.assign onto a mock ioredis
 */
module.exports.createAccountHash = function createAccountHash(fields) {
    const hash = Object.assign({}, fields);
    const writes = [];

    const commands = {
        hget: async (key, field) => (field in hash ? hash[field] : null),
        hmget: async (key, ...fields) => fields.map(field => (field in hash ? hash[field] : null)),
        hset: async (...args) => apply(hash, writes, 'hset', args),
        hdel: async (...args) => apply(hash, writes, 'hdel', args),

        multi() {
            const queued = [];
            const builder = {
                exec: async () => queued.map(({ command, args }) => [null, apply(hash, writes, command, args)])
            };
            for (let command of MULTI_COMMANDS) {
                builder[command] = (...args) => {
                    queued.push({ command, args });
                    return builder;
                };
            }
            return builder;
        }
    };

    return { hash, writes, commands };
};
