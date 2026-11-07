'use strict';

// Tells long-lived sessions that a credential or account they may depend on has changed, so they
// re-check it now instead of at their next periodic check. The message names what changed only
// as a hint: every subscriber re-checks its own sessions against the stored state, so a lost or
// duplicated message costs at most one periodic interval, never a wrong decision.
//
// Redis pub/sub rather than a worker message, because a credential can be revoked from a process
// that has no worker channel at all (the `emailengine tokens delete` command).

const logger = require('./logger');
const { redis, watchRedisReconnect } = require('./db');
const { REDIS_PREFIX } = require('./consts');

const REVOCATION_CHANNEL = `${REDIS_PREFIX}ee:revocations`;

let subscriber = null;
const handlers = new Set();

/**
 * Announces that a credential or account changed in a way that may end open sessions.
 * Never throws: the periodic re-check is the fallback for a message that is not delivered.
 *
 * @param {Object} detail - What changed, e.g. `{ type: 'token' }` or `{ type: 'account', account }`
 * @returns {Promise<void>}
 */
async function publishRevocation(detail) {
    try {
        await redis.publish(REVOCATION_CHANNEL, JSON.stringify(detail));
    } catch (err) {
        logger.warn({ msg: 'Failed to announce a credential change', detail, err });
    }
}

function dispatch(message) {
    let detail = {};
    try {
        detail = JSON.parse(message) || {};
    } catch (err) {
        // a malformed message still means "re-check"
    }
    for (const handler of handlers) {
        try {
            handler(detail);
        } catch (err) {
            logger.error({ msg: 'Credential change handler failed', err });
        }
    }
}

/**
 * Calls `handler(detail)` for every announced change. The subscriber connection is opened on the
 * first registration and shared by every handler in this process.
 *
 * @param {Function} handler
 * @returns {Function} Removes the handler
 */
function onRevocation(handler) {
    handlers.add(handler);
    if (!subscriber) {
        subscriber = redis.duplicate();
        subscriber.on('error', err => logger.warn({ msg: 'Credential change subscriber error', err }));
        subscriber.on('message', (channel, message) => dispatch(message));
        // Whatever was published while the connection was down is lost, so every handler
        // re-checks everything once it is back
        watchRedisReconnect(subscriber, () => dispatch('{}'));
        subscriber.subscribe(REVOCATION_CHANNEL).catch(err => logger.error({ msg: 'Failed to subscribe to credential changes', err }));
    }
    return () => {
        handlers.delete(handler);
        if (!handlers.size && subscriber) {
            const closing = subscriber;
            subscriber = null;
            closing.quit().catch(() => closing.disconnect());
        }
    };
}

module.exports = { publishRevocation, onRevocation, REVOCATION_CHANNEL };
