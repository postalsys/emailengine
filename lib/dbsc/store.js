'use strict';

// What the server remembers about device-bound admin sessions, in Redis so every API worker sees
// the same state:
//
//   dbsc:b:{sid}     the binding: the session key the browser registered (JSON), for as long as the
//                    admin session itself can live. Its existence is what makes the session bound,
//                    and it is never deleted, not on a refusal and not on logout (which marks it
//                    `ended`): a session cookie whose binding was removed would read as unbound and
//                    be accepted on its own again
//   dbsc:c:{value}   a challenge, single use and short-lived, naming the sid and step it was minted
//                    for, so a proof signed over one session's challenge cannot serve another
//   dbsc:o:{sid}     an offer throttle, so a browser that cannot bind (or will not) is asked about
//                    once a minute rather than on every page
//   dbsc:f:{sid}     failed refresh proofs, so a browser stuck on a bad key is told to stop rather
//                    than retried for ever (the spec puts no bound on its 403 loop)

const crypto = require('crypto');

const { REDIS_PREFIX } = require('../consts');
const { incrementCounter } = require('../rate-limit');

const CHALLENGE_TTL = 120;
const OFFER_INTERVAL = 60;
const FAILURE_WINDOW = 300;
const MAX_REFRESH_FAILURES = 3;

const bindingKey = sid => `${REDIS_PREFIX}dbsc:b:${sid}`;
const challengeKey = challenge => `${REDIS_PREFIX}dbsc:c:${challenge}`;
const offerKey = sid => `${REDIS_PREFIX}dbsc:o:${sid}`;
const failureKey = sid => `${REDIS_PREFIX}dbsc:f:${sid}`;

/**
 * @param {Object} redis - ioredis client
 */
function createDbscStore(redis) {
    return {
        /**
         * Claims the right to offer registration to a session, at most once per OFFER_INTERVAL
         * @param {string} sid
         * @returns {Promise<boolean>}
         */
        async claimOffer(sid) {
            return (await redis.set(offerKey(sid), '1', 'EX', OFFER_INTERVAL, 'NX')) === 'OK';
        },

        /**
         * @param {string} sid
         * @param {'register'|'refresh'} purpose
         * @returns {Promise<string>} a new challenge
         */
        async mintChallenge(sid, purpose) {
            const challenge = crypto.randomBytes(24).toString('base64url');
            await redis.set(challengeKey(challenge), JSON.stringify({ sid, purpose }), 'EX', CHALLENGE_TTL);
            return challenge;
        },

        /**
         * Spends a challenge. Answers true only for one minted for this session and step
         * @param {string} challenge
         * @param {string} sid
         * @param {'register'|'refresh'} purpose
         * @returns {Promise<boolean>}
         */
        async consumeChallenge(challenge, sid, purpose) {
            const stored = await redis.getdel(challengeKey(challenge));
            if (!stored) {
                return false;
            }
            try {
                const parsed = JSON.parse(stored);
                return parsed.sid === sid && parsed.purpose === purpose;
            } catch (err) {
                return false;
            }
        },

        /**
         * Stores a session's key unless the session already has one: a session is bound once, so a
         * stolen session cookie cannot be re-bound to a key of the thief's
         * @param {string} sid
         * @param {Object} binding - { id, alg, jwk }
         * @param {number} ttlSeconds - the admin session's remaining life
         * @returns {Promise<boolean>} false when the session was already bound
         */
        async bind(sid, binding, ttlSeconds) {
            const value = JSON.stringify(Object.assign({}, binding, { created: Date.now() }));
            return (await redis.set(bindingKey(sid), value, 'EX', Math.max(1, Math.ceil(ttlSeconds)), 'NX')) === 'OK';
        },

        /**
         * @param {string} sid
         * @returns {Promise<Object|null>}
         */
        async getBinding(sid) {
            const stored = await redis.get(bindingKey(sid));
            if (!stored) {
                return null;
            }
            try {
                return JSON.parse(stored);
            } catch (err) {
                return null;
            }
        },

        /**
         * Ends a binding with its session (logout) by marking it, never by deleting it: the key is
         * what keeps a copied session cookie refused, so it stays for the session's remaining life
         * and no key can be bound to that session again
         * @param {string} sid
         */
        async endBinding(sid) {
            const binding = await this.getBinding(sid);
            if (binding && !binding.ended) {
                await redis.set(bindingKey(sid), JSON.stringify(Object.assign(binding, { ended: Date.now() })), 'XX', 'KEEPTTL');
            }
            await redis.del(offerKey(sid), failureKey(sid));
        },

        /**
         * Counts a failed refresh proof
         * @param {string} sid
         * @returns {Promise<boolean>} true while the session may still be asked again
         */
        async recordRefreshFailure(sid) {
            return (await incrementCounter(failureKey(sid), 1, FAILURE_WINDOW)) <= MAX_REFRESH_FAILURES;
        },

        async clearRefreshFailures(sid) {
            await redis.del(failureKey(sid));
        }
    };
}

module.exports = { createDbscStore, MAX_REFRESH_FAILURES, bindingKey, offerKey, failureKey };
