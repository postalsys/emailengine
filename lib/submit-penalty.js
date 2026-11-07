'use strict';

// A delivery penalty per account, for the submit queue. The queue is shared by every account and
// runs one delivery at a time by default, so an account whose SMTP server holds each delivery until
// the deadline used to hold the whole queue: a few such messages delayed every other account's mail
// by the full deadline each. An account whose delivery ran into the deadline is penalised: for a
// while its next messages are moved back to the delayed set instead of being attempted, with their
// attempt count unchanged, and the queue spends its time on accounts whose servers answer. Mirrors
// lib/webhook-penalty.js.

const { REDIS_PREFIX } = require('./consts');

// How long an account is penalised after a delivery ran into the deadline
const SUBMIT_PENALTY_MS = 10 * 60 * 1000;

/**
 * @param {string} account - Account id
 * @returns {string} The Redis key of the account's penalty
 */
function submitPenaltyKey(account) {
    return `${REDIS_PREFIX}submit:penalty:${account}`;
}

module.exports = { submitPenaltyKey, SUBMIT_PENALTY_MS };
