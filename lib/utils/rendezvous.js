'use strict';

// Rendezvous (highest random weight) scoring: every party that ranks the same candidates for the
// same key gets the same order, and adding or removing a candidate moves only the keys it wins or
// loses. Ranks IMAP workers and local addresses (lib/tools.js) and instances (lib/cluster/placement.js).
//
// The output is load-bearing: it decides which worker and which instance serves an account and which
// source address it connects from, so the hash and the key format must not change (see murmurhash3.js).

const { murmurhash3 } = require('./murmurhash3');

/**
 * @param {string} key - What is being placed (an account id)
 * @param {string|number} candidate - Who might take it (a worker thread id, an address, an instance id)
 * @returns {number} Higher wins
 */
function getRendezvousScore(key, candidate) {
    return murmurhash3(`${(candidate || '').toString()}\x00${key}`);
}

module.exports = { getRendezvousScore };
