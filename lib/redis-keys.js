'use strict';

// Names of the Redis keys that more than one module builds. A key name is a storage contract: a
// module that spells one differently reads an empty key rather than failing, so a key used across
// layers (the API, the workers, the main thread) is named here once. test/redis-keys-test.js fails
// when one of the keys below is spelled out by hand anywhere else.
//
// lib/lua/s-list-accounts.lua builds the account data key itself; Lua cannot share this module.

const { REDIS_PREFIX } = require('./consts');

/**
 * The account data hash: the account record, its connection state and counters
 * @param {String} account - account id
 * @returns {String}
 */
const accountDataKey = account => `${REDIS_PREFIX}iad:${account}`;

module.exports = { accountDataKey };
