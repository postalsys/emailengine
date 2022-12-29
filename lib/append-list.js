'use strict';

const msgpack = require('msgpack5')();

/**
 * Pushes an object to the end of a list where that list is stored in a hash field
 *
 * @async
 * @param {Object} redis Redis client
 * @param {String} list Hash key
 * @param {String} key Hash field
 * @param {Object} obj Data to serialize and append to the list
 * @returns {Number} either 1 if this was the first element or 2
 */
async function append(redis, list, key, obj) {
    if (!obj) {
        return false;
    }
    let encoded;

    try {
        encoded = msgpack.encode(obj);
    } catch (err) {
        return false;
    }

    let result = await redis.hPush(list, key, encoded);
    return result;
}

/**
 * Retrieves all stored entries of a list
 *
 * @async
 * @param {Object} redis Redis client
 * @param {String} list Hash key
 * @param {String} key Hash field
 * @returns {Array} Stored objects as an array
 */
async function list(redis, list, key) {
    let contents = await redis.hgetBuffer(list, key);
    if (!contents) {
        return [];
    }

    return new Promise((resolve, reject) => {
        let decoder = msgpack.decoder({});
        let list = [];
        decoder.on('readable', () => {
            let data;
            while ((data = decoder.read()) !== null) {
                list.push(data);
            }
        });
        decoder.on('end', () => resolve(list));
        decoder.on('error', err => reject(err));
        decoder.end(contents);
    });
}

/**
 * Clears a list from Redis
 *
 * @async
 * @param {Object} redis Redis client
 * @param {String} list Hash key
 * @param {String} key Hash field
 * @returns {Number} 1 if list was deleted or 0
 */
async function clear(redis, list, key) {
    return await redis.hdel(list, key);
}

module.exports = { append, list, clear };
