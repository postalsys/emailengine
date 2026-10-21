'use strict';

// Dependency-free, so pure modules can use it without the Redis connection lib/tools.js opens

/**
 * A copy of an object with only the keys whose value is set (truthy)
 * @param {Object} obj
 * @returns {Object}
 */
function filterEmptyObjectValues(obj) {
    let res = {};
    for (let key of Object.keys(obj)) {
        if (obj[key]) {
            res[key] = obj[key];
        }
    }
    return res;
}

module.exports = { filterEmptyObjectValues };
