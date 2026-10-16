'use strict';

/**
 * Runs `fn` over `items` with at most `limit` calls in flight and resolves with the results in
 * item order once every call has settled. Rejects with the first failure, like Promise.all, but
 * only after the calls already in flight have settled, so a caller never has calls outstanding
 * it does not know about. A caller that wants every item attempted regardless settles each
 * outcome inside `fn`.
 *
 * @param {Array} items
 * @param {number} limit - Calls in flight at once
 * @param {Function} fn - async (item, index) -> result
 * @returns {Promise<Array>}
 */
async function mapConcurrent(items, limit, fn) {
    const results = new Array(items.length);
    let next = 0;
    let failure = null;
    const runner = async () => {
        while (next < items.length && !failure) {
            const index = next++;
            try {
                results[index] = await fn(items[index], index);
            } catch (err) {
                failure = failure || err;
            }
        }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, runner));
    if (failure) {
        throw failure;
    }
    return results;
}

module.exports = { mapConcurrent };
