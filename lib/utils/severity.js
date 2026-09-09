'use strict';

// One severity order for every "worst of" roll-up in the admin UI: a group of workers, the
// listeners on the TLS page. Kept in one place so two badges cannot rank the same states
// differently. Neutral sits above success on purpose - an unknown member is worth showing over
// a healthy one - and informational sits below anything that asks for attention.
const SEVERITY_ORDER = ['success', 'neutral', 'info', 'warning', 'error'];

/**
 * Where a badge type sits in the order; an unknown type ranks with success.
 *
 * @param {string} type Badge variant: success|neutral|info|warning|error
 * @returns {number} Higher means worse
 */
function severityRank(type) {
    const rank = SEVERITY_ORDER.indexOf(type);
    return rank < 0 ? 0 : rank;
}

/**
 * The worst item by badge type.
 *
 * @param {Array} items Non-empty list
 * @param {Function} typeOf Reads the badge type off an item
 * @returns {*} The item that ranks worst; the first of equals
 */
function worstBy(items, typeOf) {
    return items.reduce((worst, item) => (severityRank(typeOf(item)) > severityRank(typeOf(worst)) ? item : worst));
}

module.exports = { SEVERITY_ORDER, severityRank, worstBy };
