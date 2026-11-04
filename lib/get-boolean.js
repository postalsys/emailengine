'use strict';

// Split out of lib/tools.js so leaf modules (lib/api-listener.js) can read a switch without loading
// it. Still re-exported from lib/tools.js, which is where most callers reach it.

/**
 * Reads a configuration switch the way every EmailEngine setting reads one.
 *
 * @param {*} value - A boolean, a number, or a string such as "true", "yes", "on", "enabled" or "1"
 * @returns {boolean}
 */
function getBoolean(value) {
    if (typeof value === 'boolean') {
        return value;
    }

    if (typeof value === 'string') {
        value = value.trim();
    }

    if (typeof value === 'string' && !isNaN(value) && /^[0-9]+$/.test(value)) {
        value = Number(value);
    }

    if (typeof value === 'number') {
        return !!value;
    }

    if (typeof value === 'string') {
        // `on` and `enabled` are what several operators write in env files, and joi and
        // resolveHttpProxy() already read `on` as true
        return /^(y|true|on$|enabled$)/i.test(value);
    }

    return false;
}

module.exports = { getBoolean };
