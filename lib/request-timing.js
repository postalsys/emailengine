'use strict';

/**
 * How long an API request took, for the api_call_duration_seconds histogram. Read off Hapi's
 * request.info in the 'response' event, where `completed` is set once the response was sent.
 * A request the client abandoned has no `completed` but a `responded`, and either one is a better
 * end than the time the event happens to run.
 *
 * @param {Object} info - Hapi request.info
 * @returns {number|null} Seconds, or null when the request carries no usable timestamps
 */
function apiCallDuration(info) {
    if (!info || !Number.isFinite(info.received) || info.received <= 0) {
        return null;
    }
    const end = [info.completed, info.responded].find(value => Number.isFinite(value) && value > 0);
    if (!end || end < info.received) {
        return null;
    }
    return (end - info.received) / 1000;
}

module.exports = { apiCallDuration };
