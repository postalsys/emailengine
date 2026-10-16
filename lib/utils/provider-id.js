'use strict';

// Whether a provider id can become one path segment of a provider API URL.
//
// Provider ids are opaque strings the provider handed out, but the ones a request carries (a
// search by emailId or threadId, a reference threadId) and the ones inside a compound id
// (attachment and text ids are msgpack inside base64url) arrive from the API caller, and nothing
// above the client has looked at them. A segment of `..` walks the URL up to a sibling resource on
// the same token (another mailbox, on an application-credentials app), a `/` ends the segment
// early, and `?`, `#` and `%` change what the rest of the URL means. The joi schemas of the request
// ids and the clients' check of a decoded part are this one rule.

// eslint-disable-next-line no-control-regex
const PROVIDER_ID_SEGMENT = /^(?!\.{1,2}$)[^\s/\\?#%\u0000-\u001f\u007f]+$/;

// longer than any id a provider hands out; the regex has no cap of its own
const MAX_PROVIDER_ID_LENGTH = 1024;

/**
 * @param {*} value - the decoded part
 * @returns {Boolean}
 */
function isSafePathSegment(value) {
    return typeof value === 'string' && value.length <= MAX_PROVIDER_ID_LENGTH && PROVIDER_ID_SEGMENT.test(value);
}

module.exports = { PROVIDER_ID_SEGMENT, isSafePathSegment };
