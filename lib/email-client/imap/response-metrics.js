'use strict';

// Label values for the `imap_responses` counter.
//
// ImapFlow reports every tagged response as `{ response, code }`: the status (OK, NO, BAD, ...)
// and the bracketed response code when there is one (`[ALERT]`, `[AUTHENTICATIONFAILED]`).
// Both are atoms the server chose, and every distinct label value is a new series held by the
// Prometheus registry on the main thread for the life of the process, so a server (or a proxy on
// the path) that varies them grows that memory without bound. Only the vocabulary below reaches
// the counter; anything else is counted under `other`, which keeps the count right while bounding
// the series.

// RFC 9051 status responses, plus the two a tagged response may carry on some servers
const KNOWN_RESPONSES = new Set(['OK', 'NO', 'BAD', 'BYE', 'PREAUTH']);

// RFC 9051 and RFC 5530 response codes, plus the extension codes EmailEngine reacts to
const KNOWN_CODES = new Set([
    'ALERT',
    'ALREADYEXISTS',
    'APPENDUID',
    'AUTHENTICATIONFAILED',
    'AUTHORIZATIONFAILED',
    'BADCHARSET',
    'CANNOT',
    'CAPABILITY',
    'CLIENTBUG',
    'CLOSED',
    'COMPRESSIONACTIVE',
    'CONTACTADMIN',
    'COPYUID',
    'CORRUPTION',
    'EXPIRED',
    'EXPUNGEISSUED',
    'HASCHILDREN',
    'HIGHESTMODSEQ',
    'INUSE',
    'LIMIT',
    'NOMODSEQ',
    'NONEXISTENT',
    'NOPERM',
    'OVERQUOTA',
    'PARSE',
    'PERMANENTFLAGS',
    'PRIVACYREQUIRED',
    'READ-ONLY',
    'READ-WRITE',
    'SERVERBUG',
    'TRYCREATE',
    'UIDNEXT',
    'UIDNOTSTICKY',
    'UIDVALIDITY',
    'UNAVAILABLE',
    'UNKNOWN-CTE',
    'UNSEEN'
]);

const OTHER = 'other';

/**
 * @param {Object} data - the `response` event payload from ImapFlow
 * @returns {{response: String, code?: String}} the label values to count
 */
function imapResponseLabels(data) {
    let response = data && typeof data.response === 'string' ? data.response.toUpperCase() : '';
    let labels = { response: KNOWN_RESPONSES.has(response) ? response : OTHER };

    if (data && data.code !== undefined && data.code !== null) {
        let code = typeof data.code === 'string' ? data.code.toUpperCase() : '';
        labels.code = KNOWN_CODES.has(code) ? code : OTHER;
    }

    return labels;
}

module.exports = { imapResponseLabels, KNOWN_RESPONSES, KNOWN_CODES };
