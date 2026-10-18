'use strict';

// Parsers for the admin form textareas that hold one entry per line. Dependency-free, so any
// lib/ui-routes module can use them without pulling in route-helpers.js. A missing field parses
// as an empty list, so a handler updating a stored value checks the field was sent first.

/**
 * Parses the "Custom headers" textarea of the webhook forms, one `Name: value` per line, into
 * the `{ key, value }` list the webhooksCustomHeaders setting stores. A line without a colon is
 * a header with an empty value. A missing field parses as no headers.
 *
 * @param {string} [text] - the submitted textarea value
 * @returns {Array<{key: string, value: string}>}
 */
function parseCustomHeaders(text) {
    return (text || '')
        .split(/[\r\n]+/)
        .map(header => header.trim())
        .filter(header => header)
        .map(line => {
            let sep = line.indexOf(':');
            if (sep >= 0) {
                return {
                    key: line.substring(0, sep).trim(),
                    value: line.substring(sep + 1).trim()
                };
            }
            return {
                key: line,
                value: ''
            };
        });
}

/**
 * Splits the whitespace separated scope list of the OAuth2 app form. A missing field parses as
 * an empty list.
 *
 * @param {string} [text] - the submitted textarea value
 * @returns {string[]}
 */
function parseScopeList(text) {
    return (text || '').split(/\s+/).filter(scope => scope);
}

module.exports = { parseCustomHeaders, parseScopeList };
