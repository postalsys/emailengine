'use strict';

const Joi = require('joi');
const { IMAP_MAX_IDLE_TIME_MIN, IMAP_MAX_IDLE_TIME_MAX } = require('../consts');

// The IDLE restart interval on the account edit form. The form takes seconds, like the resync
// interval next to it, while the account stores milliseconds, the unit of the ImapFlow option it
// feeds. Split out of ./account-routes.js, which is at its size budget.

// allow('') with no default, so the key is present exactly when the page showed the input (see the
// folder overrides in ./account-routes.js for what a default does to that presence test)
const imapMaxIdleTimeFormSchema = Joi.number()
    .integer()
    .min(IMAP_MAX_IDLE_TIME_MIN / 1000)
    .max(IMAP_MAX_IDLE_TIME_MAX / 1000)
    .allow('', null);

/**
 * The value the edit form shows for a stored account
 * @param {Object} [accountImap] - The account's stored `imap` object
 * @returns {number|string} Seconds, or an empty string when unset
 */
const imapMaxIdleTimeFormValue = accountImap => (accountImap?.maxIdleTime ? accountImap.maxIdleTime / 1000 : '');

/**
 * Writes a submitted interval into the IMAP update. Written only when the page showed the input and
 * the effective value changed, because any `imap` diff forces a reconnect
 * @param {Object} payload - The validated form payload
 * @param {Object} [oldImap] - The account's stored `imap` object
 * @param {Object} updateKeys - The IMAP keys to write, modified in place
 */
function applyImapMaxIdleTimeForm(payload, oldImap, updateKeys) {
    if (!('imap_maxIdleTime' in payload)) {
        return;
    }
    const value = payload.imap_maxIdleTime ? payload.imap_maxIdleTime * 1000 : null;
    if (value !== (oldImap?.maxIdleTime || null)) {
        updateKeys.maxIdleTime = value;
    }
}

module.exports = { imapMaxIdleTimeFormSchema, imapMaxIdleTimeFormValue, applyImapMaxIdleTimeForm };
