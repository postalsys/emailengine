'use strict';

const { SPECIAL_USE_PATH_TYPES } = require('../consts');

// The words the admin UI shows for each special-use folder override. The TYPES are not re-listed
// here: SPECIAL_USE_PATH_TYPES in lib/consts.js is the contract the IMAP client reads (it turns the
// list into the specialUseHints it passes to LIST) and the account schemas declare a field per entry,
// so a type added there reaches the form with it rather than needing a second edit.
//
// Split out of ./account-routes.js, which is at its size budget, and because this is page copy rather
// than routing: the same shape as ./ai-options.js next to it.
const SPECIAL_USE_PATH_LABELS = {
    sent: { label: 'Sent Mail', description: 'Store copies of sent emails in this folder.' },
    drafts: { label: 'Drafts', description: 'Treat this folder as the Drafts folder.' },
    junk: { label: 'Junk', description: 'Treat this folder as the Junk folder.' },
    trash: { label: 'Trash', description: 'Treat this folder as the Trash folder, where deleted messages are moved.' },
    archive: { label: 'Archive', description: 'Treat this folder as the Archive folder.' }
};

/**
 * The override fields as the edit form and the account page consume them: the account field name, the
 * form input id and the words to show, in the order the two templates render them.
 *
 * `{ type, key, inputId, label, description }` per entry. The form renders one input per entry from
 * `inputId`, its joi schema is generated per entry, and the update loop writes `key` onto the account
 * - so the four of them cannot drift. Only `sentMailPath` was ever offered on the form, which is how
 * the other four came to be settable over PUT /v1/account/{account} alone.
 */
const SPECIAL_USE_PATH_FIELDS = SPECIAL_USE_PATH_TYPES.map(type =>
    Object.assign({ type, key: `${type}MailPath`, inputId: `imap_${type}MailPath` }, SPECIAL_USE_PATH_LABELS[type])
);

module.exports = { SPECIAL_USE_PATH_FIELDS, SPECIAL_USE_PATH_LABELS };
