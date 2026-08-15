'use strict';

// What running an operation actually does to the instance, for the Try it panel in the API
// reference. Declared per route under `plugins.openapi['x-ee-impact']`, which the generator
// publishes verbatim (see assignVendorExtensions in lib/openapi/build-document.js), so the
// classification reaches every consumer of /swagger.json and not just the admin UI.
//
// It exists because the Try it panel used to carry the same warning on all 82 operations -
// including 42 that only read - which is how a warning teaches readers to skim past it. The
// weight of the warning now tracks the consequence: nothing on a read, a muted line on an
// ordinary write, and a real warning on the operations that destroy data or send mail.
//
// Only the exceptions are declared. lib/api-reference/model.js derives the default from the
// HTTP method, so a plain GET needs nothing and a POST that writes needs nothing. Declare an
// impact when the method is a bad proxy for the effect, which is both directions here:
// `POST /v1/unified/search` only reads, and `PUT /v1/account/{account}/messages/delete`
// deletes in bulk.
const IMPACT = {
    // Removes data, or discards state that cannot be recovered from EmailEngine
    DESTRUCTIVE: 'destructive',

    // Hands a message to a mail server. Whatever else happens, mail leaves the instance and
    // reaches real recipients - the one Try it consequence that is not undoable from here.
    SENDS: 'sends',

    // Reads only, despite not being a GET
    READONLY: 'readonly'
};

module.exports = { IMPACT };
