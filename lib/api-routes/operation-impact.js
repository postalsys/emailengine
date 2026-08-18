'use strict';

// What running an operation actually does to the instance. Declared per route under
// `plugins.openapi['x-ee-impact']`, which the generator publishes verbatim (see
// assignVendorExtensions in lib/openapi/build-document.js), so the classification reaches every
// consumer of /swagger.json and not just the admin UI.
//
// It exists because the Try it panel used to carry the same warning on all 82 operations -
// including 42 that only read - which is how a warning teaches readers to skim past it. The
// weight of the warning now tracks the consequence: nothing on a read, a muted line on an
// ordinary write, and a real warning on the operations that destroy data or send mail.
//
// Only the exceptions are declared. resolveImpact() derives the default from the HTTP method, so
// a plain GET needs nothing and a POST that writes needs nothing. Declare an impact when the
// method is a bad proxy for the effect, which is both directions here:
// `POST /v1/unified/search` only reads, and `PUT /v1/account/{account}/messages/delete`
// deletes in bulk.
//
// The derivation lives here rather than in the one place that reads it today because it is about
// to have a second reader. lib/api-reference/model.js weights the Try it warning by it; the token
// permission model narrows on the same value. A route classified one way for the warning banner
// and another way for access control is a divergence nothing would catch, so both call this.
const IMPACT = {
    // Removes data, or discards state that cannot be recovered from EmailEngine
    DESTRUCTIVE: 'destructive',

    // Hands a message to a mail server. Whatever else happens, mail leaves the instance and
    // reaches real recipients - the one Try it consequence that is not undoable from here.
    SENDS: 'sends',

    // Reads only, despite not being a GET
    READONLY: 'readonly',

    // What an undeclared non-GET resolves to. Derived rather than declared, so it is absent from
    // DECLARABLE below, but the consumers that switch on an impact still need a name for it.
    WRITE: 'write'
};

// What a route may put in `x-ee-impact`. WRITE is deliberately excluded: it is the default, so
// declaring it says nothing, and treating it as valid input would mean two spellings of the same
// classification. Exported because test/api-reference-test.js asserts what the routes declare and
// has no business keeping its own copy of the vocabulary.
const DECLARABLE_IMPACTS = new Set([IMPACT.DESTRUCTIVE, IMPACT.SENDS, IMPACT.READONLY]);

/**
 * Resolves an operation's impact from what it declares plus its HTTP method.
 *
 * Returns null when `declared` is not a declarable impact. That is a typo in a route definition
 * rather than a fourth kind of impact, and guessing would hide it: a route meaning `destructive`
 * but spelling it `deletes` would silently resolve to the method default and lose its warning.
 * Callers decide what null means for them - the reference page renders no warning, which is what
 * it did before this function existed.
 *
 * @param {String} [declared] - the route's `x-ee-impact`, if it sets one
 * @param {String} method - HTTP method, in any case
 * @returns {String|null} one of IMPACT, or null when `declared` is not declarable
 */
function resolveImpact(declared, method) {
    if (declared) {
        return DECLARABLE_IMPACTS.has(declared) ? declared : null;
    }

    switch (String(method).toLowerCase()) {
        case 'get':
            return IMPACT.READONLY;

        // A DELETE removes something. Defaulting it to WRITE made `destructive` opt-in, which is
        // fail-open now that a token can be narrowed to "write but not destructive": a new DELETE
        // that forgot its declaration would resolve to WRITE and be callable by a token explicitly
        // issued without destructive rights. Every DELETE today declares IMPACT.DESTRUCTIVE, so
        // this changes no current classification - it removes the way the next one could go wrong.
        case 'delete':
            return IMPACT.DESTRUCTIVE;

        default:
            return IMPACT.WRITE;
    }
}

module.exports = { IMPACT, DECLARABLE_IMPACTS, resolveImpact };
