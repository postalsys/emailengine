'use strict';

// Narrowing check for an access token that carries a `permissions` record.
//
// Two forms, both subtractive. The two-axis form is the original: `actions` says what the token may
// do, `groups` says what it may touch, and an operation has to pass both, so the record means the
// cross product of the two lists. The pair-list form, `grants`, names exact (action, group) pairs
// instead, for the narrowing the cross product cannot express - read on one section and write on
// another - and stands alone: a record carrying it beside an axis is refused rather than
// intersected. The vocabulary for both lives in lib/api-routes/permission-map.js. This function
// only ever SUBTRACTS from what `scopes` and the account binding already allow - there is no value
// of `permissions` that grants anything, so it is safe to run after those checks rather than
// instead of them.
//
// Shared by both enforcement points on the same precedent that put lib/auth-token.js in one place:
// the api-token strategy in workers/api.js for HTTP, and lib/auth-token.js for the SMTP submission
// and IMAP proxy surfaces. A policy change that landed on one and missed the other would be a hole
// in whichever surface was forgotten.

const { NEVER_GRANTABLE, ACTION_VALUES, GROUP_VALUES, GRANTABLE_GROUPS, grantKey } = require('./api-routes/permission-map');

// One parse per record object. check() runs once per tool for every tools/list and once per
// MCP-dispatched request, over the same msgpack-decoded record each time, and the pair-list form
// validates and copies every entry on each parse. Keyed weakly on the record object itself, so a
// record lives in the cache exactly as long as the token data it came from; primitives (which
// are always malformed) are not cached and cost nothing to re-read.
const parsedRecords = new WeakMap();

// The axes a record may carry, and the vocabulary each accepts. Anything else is a record this
// version does not understand.
const AXIS_VALUES = {
    actions: ACTION_VALUES,
    groups: GROUP_VALUES
};

const AXES = Object.keys(AXIS_VALUES);

// The pair-list form. Listed apart from the axes because it is not one: it replaces both.
const GRANTS_KEY = 'grants';
const RECORD_KEYS = AXES.concat(GRANTS_KEY);

// The two keys a grant entry carries, and no other. An entry with an extra key is refused the same
// way a record with an extra axis is: a later version may give the pair a third field, and this
// one must deny rather than honour the two halves it understands.
const GRANT_KEYS = ['action', 'group'];

// Why a request was refused. Reported to the caller rather than rendered here, because HTTP, SMTP
// and IMAP each say "no" differently.
const REASON = {
    // The route resolved to no action or no group, so this vocabulary does not describe it. Means
    // the route table and permission-map.js have diverged, which test/api-routes-table-test.js
    // exists to prevent.
    UNCLASSIFIED: 'unclassified',

    // `permissions` is present but not a shape this version can read. Deliberately NOT treated as
    // absent: see the comment on parsePermissions().
    MALFORMED: 'malformed',

    // A group no `permissions` record may ever name, whatever it says.
    RESTRICTED: 'restricted',

    ACTION: 'action',
    GROUP: 'group',

    // No pair in a `grants` list covers the operation. One reason rather than two, because a pair
    // list has no axes to name.
    GRANT: 'grant'
};

/**
 * Reads a `grants` list, or reports that it cannot be read.
 *
 * Every entry is checked the way the axes are: own keys only, exactly the two the pair is made of,
 * and both values in the vocabulary. The entries are copied out rather than kept, so the caller
 * holds plain pairs and not whatever object msgpack decoded.
 *
 * @param {*} value - the record's `grants` field
 * @returns {{pairs: Array, keys: Set}|null} the pairs and their `action:group` keys, or null when
 *          the list is not one this version can read
 */
function parseGrants(value) {
    if (!Array.isArray(value)) {
        return null;
    }

    const pairs = [];
    const keys = new Set();
    for (const entry of value) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
            return null;
        }

        const own = Object.keys(entry);
        if (own.length !== GRANT_KEYS.length || !GRANT_KEYS.every(key => Object.hasOwn(entry, key))) {
            return null;
        }

        if (!ACTION_VALUES.has(entry.action) || !GROUP_VALUES.has(entry.group)) {
            return null;
        }

        pairs.push({ action: entry.action, group: entry.group });
        keys.add(grantKey(entry));
    }

    return { pairs, keys };
}

/**
 * Reads a `permissions` record, or reports that it cannot be read.
 *
 * The distinction between "absent" and "unreadable" is the whole safety of this module, because the
 * two mean opposite things: absent is every token issued before permissions existed and must keep
 * working unnarrowed, while unreadable must grant nothing. Collapsing them would turn a malformed
 * record into a full-privilege token.
 *
 * That is not hypothetical. tokens.setRawData() writes whatever fields its input carries with no
 * joi schema at all, and it is the import path for EENGINE_PREPARED_TOKEN, so an arbitrary
 * `permissions` value can reach a record without ever passing route validation.
 *
 * @param {*} permissions - the record's `permissions` field
 * @returns {{narrowed: Boolean, axes: (Object|null), grants: (Array|null), malformed: Boolean}}
 */
function parsePermissions(permissions) {
    if (permissions === null || typeof permissions === 'undefined') {
        return { narrowed: false, axes: null, grants: null, malformed: false };
    }

    const malformed = { narrowed: true, axes: null, grants: null, malformed: true };

    if (typeof permissions !== 'object' || Array.isArray(permissions)) {
        return malformed;
    }

    let parsed = parsedRecords.get(permissions);
    if (!parsed) {
        parsed = parseRecord(permissions, malformed);
        parsedRecords.set(permissions, parsed);
    }
    return parsed;
}

function parseRecord(permissions, malformed) {
    const keys = Object.keys(permissions);

    // An unknown key is refused rather than ignored. That is what let `grants` be added to a model
    // that already had tokens in the field, and what lets the next key be added the same way: an
    // older release denies the request instead of honouring a narrowing it cannot apply.
    if (keys.some(key => !RECORD_KEYS.includes(key))) {
        return malformed;
    }

    // `{}` is ambiguous between "no narrowing" and "grant nothing". The joi schema refuses it so it
    // never reaches a record through the API, and anything that gets in another way is denied.
    if (!keys.length) {
        return malformed;
    }

    if (Object.hasOwn(permissions, GRANTS_KEY)) {
        // The pair list stands alone. Beside an axis it would be two records claiming one token,
        // and neither "intersect them" nor "the list wins" is a reading a reader could predict.
        if (keys.length !== 1) {
            return malformed;
        }

        const grants = parseGrants(permissions[GRANTS_KEY]);
        if (!grants) {
            return malformed;
        }

        // An empty list is well-formed and grants nothing, exactly like an empty axis
        return { narrowed: true, axes: null, grants, malformed: false };
    }

    const axes = {};
    for (const axis of AXES) {
        // Object.hasOwn rather than `in`: this record was msgpack-decoded from Redis by a path with
        // no schema, and `in` walks the prototype chain, so a payload that got something onto the
        // decoded object's prototype could otherwise supply an axis the record does not own.
        if (!Object.hasOwn(permissions, axis)) {
            continue;
        }

        const value = permissions[axis];
        if (!Array.isArray(value) || value.some(entry => !AXIS_VALUES[axis].has(entry))) {
            return { narrowed: true, axes: null, malformed: true };
        }

        // An empty array is well-formed and grants nothing: an allowlist that lists nothing allows
        // nothing. That is the opposite of the axis being absent, and it matches how `scopes: []`
        // already behaves.
        axes[axis] = value;
    }

    return { narrowed: true, axes, grants: null, malformed: false };
}

/**
 * Is this operation allowed to the token?
 *
 * @param {Object} opts
 * @param {Object} opts.tokenData - the record from tokens.get()
 * @param {Object} opts.operation - { action, group }, resolved by the caller from the route
 * @returns {{allowed: Boolean, reason: (String|null), required: (Object|null)}}
 */
function check({ tokenData, operation }) {
    const { action = null, group = null } = operation || {};
    const parsed = parsePermissions(tokenData && tokenData.permissions);

    if (!parsed.narrowed) {
        // No narrowing on this token, so nothing to subtract. Every token issued before this
        // feature shipped takes this path, which is what makes the change additive.
        return { allowed: true, reason: null, required: null };
    }

    const required = { action, group };

    if (parsed.malformed) {
        return { allowed: false, reason: REASON.MALFORMED, required };
    }

    if (!action || !group) {
        return { allowed: false, reason: REASON.UNCLASSIFIED, required };
    }

    // Checked before the axes, and independently of them, so no value of `groups` can reach these.
    // This is the rule the rest of the model rests on: while it holds, a narrowed token cannot mint
    // a token and cannot read a live provider credential, so it cannot widen itself (the settings
    // that would let it are refused per key, see assertNoPrivilegedSettings() in
    // lib/api-routes/route-helpers.js). Encoded as a deny set rather than as an absence from the
    // grantable list so that widening the grantable list can never quietly reopen it.
    if (NEVER_GRANTABLE.has(group)) {
        return { allowed: false, reason: REASON.RESTRICTED, required };
    }

    if (parsed.grants) {
        if (!parsed.grants.keys.has(grantKey(required))) {
            return { allowed: false, reason: REASON.GRANT, required };
        }
        return { allowed: true, reason: null, required };
    }

    if (parsed.axes.actions && !parsed.axes.actions.includes(action)) {
        return { allowed: false, reason: REASON.ACTION, required };
    }

    if (parsed.axes.groups && !parsed.axes.groups.includes(group)) {
        return { allowed: false, reason: REASON.GROUP, required };
    }

    return { allowed: true, reason: null, required };
}

/**
 * What this module makes of a token's `permissions` field, without an operation to check against.
 *
 * Exists so the admin UI can label a record the same way the enforcement reads it. Deriving the
 * shape a second time in the view diverged immediately: `{}`, an unknown axis and an out-of-vocabulary
 * slug are all refusals here, but a view that only looked for a non-object rendered them as working
 * narrow credentials.
 *
 * @param {Object} tokenData - the record from tokens.get()
 * @returns {{narrowed: Boolean, malformed: Boolean}}
 */
function inspect(tokenData) {
    const { narrowed, malformed } = parsePermissions(tokenData && tokenData.permissions);
    return { narrowed, malformed };
}

/**
 * The (action, group) pairs a record allows, whichever form it is written in.
 *
 * The two-axis form expands to its cross product, with an absent axis standing for every value of
 * that axis - every action, or every grantable group. The pair form is returned as it is. The
 * never-grantable groups are left out either way, because check() refuses them before it reads
 * the record, so a pair naming one is not something the record allows.
 *
 * For consumers that describe a record rather than enforce it: the admin listing summarises a
 * pair-list record through this rather than holding its own reading of the form.
 *
 * @param {*} permissions - the record's `permissions` field
 * @returns {Array<{action: String, group: String}>|null} the pairs, or null when the record narrows
 *          nothing or cannot be read (inspect() tells those two apart)
 */
function effectiveGrants(permissions) {
    const parsed = parsePermissions(permissions);
    if (!parsed.narrowed || parsed.malformed) {
        return null;
    }

    if (parsed.grants) {
        return parsed.grants.pairs.filter(grant => !NEVER_GRANTABLE.has(grant.group)).map(grant => ({ action: grant.action, group: grant.group }));
    }

    const actions = parsed.axes.actions || [...ACTION_VALUES];
    const groups = parsed.axes.groups || GRANTABLE_GROUPS;

    const grants = [];
    for (const action of actions) {
        for (const group of groups) {
            if (!NEVER_GRANTABLE.has(group)) {
                grants.push({ action, group });
            }
        }
    }
    return grants;
}

module.exports = { check, inspect, effectiveGrants, REASON };
