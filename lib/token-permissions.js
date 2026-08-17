'use strict';

// Narrowing check for an access token that carries a `permissions` record.
//
// Two axes, both subtractive: `actions` says what the token may do, `groups` says what it may
// touch, and the vocabulary for both lives in lib/api-routes/permission-map.js. This function only
// ever SUBTRACTS from what `scopes` and the account binding already allow - there is no value of
// `permissions` that grants anything, so it is safe to run after those checks rather than instead
// of them.
//
// Shared by both enforcement points on the same precedent that put lib/auth-token.js in one place:
// the api-token strategy in workers/api.js for HTTP, and lib/auth-token.js for the SMTP submission
// and IMAP proxy surfaces. A policy change that landed on one and missed the other would be a hole
// in whichever surface was forgotten.

const { NEVER_GRANTABLE, ACTION_VALUES, GROUP_VALUES } = require('./api-routes/permission-map');

// The axes a record may carry, and the vocabulary each accepts. Anything else is a record this
// version does not understand.
const AXIS_VALUES = {
    actions: ACTION_VALUES,
    groups: GROUP_VALUES
};

const AXES = Object.keys(AXIS_VALUES);

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
    GROUP: 'group'
};

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
 * @returns {{narrowed: Boolean, axes: (Object|null), malformed: Boolean}}
 */
function parsePermissions(permissions) {
    if (permissions === null || typeof permissions === 'undefined') {
        return { narrowed: false, axes: null, malformed: false };
    }

    if (typeof permissions !== 'object' || Array.isArray(permissions)) {
        return { narrowed: true, axes: null, malformed: true };
    }

    const keys = Object.keys(permissions);

    // An unknown key is refused rather than ignored. That is what lets a later version add a third
    // axis without this one silently disregarding it - an older release denies the request instead
    // of honouring a narrowing it cannot apply.
    if (keys.some(key => !AXES.includes(key))) {
        return { narrowed: true, axes: null, malformed: true };
    }

    // `{}` is ambiguous between "no narrowing" and "grant nothing". The joi schema refuses it so it
    // never reaches a record through the API, and anything that gets in another way is denied.
    if (!keys.length) {
        return { narrowed: true, axes: null, malformed: true };
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

    return { narrowed: true, axes, malformed: false };
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
    // This is the rule the rest of the model rests on: while it holds, a narrowed token cannot read
    // the settings blob, cannot read a stored OAuth2 credential, and cannot mint or revoke a token,
    // so it cannot widen itself. Encoded as a deny set rather than as an absence from the grantable
    // list so that widening the grantable list can never quietly reopen it.
    if (NEVER_GRANTABLE.has(group)) {
        return { allowed: false, reason: REASON.RESTRICTED, required };
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
 * Does this token carry a narrowing at all? Used to decide whether a denial is worth explaining in
 * terms of permissions, and by the admin UI to label a token.
 *
 * @param {Object} tokenData - the record from tokens.get()
 * @returns {Boolean}
 */
function isNarrowed(tokenData) {
    return parsePermissions(tokenData && tokenData.permissions).narrowed;
}

module.exports = { check, isNarrowed, REASON };
