'use strict';

// Presentation of the token permission vocabulary for the admin UI: the checkbox rows on the token
// form, the presets above them, and the one-line summary on the token list.
//
// Its own module because two views need the same labels, and because the labels have to be derived
// from lib/api-routes/permission-map.js rather than typed again - a group added there without a
// label here would render as a blank checkbox, and one removed would leave a control that posts a
// value the API refuses.

const { ACTION, GROUP, GRANTABLE_GROUPS, SURFACE_GRANTS, PER_REQUEST_SURFACES } = require('./api-routes/permission-map');
const tokenPermissions = require('./token-permissions');
const { ENUM_DESCRIPTIONS } = require('./enum-descriptions');

// Sentence-case labels for the checkbox rows. The slug itself is shown beside each one, so this only
// has to read well - it is not the identifier.
const ACTION_LABELS = {
    [ACTION.READ]: 'Read',
    [ACTION.WRITE]: 'Create and modify',
    [ACTION.SEND]: 'Send email',
    [ACTION.DESTRUCTIVE]: 'Delete'
};

const GROUP_LABELS = {
    [GROUP.ACCOUNT]: 'Accounts',
    [GROUP.MAILBOX]: 'Folders',
    [GROUP.MESSAGE]: 'Messages',
    [GROUP.SUBMIT]: 'Sending',
    [GROUP.OUTBOX]: 'Sending queue',
    [GROUP.EXPORT]: 'Bulk export',
    [GROUP.TEMPLATE]: 'Templates',
    [GROUP.BLOCKLIST]: 'Suppression lists',
    [GROUP.WEBHOOK]: 'Webhook routes',
    [GROUP.GATEWAY]: 'SMTP gateways',
    [GROUP.EVENTS]: 'Change stream',
    [GROUP.DIAGNOSTICS]: 'Statistics and status',
    [GROUP.LOGS]: 'Connection logs'
};

// Clusters for the section list. Thirteen rows at identical weight is a scan rather than a choice,
// and the split is the one a reader already has: the mail itself, the things that act on it, and the
// things that only watch.
const GROUP_CLUSTERS = [
    { label: 'Mail', groups: [GROUP.ACCOUNT, GROUP.MAILBOX, GROUP.MESSAGE, GROUP.SUBMIT, GROUP.OUTBOX, GROUP.EXPORT] },
    { label: 'Configuration', groups: [GROUP.TEMPLATE, GROUP.BLOCKLIST, GROUP.WEBHOOK, GROUP.GATEWAY] },
    { label: 'Monitoring', groups: [GROUP.EVENTS, GROUP.DIAGNOSTICS, GROUP.LOGS] }
];

// Starting points, because a fourteen-row matrix is not how anyone begins. Each is a real shape
// somebody asks for rather than an illustration of the axes.
const PRESETS = [
    {
        label: 'Read only',
        title: 'Read messages, folders and accounts. Cannot change or send anything',
        actions: [ACTION.READ],
        groups: [GROUP.ACCOUNT, GROUP.MAILBOX, GROUP.MESSAGE, GROUP.OUTBOX, GROUP.DIAGNOSTICS]
    },
    {
        // Not "never delete it". Filing mail is the same operation as deleting it here - the delete
        // endpoint moves the message to Trash, which this preset allows the token to do directly -
        // so the honest claim is about the endpoints, not the outcome. See the note on
        // ACTION.DESTRUCTIVE in lib/api-routes/permission-map.js.
        label: 'Mail agent',
        title: 'Read, file and send mail, without reaching the delete endpoints',
        actions: [ACTION.READ, ACTION.WRITE, ACTION.SEND],
        groups: [GROUP.ACCOUNT, GROUP.MAILBOX, GROUP.MESSAGE, GROUP.SUBMIT, GROUP.OUTBOX]
    },
    {
        // Deliberately not described as "no access to stored messages": a submit payload may carry
        // `reference: {message, action: 'forward'}`, which reads a stored message and delivers it, so
        // sending implies read-through of a message the holder can name. The grant is route-level and
        // does not inspect the payload, so the claim would have been false.
        label: 'Send only',
        title: 'Submit mail and watch the sending queue',
        actions: [ACTION.READ, ACTION.SEND],
        groups: [GROUP.SUBMIT, GROUP.OUTBOX]
    },
    {
        label: 'Everything allowed',
        title: 'Every action on every section that can be granted. Still cannot reach credentials or settings',
        actions: Object.values(ACTION),
        groups: GRANTABLE_GROUPS
    }
];

// How each non-API scope reads in a sentence. The grants themselves come from SURFACE_GRANTS, which
// is what the enforcement reads, so this cannot describe rules that have since changed.
const SURFACE_LABELS = {
    smtp: 'send over SMTP',
    'imap-proxy': 'connect through the IMAP proxy',
    metrics: 'read the metrics endpoint',
    mcp: 'call MCP tools'
};

/**
 * View model for the permission controls on the token form.
 *
 * @returns {Object} { permissionActions, permissionGroups, permissionPresets }
 */
function formModel() {
    return {
        permissionActions: Object.values(ACTION).map(value => ({
            value,
            inputId: `permissionAction_${value}`,
            label: ACTION_LABELS[value] || value,
            description: ENUM_DESCRIPTIONS.tokenAction[value] || ''
        })),

        // Clustered rather than flat. Asserted against GRANTABLE_GROUPS in the tests, so a group
        // added without a cluster cannot silently vanish from the form.
        permissionGroupClusters: GROUP_CLUSTERS.map(cluster => ({
            label: cluster.label,
            groups: cluster.groups.map(value => ({
                value,
                inputId: `permissionGroup_${value}`,
                label: GROUP_LABELS[value] || value,
                description: ENUM_DESCRIPTIONS.tokenGroup[value] || ''
            }))
        })),

        // What each non-API scope needs before it can be used, derived from the tables that enforce
        // it rather than restated in the page script. A hand-copied mirror would let the form keep
        // showing an old warning after the grant list changed, which is exactly the drift
        // lib/auth-token.js exists to prevent.
        //
        // `mode` is the surface's quantifier (see PER_REQUEST_SURFACES): 'all' surfaces are checked
        // once at login and need every listed grant, 'any' surfaces are checked per request and
        // work as long as a single grant pair remains allowed - the page script warns accordingly,
        // which is why the exact (action, group) pairs ride along in `grantList`.
        permissionSurfaces: Object.entries(SURFACE_LABELS).map(([scope, label]) => ({
            scope,
            label,
            mode: PER_REQUEST_SURFACES.has(scope) ? 'any' : 'all',
            actionList: [...new Set(SURFACE_GRANTS[scope].map(grant => grant.action))].join(','),
            groupList: [...new Set(SURFACE_GRANTS[scope].map(grant => grant.group))].join(','),
            grantList: SURFACE_GRANTS[scope].map(grant => `${grant.action}:${grant.group}`).join(',')
        })),

        // data-actions/data-groups are read by the preset buttons in views/tokens/new.hbs
        permissionPresets: PRESETS.map(preset => ({
            label: preset.label,
            title: preset.title,
            actionList: preset.actions.join(','),
            groupList: preset.groups.join(',')
        }))
    };
}

// Phrases the two axes as something a person reads rather than as two labelled fields. An axis that
// is absent is not a restriction, so it is left out of the sentence entirely - saying "all sections"
// would imply a grant the record does not make.
//
// An axis that names everything is collapsed rather than enumerated. Spelling out all thirteen
// sections produced a line long enough to push the table sideways, and it read as a detailed
// restriction when it is the opposite: the interesting fact about such a token is what it still
// cannot reach.
function sentenceFor(actions, groups, coversAllActions, coversAllGroups) {
    // An empty allowlist allows nothing, so the token authenticates and then refuses everything.
    // "Can none only" said the record; this says what it means.
    if (actions === 'none' || groups === 'none') {
        return 'Allows nothing - this token cannot make any request';
    }
    const verb = coversAllActions ? 'Full access' : actions && `Can ${actions.toLowerCase()}`;
    const where = coversAllGroups ? 'every section' : groups;

    if (verb && where) {
        return coversAllActions && coversAllGroups ? 'Full access, except settings, credentials and tokens' : `${verb} in ${where}`;
    }
    if (verb) {
        return coversAllActions ? 'Full access' : `${verb} only`;
    }
    if (where) {
        return coversAllGroups ? 'Every section' : `Limited to ${where}`;
    }
    return 'Restricted';
}

/**
 * One-line description of what a stored `permissions` record allows, for the token list.
 *
 * @param {*} permissions - the record's `permissions` field
 * @returns {Object|null} { actions, groups, unreadable } or null when the token is not narrowed
 */
function summarize(permissions) {
    // Asked of the module that enforces it rather than re-derived here. `{}`, an unknown axis and a
    // slug outside the vocabulary are all refusals, so a view that only looked for a non-object
    // would render them as working narrow credentials - which is the opposite of the truth, since
    // every request such a token makes is denied.
    const verdict = tokenPermissions.inspect({ permissions });

    if (!verdict.narrowed) {
        return null;
    }

    if (verdict.malformed) {
        return { actions: null, groups: null, unreadable: true };
    }

    const label = (values, labels) => {
        if (!Array.isArray(values)) {
            return null;
        }
        if (!values.length) {
            // An empty allowlist allows nothing, which is the opposite of the axis being absent
            return 'none';
        }
        // Object.hasOwn rather than a bare lookup, for the same reason the parse uses it: a slug of
        // `constructor` would otherwise render an Object.prototype member
        return values.map(value => (Object.hasOwn(labels, value) ? labels[value] : value)).join(', ');
    };

    const actions = label(permissions.actions, ACTION_LABELS);
    const groups = label(permissions.groups, GROUP_LABELS);

    const covers = (values, whole) => Array.isArray(values) && values.length === whole.length && whole.every(entry => values.includes(entry));

    return {
        actions,
        groups,
        // One line a person can read, rather than two labelled fragments. "Can: Read / In: Messages"
        // is the record read out loud; this is what the record means.
        sentence: sentenceFor(actions, groups, covers(permissions.actions, Object.values(ACTION)), covers(permissions.groups, GRANTABLE_GROUPS)),
        unreadable: false
    };
}

module.exports = { formModel, summarize, ACTION_LABELS, GROUP_LABELS };
