'use strict';

// Presentation of the token permission vocabulary for the admin UI: the checkbox rows on the token
// form, the presets above them, and the one-line summary on the token list.
//
// Its own module because two views need the same labels, and because the labels have to be derived
// from lib/api-routes/permission-map.js rather than typed again - a group added there without a
// label here would render as a blank checkbox, and one removed would leave a control that posts a
// value the API refuses.

const { ACTION, GRANTABLE_GROUPS } = require('./api-routes/permission-map');
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
    account: 'Accounts',
    mailbox: 'Folders',
    message: 'Messages',
    submit: 'Sending',
    outbox: 'Sending queue',
    export: 'Bulk export',
    template: 'Templates',
    blocklist: 'Suppression lists',
    webhook: 'Webhook routes',
    gateway: 'SMTP gateways',
    events: 'Change stream',
    diagnostics: 'Statistics and status',
    logs: 'Connection logs'
};

// Starting points, because a fourteen-row matrix is not how anyone begins. Each is a real shape
// somebody asks for rather than an illustration of the axes.
const PRESETS = [
    {
        label: 'Read only',
        title: 'Read messages, folders and accounts. Cannot change or send anything',
        actions: [ACTION.READ],
        groups: ['account', 'mailbox', 'message', 'outbox', 'diagnostics']
    },
    {
        label: 'Mail agent',
        title: 'Read, file and send mail, but never delete it',
        actions: [ACTION.READ, ACTION.WRITE, ACTION.SEND],
        groups: ['account', 'mailbox', 'message', 'submit', 'outbox']
    },
    {
        label: 'Send only',
        title: 'Submit mail and watch the queue. No access to stored messages',
        actions: [ACTION.READ, ACTION.SEND],
        groups: ['submit', 'outbox']
    },
    {
        label: 'Everything allowed',
        title: 'Every action on every section that can be granted. Still cannot reach credentials or settings',
        actions: Object.values(ACTION),
        groups: GRANTABLE_GROUPS
    }
];

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

        permissionGroups: GRANTABLE_GROUPS.map(value => ({
            value,
            inputId: `permissionGroup_${value}`,
            label: GROUP_LABELS[value] || value,
            description: ENUM_DESCRIPTIONS.tokenGroup[value] || ''
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

    return {
        actions: label(permissions.actions, ACTION_LABELS),
        groups: label(permissions.groups, GROUP_LABELS),
        unreadable: false
    };
}

module.exports = { formModel, summarize, ACTION_LABELS, GROUP_LABELS };
