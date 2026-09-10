'use strict';

// Presentation of the token permission vocabulary for the admin UI: the checkbox rows on the token
// form, the presets above them, and the one-line summary on the token list.
//
// Its own module because two views need the same labels, and because the labels have to be derived
// from lib/api-routes/permission-map.js rather than typed again - a group added there without a
// label here would render as a blank checkbox, and one removed would leave a control that posts a
// value the API refuses.

const { ACTION, GROUP, GRANTABLE_GROUPS, IMPLICIT_GROUPS, SURFACE_GRANTS, PER_REQUEST_SURFACES, MCP_SCOPES } = require('./api-routes/permission-map');
const tokenPermissions = require('./token-permissions');
const { ENUM_DESCRIPTIONS } = require('./enum-descriptions');

// Sentence-case labels for the checkbox rows. The slug itself is shown beside each one, so this only
// has to read well - it is not the identifier. The same labels are also lowercased into running
// prose (the grant wording of the MCP access levels below), so each one has to work as a sentence fragment too.
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
    [GROUP.LOGS]: 'Connection logs',
    [GROUP.SETTINGS]: 'Instance settings',
    [GROUP.OAUTH2]: 'OAuth2 applications',
    [GROUP.LICENSE]: 'License',
    [GROUP.TOKEN]: 'Access tokens',
    [GROUP.PROVISIONING]: 'Account and gateway setup'
};

// The one spelling of the slug-to-label lookup. Object.hasOwn rather than a bare lookup: a slug
// of `constructor` would otherwise render an Object.prototype member.
const mapLabels = (values, labels) => values.map(value => (Object.hasOwn(labels, value) ? labels[value] : value));

// The `action:group` spelling of a pair, for keyed lookups and the browser-side lists
const grantKey = grant => `${grant.action}:${grant.group}`;

// The same vocabulary as a sentence fragment: lowercased and joined as an English list, for
// prose like the consent screen's grant sentences ("read, create and modify, and send email").
const GRANT_LIST_FORMAT = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' });
const humanGrantList = (values, labels) => GRANT_LIST_FORMAT.format(mapLabels(values, labels).map(word => word.toLowerCase()));

// Clusters for the section list. Eighteen rows at identical weight is a scan rather than a choice,
// and the split is the one a reader already has: the mail itself, the things that act on it, the
// things that only watch, and the instance underneath all of it.
const GROUP_CLUSTERS = [
    { label: 'Mail', groups: [GROUP.ACCOUNT, GROUP.MAILBOX, GROUP.MESSAGE, GROUP.SUBMIT, GROUP.OUTBOX, GROUP.EXPORT] },
    { label: 'Configuration', groups: [GROUP.TEMPLATE, GROUP.BLOCKLIST, GROUP.WEBHOOK, GROUP.GATEWAY] },
    { label: 'Monitoring', groups: [GROUP.EVENTS, GROUP.DIAGNOSTICS, GROUP.LOGS] },
    { label: 'Instance', groups: [GROUP.SETTINGS, GROUP.PROVISIONING, GROUP.OAUTH2, GROUP.TOKEN, GROUP.LICENSE] }
];

// How the token list names the sections an absent `groups` axis reaches (IMPLICIT_GROUPS): by
// what it leaves out, because that is the interesting part. The difference is rendered as the
// cluster heading the token form shows when it is exactly one cluster, and as the section labels
// otherwise, so a section added outside the implicit set changes the wording rather than hiding
// behind a heading that no longer covers it.
const IMPLICIT_GROUPS_LABEL = (() => {
    const left = GRANTABLE_GROUPS.filter(group => !IMPLICIT_GROUPS.includes(group));
    const cluster = GROUP_CLUSTERS.find(entry => entry.groups.length === left.length && entry.groups.every(group => left.includes(group)));
    return `every section except ${cluster ? cluster.label : GRANT_LIST_FORMAT.format(mapLabels(left, GROUP_LABELS))}`;
})();

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
        title: 'Every action on every section that can be granted. Still cannot create tokens or read stored credentials',
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
    'mcp-manage': 'call the MCP management tools',
    mcp: 'call the MCP mail tools'
};

// The MCP access levels: what the OAuth consent prompt, the MCP config page's generator and the
// token form offer, and what each choice mints. Two sections, because the endpoint has two tool
// sets behind two scopes and a person approving an agent decides about them separately -
// managing the instance is the default question, mailbox contents the opt-in one. Each level is
// a pair list rather than a two-axis record: one token can hold a management level and a mail
// level at once, and the cross product of two axes cannot keep "operate the instance" from
// leaking write access onto the messages. Derived once at load from the surface tables the
// enforcement reads, nothing else; lives here because this module owns how permission records
// are presented, and a second derivation had already drifted once.
//
// A section is declined with the `none` level, which every section has and which mints nothing:
// one value per section, so no page has to carry "is this section on" beside the level. The
// consent prompt and the generator offer it as a radio; the token form declines a section by
// leaving its scope unticked and offers the other levels only.
//
// A minted token always carries the pair list of the levels approved, never an absent record:
// a consent given for the tools of today must not grow to include a tool shipped next release.
const pairsOf = (scope, predicate) => SURFACE_GRANTS[scope].filter(predicate).map(grant => ({ action: grant.action, group: grant.group }));

// Everything a level carries: `caveat` is the sentence the consent prompt shows under the derived
// grant list - what the level still cannot do, and what it can that a reader might not expect -
// and `lead` on the section opens that sentence. The wording of the pairs themselves, and the
// alert severity, are computed onto each level below.
const MCP_SECTIONS = {
    manage: {
        scope: MCP_SCOPES.manage,
        label: 'Instance management',
        lead: 'Through the management tools the client will be able to',
        defaultLevel: 'observe',
        none: { label: 'No management access', hint: 'The client gets only what is granted below.' },
        levels: [
            {
                value: 'observe',
                label: 'Observe',
                hint: 'Recommended. Read accounts, settings, queues, OAuth2 applications, gateways, tokens and logs. Cannot change anything.',
                caveat: 'It cannot change anything, create tokens or read stored credentials. Connection logs name folders and subjects, and the token audit log records who read which account.',
                pairs: pairsOf(MCP_SCOPES.manage, grant => grant.action === ACTION.READ)
            },
            {
                value: 'operate',
                label: 'Operate',
                hint: 'Also reconnect and add accounts, change settings, and manage OAuth2 applications, gateways and templates.',
                caveat: 'Settings changes take effect at once, including where webhooks are delivered, and reconfiguring an account or gateway can send its stored credential to a new host. It cannot delete anything, create tokens or read stored credentials.',
                pairs: pairsOf(MCP_SCOPES.manage, grant => grant.action !== ACTION.DESTRUCTIVE)
            },
            {
                value: 'administer',
                label: 'Administer',
                hint: 'Also delete accounts, applications, gateways and templates, revoke tokens and flush accounts.',
                caveat: 'Everything Operate allows, plus deletion. It still cannot create tokens or read stored credentials.',
                pairs: pairsOf(MCP_SCOPES.manage, () => true)
            }
        ]
    },
    mail: {
        scope: MCP_SCOPES.mail,
        label: 'Email access',
        lead: 'Through the mail tools the client will be able to',
        defaultLevel: 'none',
        none: {
            label: 'No mail access',
            hint: 'Recommended unless the client should read mail. Email content then flows into whatever model the connected client runs.'
        },
        levels: [
            {
                value: 'read',
                label: 'Read-only',
                hint: 'List, search and read mail - cannot send, delete or change anything.',
                caveat: 'It cannot send email, delete anything or change anything in the mailboxes.',
                pairs: pairsOf(MCP_SCOPES.mail, grant => grant.action === ACTION.READ)
            },
            {
                value: 'mail',
                label: 'Mail agent',
                hint: 'Read, organize, draft and send mail - everything except the delete tool.',
                caveat: 'Everything except the delete tool. Instructions inside received mail are a real prompt-injection risk once sending is granted.',
                pairs: pairsOf(MCP_SCOPES.mail, grant => grant.action !== ACTION.DESTRUCTIVE)
            },
            {
                value: 'full',
                label: 'Full access',
                hint: 'Every mail tool, including deleting messages.',
                caveat: 'Instructions inside received mail are a real prompt-injection risk once sending is granted.',
                pairs: pairsOf(MCP_SCOPES.mail, () => true)
            }
        ]
    }
};

// What each level's grants mean in plain words, and how the consent prompt colours it: the
// narrowest level of a section is information, every wider one a warning. Computed once at load
// onto the level itself, so a level cannot be offered without wording.
for (const section of Object.values(MCP_SECTIONS)) {
    section.levels.forEach((level, index) => {
        level.actions = humanGrantList([...new Set(level.pairs.map(grant => grant.action))], ACTION_LABELS);
        level.groups = humanGrantList([...new Set(level.pairs.map(grant => grant.group))], GROUP_LABELS);
        level.variant = index ? 'warning' : 'info';
    });
}

/**
 * The level record a section offers under a name, or null for `none` and for a name it does not
 * have. Callers that need to tell those two apart check the name first; declining is not a level.
 */
function mcpLevel(section, value) {
    return section.levels.find(level => level.value === value) || null;
}

/**
 * What a choice of levels mints: the scopes of the sections that were not declined, management
 * first, and the union of their pair lists as a permissions record.
 *
 * The single spelling for the three pages that mint an MCP token, so the same choice means the
 * same credential on all of them. An unknown level throws rather than minting something narrower
 * or wider than asked - the routes validate the level names against MCP_SECTIONS before calling
 * this, so a throw here is a page posting a vocabulary this table does not have.
 *
 * @param {Object} choice - a level per section key (`manage`, `mail`); absent or 'none' declines it
 * @returns {{scopes: Array<String>, permissions: {grants: Array}}} empty scopes when everything was declined
 */
function mcpGrantsFor(choice) {
    const scopes = [];
    const grants = [];
    const seen = new Set();

    for (const [key, section] of Object.entries(MCP_SECTIONS)) {
        const value = choice && choice[key];
        if (!value || value === 'none') {
            continue;
        }
        const level = mcpLevel(section, value);
        if (!level) {
            throw new Error(`Unknown ${key} access level: ${value}`);
        }
        scopes.push(section.scope);
        for (const grant of level.pairs) {
            const pairKey = grantKey(grant);
            if (!seen.has(pairKey)) {
                seen.add(pairKey);
                grants.push({ action: grant.action, group: grant.group });
            }
        }
    }

    return { scopes, permissions: { grants } };
}

/**
 * The level names a section's form control may post: its levels plus `none`. The one spelling
 * of the vocabulary the consent route validates against.
 */
function mcpLevelNames(section) {
    return ['none'].concat(section.levels.map(level => level.value));
}

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
            grantList: SURFACE_GRANTS[scope].map(grantKey).join(',')
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

// Phrases the two axes as something a person reads rather than as two labelled fields. An absent
// actions axis is not a restriction, so it is left out of the sentence entirely - saying "every
// action" would imply a grant the record does not make. (An absent groups axis IS one, and arrives
// here already labelled by what it leaves out.)
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
        return coversAllActions && coversAllGroups ? 'Full access, except creating tokens and reading credentials' : `${verb} in ${where}`;
    }
    if (verb) {
        return coversAllActions ? 'Full access' : `${verb} only`;
    }
    if (where) {
        return coversAllGroups ? 'Every section' : `Limited to ${where}`;
    }
    return 'Restricted';
}

// An axis as labels: null for an absent axis (not a restriction), 'none' for an empty allowlist
// (which allows nothing, the opposite of absent), otherwise the labels in the record's order
const labelAxis = (values, labels) => {
    if (!Array.isArray(values)) {
        return null;
    }
    if (!values.length) {
        return 'none';
    }
    return mapLabels(values, labels).join(', ');
};

const coversAll = (values, whole) => Array.isArray(values) && values.length === whole.length && whole.every(entry => values.includes(entry));

/**
 * One-line description of what a stored `permissions` record allows, for the token list.
 *
 * @param {*} permissions - the record's `permissions` field
 * @returns {Object|null} { actions, groups, sentence, unreadable } or null when the token is not narrowed
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

    if (!Array.isArray(permissions.grants)) {
        // The two-axis form, read out as written rather than through effectiveGrants(): an absent
        // actions axis is not a restriction and stays out of the sentence, and an absent groups
        // axis is what the enforcement makes of it, named by what it leaves out
        const actions = labelAxis(permissions.actions, ACTION_LABELS);
        const groups = labelAxis(permissions.groups, GROUP_LABELS) ?? IMPLICIT_GROUPS_LABEL;

        return {
            actions,
            groups,
            // One line a person can read, rather than two labelled fragments. "Can: Read / In:
            // Messages" is the record read out loud; this is what the record means.
            sentence: sentenceFor(actions, groups, coversAll(permissions.actions, Object.values(ACTION)), coversAll(permissions.groups, GRANTABLE_GROUPS)),
            unreadable: false
        };
    }

    // The pair-list form, through the reader the enforcement shares. A list that happens to be a
    // full cross product is the two-axis record in another spelling and gets that record's
    // sentence; anything else is described section by section, in declaration order rather than
    // list order so two records granting the same pairs read the same however they were written,
    // because "read on Messages, write on Templates" is the shape the form exists for and it has
    // no two-axis sentence.
    const grants = tokenPermissions.effectiveGrants(permissions);
    const actionOrder = Object.values(ACTION);
    const actions = actionOrder.filter(action => grants.some(grant => grant.action === action));
    const groups = Object.values(GROUP).filter(group => grants.some(grant => grant.group === group));

    const summary = {
        actions: labelAxis(actions, ACTION_LABELS),
        groups: labelAxis(groups, GROUP_LABELS),
        unreadable: false
    };

    if (!grants.length || grants.length === actions.length * groups.length) {
        summary.sentence = sentenceFor(summary.actions, summary.groups, coversAll(actions, actionOrder), coversAll(groups, GRANTABLE_GROUPS));
        return summary;
    }

    summary.sentence = groups
        .map(group => {
            const granted = actions.filter(action => grants.some(grant => grant.action === action && grant.group === group));
            return `${mapLabels([group], GROUP_LABELS)[0]}: ${humanGrantList(granted, ACTION_LABELS)}`;
        })
        .join('; ');

    return summary;
}

module.exports = {
    formModel,
    summarize,
    ACTION_LABELS,
    GROUP_LABELS,
    MCP_SECTIONS,
    mcpLevel,
    mcpLevelNames,
    mcpGrantsFor
};
