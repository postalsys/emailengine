'use strict';

// Tests for the admin-UI presentation of the permission vocabulary.
//
// The point of most of these is coverage: the labels are a second spelling of the two enums, so a
// group added to lib/api-routes/permission-map.js without a label here would render as a blank
// checkbox that posts a value, and one removed would leave a control the API refuses.

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { formModel, summarize, ACTION_LABELS, GROUP_LABELS, MCP_SECTIONS, mcpGrantsFor } = require('../lib/token-permission-view');
const { ACTION, GRANTABLE_GROUPS, GROUP, SURFACE_GRANTS } = require('../lib/api-routes/permission-map');
const tokenPermissions = require('../lib/token-permissions');

describe('token permission view', () => {
    describe('formModel', () => {
        const model = formModel();
        const clusteredGroups = model.permissionGroupClusters.flatMap(cluster => cluster.groups);

        it('offers every action and every grantable group, and nothing else', () => {
            assert.deepEqual(model.permissionActions.map(entry => entry.value).sort(), Object.values(ACTION).sort());
            // Clustered for the form, so a group added without a cluster would simply not render -
            // an option silently missing from the UI while the API still accepts it
            assert.deepEqual(clusteredGroups.map(entry => entry.value).sort(), [...GRANTABLE_GROUPS].sort());
        });

        it('puts each group in exactly one cluster', () => {
            const seen = clusteredGroups.map(entry => entry.value);
            assert.equal(new Set(seen).size, seen.length, 'a group appears in more than one cluster');
            assert.ok(model.permissionGroupClusters.every(cluster => cluster.label && cluster.groups.length));
        });

        it('never offers the admin group', () => {
            // It can never be granted, so a control for it would be a checkbox that does nothing
            assert.ok(!clusteredGroups.some(entry => entry.value === GROUP.ADMIN));
        });

        it('gives every control a label, a description and a unique id', () => {
            // Object.hasOwn rather than a truthiness check on the rendered label: formModel() falls
            // back to the slug, so a missing label would still produce a non-empty string and this
            // assertion could never fail
            for (const entry of model.permissionActions) {
                assert.ok(Object.hasOwn(ACTION_LABELS, entry.value), `${entry.value} has no label`);
            }
            for (const entry of clusteredGroups) {
                assert.ok(Object.hasOwn(GROUP_LABELS, entry.value), `${entry.value} has no label`);
            }

            const ids = new Set();
            for (const entry of [...model.permissionActions, ...clusteredGroups]) {
                assert.ok(entry.label, `${entry.value} has no label`);
                assert.ok(entry.description, `${entry.value} has no description`);
                assert.ok(!ids.has(entry.inputId), `duplicate control id ${entry.inputId}`);
                ids.add(entry.inputId);
            }
        });

        it('only offers presets that name values the API would accept', () => {
            // A preset naming a retired slug would tick a box that mints a token the API refuses
            for (const preset of model.permissionPresets) {
                assert.ok(preset.label && preset.title, 'a preset is missing its label or title');

                for (const action of preset.actionList.split(',')) {
                    assert.ok(Object.values(ACTION).includes(action), `preset "${preset.label}" names unknown action ${action}`);
                }
                for (const group of preset.groupList.split(',')) {
                    assert.ok(GRANTABLE_GROUPS.includes(group), `preset "${preset.label}" names ungrantable group ${group}`);
                }
            }
        });

        it('has a preset that grants everything grantable', () => {
            // The starting point for "narrow this a bit" rather than "build it up from nothing"
            const everything = model.permissionPresets.find(preset => preset.groupList.split(',').length === GRANTABLE_GROUPS.length);
            assert.ok(everything, 'no preset covers every grantable group');
            assert.deepEqual(everything.actionList.split(',').sort(), Object.values(ACTION).sort());
        });
    });

    describe('MCP access sections', () => {
        const key = grant => `${grant.action}:${grant.group}`;

        it('offers the two sections, management first, each bound to its scope', () => {
            assert.deepEqual(Object.keys(MCP_SECTIONS), ['manage', 'mail']);
            assert.equal(MCP_SECTIONS.manage.scope, 'mcp-manage');
            assert.equal(MCP_SECTIONS.mail.scope, 'mcp');
            // The defaults the pages start from: observe the instance, no mail
            assert.equal(MCP_SECTIONS.manage.defaultLevel, 'observe');
            assert.ok(MCP_SECTIONS.mail.toggle, 'the mail section is behind a toggle');
        });

        it('derives every level from the surface table of its scope, and nothing else', () => {
            // A grant added to a surface must reach the level it belongs to without anyone
            // copying it here, and a level must never name a pair its scope does not admit
            for (const section of Object.values(MCP_SECTIONS)) {
                const table = new Set(SURFACE_GRANTS[section.scope].map(key));
                assert.deepEqual(section.levels.none, []);
                for (const [level, pairs] of Object.entries(section.levels)) {
                    for (const grant of pairs) {
                        assert.ok(table.has(key(grant)), `${section.scope} level ${level} names ${key(grant)}, which the surface does not admit`);
                    }
                }
                // and the widest level is the whole table
                const widest = section.levels[Object.keys(section.levels).at(-1)];
                assert.deepEqual(widest.map(key).sort(), [...table].sort());
            }

            const reads = pairs => pairs.every(grant => grant.action === ACTION.READ);
            assert.ok(reads(MCP_SECTIONS.manage.levels.observe) && MCP_SECTIONS.manage.levels.observe.length);
            assert.ok(reads(MCP_SECTIONS.mail.levels.read) && MCP_SECTIONS.mail.levels.read.length);
            assert.ok(!MCP_SECTIONS.manage.levels.operate.some(grant => grant.action === ACTION.DESTRUCTIVE));
            assert.ok(!MCP_SECTIONS.mail.levels.mail.some(grant => grant.action === ACTION.DESTRUCTIVE));
            assert.ok(
                MCP_SECTIONS.mail.levels.mail.some(grant => grant.action === ACTION.SEND),
                'the mail agent level sends'
            );
        });

        it('offers every level with wording and the pair keys the pages count against', () => {
            for (const section of Object.values(MCP_SECTIONS)) {
                const offered = section.options.map(option => option.value);
                assert.deepEqual(
                    offered.sort(),
                    Object.keys(section.levels)
                        .filter(level => level !== 'none')
                        .sort(),
                    `${section.scope} offers levels its table does not have, or hides some`
                );
                for (const option of section.options) {
                    assert.ok(option.label && option.hint && option.caveat, `${option.value} lacks wording`);
                    assert.ok(option.actions && option.groups, `${option.value} lacks grant wording`);
                    assert.deepEqual(option.grants, section.levels[option.value].map(key));
                }
            }
            assert.equal(MCP_SECTIONS.manage.noneOption.value, 'none');
        });
    });

    describe('mcpGrantsFor', () => {
        it('mints the scopes of the sections not declined, management first, and the union of their pairs', () => {
            const both = mcpGrantsFor({ manage: 'operate', mail: 'read' });
            assert.deepEqual(both.scopes, ['mcp-manage', 'mcp']);

            const keys = both.permissions.grants.map(grant => `${grant.action}:${grant.group}`);
            assert.ok(keys.includes(`write:${GROUP.SETTINGS}`));
            assert.ok(keys.includes(`read:${GROUP.MESSAGE}`));
            // the point of the pair form: the management write does not leak onto the messages
            assert.ok(!keys.includes(`write:${GROUP.MESSAGE}`));
            // and a pair both sections grant appears once
            assert.equal(keys.filter(entry => entry === `read:${GROUP.ACCOUNT}`).length, 1);

            // what check() makes of the minted record agrees
            const tokenData = { permissions: both.permissions };
            assert.ok(tokenPermissions.check({ tokenData, operation: { action: ACTION.WRITE, group: GROUP.SETTINGS } }).allowed);
            assert.ok(tokenPermissions.check({ tokenData, operation: { action: ACTION.READ, group: GROUP.MESSAGE } }).allowed);
            assert.ok(!tokenPermissions.check({ tokenData, operation: { action: ACTION.WRITE, group: GROUP.MESSAGE } }).allowed);
        });

        it('mints one scope for one section, and no scope when everything is declined', () => {
            assert.deepEqual(mcpGrantsFor({ manage: 'none', mail: 'full' }).scopes, ['mcp']);
            assert.deepEqual(mcpGrantsFor({ manage: 'observe' }).scopes, ['mcp-manage']);
            assert.deepEqual(mcpGrantsFor({ manage: 'none', mail: 'none' }), { scopes: [], permissions: { grants: [] } });
            assert.deepEqual(mcpGrantsFor({}).scopes, []);
        });

        it('always mints an explicit pair list, even for the widest choice', () => {
            // A consent given for the tools of today must not grow to include a tool shipped next
            // release, which is what an absent record would do
            const widest = mcpGrantsFor({ manage: 'administer', mail: 'full' });
            assert.ok(Array.isArray(widest.permissions.grants) && widest.permissions.grants.length);
            assert.ok(tokenPermissions.inspect({ permissions: widest.permissions }).narrowed);
        });

        it('refuses a level the table does not have rather than guessing', () => {
            assert.throws(() => mcpGrantsFor({ manage: 'root' }), /Unknown manage access level/);
            assert.throws(() => mcpGrantsFor({ mail: 'everything' }), /Unknown mail access level/);
        });
    });

    describe('summarize', () => {
        it('reports an un-narrowed token as nothing to show', () => {
            // The list must not label a normal token as restricted
            assert.equal(summarize(undefined), null);
            assert.equal(summarize(null), null);
        });

        it('names both axes in human terms', () => {
            const summary = summarize({ actions: [ACTION.READ], groups: ['message'] });
            assert.equal(summary.actions, ACTION_LABELS[ACTION.READ]);
            assert.equal(summary.groups, GROUP_LABELS.message);
            assert.equal(summary.unreadable, false);
        });

        it('leaves an absent axis out rather than calling it empty', () => {
            // Absent means "not narrowed on this axis", which is the opposite of an empty allowlist
            const summary = summarize({ groups: ['message'] });
            assert.equal(summary.actions, null);
            assert.equal(summary.groups, GROUP_LABELS.message);
        });

        it('says plainly that an empty allowlist allows nothing', () => {
            // Grants nothing, so the token authenticates and then refuses every request. The listing
            // has to say that rather than imply a working narrow credential.
            assert.equal(summarize({ actions: [] }).actions, 'none');
            assert.match(summarize({ actions: [] }).sentence, /cannot make any request/);
            assert.match(summarize({ groups: [] }).sentence, /cannot make any request/);
        });

        it('collapses an axis that names everything instead of enumerating it', () => {
            // Spelling out all thirteen sections made a line long enough to push the table sideways,
            // and it read as a detailed restriction when it is the opposite - what such a token
            // still cannot reach is the interesting part.
            const everything = summarize({ actions: [...Object.values(ACTION)], groups: [...GRANTABLE_GROUPS] });
            assert.match(everything.sentence, /^Full access, except/);
            assert.ok(!everything.sentence.includes('Suppression lists'), 'the section list was enumerated');

            assert.equal(summarize({ actions: ['read'], groups: [...GRANTABLE_GROUPS] }).sentence, 'Can read in every section');
            assert.equal(summarize({ actions: [...Object.values(ACTION)], groups: ['message'] }).sentence, 'Full access in Messages');
        });

        it('reads as a sentence rather than as two labelled fields', () => {
            assert.equal(summarize({ actions: ['read'], groups: ['message', 'mailbox'] }).sentence, 'Can read in Messages, Folders');
            // An absent axis is not a restriction, so it is left out entirely - "all sections" would
            // imply a grant the record does not make
            assert.equal(summarize({ actions: ['read'] }).sentence, 'Can read only');
            assert.equal(summarize({ groups: ['message'] }).sentence, 'Limited to Messages');
        });

        it('flags every record the enforcement refuses, not just the obviously broken ones', () => {
            // The verdict comes from lib/token-permissions.js rather than being re-derived here. A
            // view that only looked for a non-object rendered `{actions: ['bogus']}` as
            // "Restricted / Can: bogus" - a working narrow credential - when in fact every request
            // it makes is denied.
            for (const permissions of ['nonsense', 42, ['read'], {}, { foo: 1 }, { actions: ['bogus'] }, { actions: 'read' }]) {
                const summary = summarize(permissions);
                assert.equal(summary.unreadable, true, `${JSON.stringify(permissions)} was not flagged as unreadable`);
                assert.equal(summary.actions, null);
                assert.equal(summary.groups, null);
            }
        });

        it('reports a record naming only admin as it is, rather than as unreadable', () => {
            // admin is in the vocabulary on purpose, so a record naming it is well formed - it is
            // refused because nobody may hold it, which is a different answer from "I could not read
            // that". The listing shows what the record says and the request-time denial does the
            // rest; the schema refuses to issue one in the first place.
            const summary = summarize({ groups: ['admin'] });
            assert.equal(summary.unreadable, false);
            assert.equal(summary.groups, 'admin');
        });

        it('describes a pair list section by section', () => {
            // The shape the form exists for has no two-axis sentence, so each section says what it
            // allows, in declaration order rather than in the order the record happened to list
            const summary = summarize({
                grants: [
                    { action: ACTION.WRITE, group: GROUP.TEMPLATE },
                    { action: ACTION.READ, group: GROUP.MESSAGE },
                    { action: ACTION.READ, group: GROUP.TEMPLATE }
                ]
            });
            assert.equal(summary.unreadable, false);
            assert.equal(summary.sentence, `${GROUP_LABELS.message}: read; ${GROUP_LABELS.template}: read and create and modify`);
            assert.equal(summary.actions, `${ACTION_LABELS.read}, ${ACTION_LABELS.write}`);
            assert.equal(summary.groups, `${GROUP_LABELS.message}, ${GROUP_LABELS.template}`);
        });

        it('reads a pair list that is a full cross product the way it reads the two axes', () => {
            // The same record in another spelling should not get a longer sentence
            const grants = [];
            for (const action of [ACTION.READ, ACTION.WRITE]) {
                for (const group of [GROUP.MESSAGE, GROUP.MAILBOX]) {
                    grants.push({ action, group });
                }
            }
            // Groups in declaration order, which is what the pair form always renders in
            assert.equal(summarize({ grants }).sentence, summarize({ actions: [ACTION.READ, ACTION.WRITE], groups: [GROUP.MAILBOX, GROUP.MESSAGE] }).sentence);
            assert.equal(summarize({ grants: [{ action: ACTION.READ, group: GROUP.MESSAGE }] }).sentence, 'Can read in Messages');
        });

        it('says an empty pair list allows nothing', () => {
            assert.match(summarize({ grants: [] }).sentence, /cannot make any request/);
        });

        it('flags an unreadable pair list like any other unreadable record', () => {
            for (const permissions of [{ grants: 'read' }, { grants: [{ action: 'read' }] }, { grants: [], actions: ['read'] }]) {
                assert.equal(summarize(permissions).unreadable, true, `${JSON.stringify(permissions)} was not flagged`);
            }
        });
    });
});
