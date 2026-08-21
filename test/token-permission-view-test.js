'use strict';

// Tests for the admin-UI presentation of the permission vocabulary.
//
// The point of most of these is coverage: the labels are a second spelling of the two enums, so a
// group added to lib/api-routes/permission-map.js without a label here would render as a blank
// checkbox that posts a value, and one removed would leave a control the API refuses.

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const {
    formModel,
    summarize,
    ACTION_LABELS,
    GROUP_LABELS,
    MCP_READ_ONLY_PERMISSIONS,
    MCP_MAIL_AGENT_PERMISSIONS,
    MCP_ACCESS_LEVELS
} = require('../lib/token-permission-view');
const { ACTION, GRANTABLE_GROUPS, GROUP, SURFACE_GRANTS } = require('../lib/api-routes/permission-map');

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

    describe('MCP access levels', () => {
        const mcpGrants = SURFACE_GRANTS.mcp;

        it('offers exactly the three levels the consent page and generator present', () => {
            assert.deepEqual(Object.keys(MCP_ACCESS_LEVELS).sort(), ['full', 'mail', 'read']);
            assert.equal(MCP_ACCESS_LEVELS.read, MCP_READ_ONLY_PERMISSIONS);
            assert.equal(MCP_ACCESS_LEVELS.mail, MCP_MAIL_AGENT_PERMISSIONS);
            assert.equal(MCP_ACCESS_LEVELS.full, null, 'full access is the absence of a permissions record');
        });

        it('keeps the read-only level to the surface read grants and nothing else', () => {
            // [...] copies before sorting: .sort() in place would reorder the exported record
            // itself, which other suites deepEqual against minted token records
            assert.deepEqual(MCP_READ_ONLY_PERMISSIONS.actions, [ACTION.READ]);
            assert.deepEqual(
                [...MCP_READ_ONLY_PERMISSIONS.groups].sort(),
                [...new Set(mcpGrants.filter(grant => grant.action === ACTION.READ).map(grant => grant.group))].sort()
            );
        });

        it('gives the mail-agent level everything but the destructive action', () => {
            // Derived from the same table the enforcement reads: a destructive grant added to
            // the surface must never leak into this level, and a new non-destructive action
            // must appear in it without anyone remembering to copy it here
            const nonDestructive = mcpGrants.filter(grant => grant.action !== ACTION.DESTRUCTIVE);
            assert.deepEqual([...MCP_MAIL_AGENT_PERMISSIONS.actions].sort(), [...new Set(nonDestructive.map(grant => grant.action))].sort());
            assert.deepEqual([...MCP_MAIL_AGENT_PERMISSIONS.groups].sort(), [...new Set(nonDestructive.map(grant => grant.group))].sort());
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
    });
});
