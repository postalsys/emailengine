'use strict';

// Tests for the admin-UI presentation of the permission vocabulary.
//
// The point of most of these is coverage: the labels are a second spelling of the two enums, so a
// group added to lib/api-routes/permission-map.js without a label here would render as a blank
// checkbox that posts a value, and one removed would leave a control the API refuses.

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { formModel, summarize, ACTION_LABELS, GROUP_LABELS } = require('../lib/token-permission-view');
const { ACTION, GRANTABLE_GROUPS, GROUP } = require('../lib/api-routes/permission-map');

describe('token permission view', () => {
    describe('formModel', () => {
        const model = formModel();

        it('offers every action and every grantable group, and nothing else', () => {
            assert.deepEqual(model.permissionActions.map(entry => entry.value).sort(), Object.values(ACTION).sort());
            assert.deepEqual(model.permissionGroups.map(entry => entry.value).sort(), [...GRANTABLE_GROUPS].sort());
        });

        it('never offers the admin group', () => {
            // It can never be granted, so a control for it would be a checkbox that does nothing
            assert.ok(!model.permissionGroups.some(entry => entry.value === GROUP.ADMIN));
        });

        it('gives every control a label, a description and a unique id', () => {
            // Object.hasOwn rather than a truthiness check on the rendered label: formModel() falls
            // back to the slug, so a missing label would still produce a non-empty string and this
            // assertion could never fail
            for (const entry of model.permissionActions) {
                assert.ok(Object.hasOwn(ACTION_LABELS, entry.value), `${entry.value} has no label`);
            }
            for (const entry of model.permissionGroups) {
                assert.ok(Object.hasOwn(GROUP_LABELS, entry.value), `${entry.value} has no label`);
            }

            const ids = new Set();
            for (const entry of [...model.permissionActions, ...model.permissionGroups]) {
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

        it('says "none" for an empty allowlist', () => {
            // Grants nothing, and the list has to show that rather than imply no restriction
            assert.equal(summarize({ actions: [] }).actions, 'none');
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

        it('does not read a label off the object prototype', () => {
            // Same hazard the parse guards with Object.hasOwn. Only reachable through a record the
            // schema never saw, and the output is escaped, but a slug should never resolve to an
            // Object.prototype member.
            const summary = summarize({ groups: ['message'] });
            assert.equal(summary.groups, GROUP_LABELS.message);
        });
    });
});
