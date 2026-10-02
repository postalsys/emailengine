'use strict';

// The special-use folder overrides of an IMAP account (sent, drafts, junk, trash, archive).
//
// The IMAP client reads them as one uniform set - a loop over the types builds the specialUseHints it
// passes to LIST - but the admin edit form offered only sentMailPath, so the other four were settable
// over PUT /v1/account/{account} alone. Four places have to agree on the set now, and all four derive
// it from SPECIAL_USE_PATH_TYPES in lib/consts.js rather than repeating it: the account schemas, the
// edit form's own validation schema, the update loop, and the two templates.
//
// Pure filesystem read plus the schema modules - no Redis, no server. The write behavior is exercised
// against the real handler in test/ui-routes-handlers-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { imapSchema, imapUpdateSchema } = require('../lib/schemas');
const { SPECIAL_USE_PATH_TYPES } = require('../lib/consts');

const ROOT = pathlib.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(pathlib.join(ROOT, ...parts), 'utf-8');

const EXPECTED = SPECIAL_USE_PATH_TYPES.map(type => `${type}MailPath`);

test('the special-use folder overrides are offered everywhere they apply', async t => {
    await t.test('the shared list is the five the account stores', () => {
        assert.deepEqual(EXPECTED, ['sentMailPath', 'draftsMailPath', 'junkMailPath', 'trashMailPath', 'archiveMailPath']);
    });

    await t.test('the IMAP client derives its hints from the shared list', () => {
        // Rather than from a copy of the names. The client's loop is what makes an override take
        // effect, so a type the form offers and the client does not read would do nothing at all.
        const client = read('lib', 'email-client', 'imap-client.js');
        assert.match(client, /for \(let type of SPECIAL_USE_PATH_TYPES\)/);
        assert.match(client, /accountData\.imap\[`\$\{type\}MailPath`\]/);
    });

    await t.test('the account schemas declare every one', () => {
        for (const key of EXPECTED) {
            assert.ok(imapSchema[key], `imapSchema is missing ${key}`);
            assert.ok(imapUpdateSchema[key], `imapUpdateSchema is missing ${key}`);
        }
    });

    await t.test('the UI field table is derived from the shared list, and labels every type', () => {
        // Imported rather than scraped: the module is pure, so the shape the templates and the schema
        // consume can simply be asserted
        const { SPECIAL_USE_PATH_FIELDS, SPECIAL_USE_PATH_LABELS } = require('../lib/ui-routes/special-use-paths');

        assert.deepEqual(
            SPECIAL_USE_PATH_FIELDS.map(field => field.type),
            SPECIAL_USE_PATH_TYPES,
            'the table carries the shared list, in order'
        );

        for (const field of SPECIAL_USE_PATH_FIELDS) {
            assert.equal(field.key, `${field.type}MailPath`, 'the account field name');
            assert.equal(field.inputId, `imap_${field.key}`, 'the form input id');
            // A type with no words renders an unlabelled input
            assert.ok(field.label, `${field.type} has no label`);
            assert.ok(field.description, `${field.type} has no description`);
        }

        assert.deepEqual(Object.keys(SPECIAL_USE_PATH_LABELS).sort(), [...SPECIAL_USE_PATH_TYPES].sort(), 'no label for a type that does not exist');
    });

    await t.test('both templates render the list rather than naming the fields', () => {
        // Five hand-written blocks per template is how four of the five came to be missing from one
        for (const [view, file] of [
            ['the edit form', ['views', 'accounts', 'edit.hbs']],
            ['the account page', ['views', 'accounts', 'account.hbs']]
        ]) {
            const template = read(...file);
            assert.match(template, /\{\{#each specialUsePathFields\}\}/, `${view} does not iterate the list`);
            assert.ok(!/MailPath/.test(template), `${view} still names a field by hand`);
        }
    });

    await t.test('every render of those templates is handed the list', () => {
        // A render that forgets it shows no overrides at all, and the form would lose five inputs
        const routes = read('lib', 'ui-routes', 'account-routes.js');
        const renders = [...routes.matchAll(/'accounts\/(edit|account)',/g)];
        assert.ok(renders.length >= 4, `expected every accounts/edit and accounts/account render, found ${renders.length}`);
        for (const render of renders) {
            // The context object follows the view name; a generous window rather than a brace match,
            // which would couple this test to the formatting of a handler it only has to count
            const context = routes.slice(render.index, render.index + 900);
            assert.match(context, /specialUsePathFields/, `the accounts/${render[1]} render at offset ${render.index} is missing the list`);
        }
    });
});
