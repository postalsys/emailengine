'use strict';

// The five special-use folder overrides of an IMAP account (sent, drafts, junk, trash, archive).
//
// The IMAP client reads them as one uniform set - a loop over the five names builds the
// specialUseHints it passes to LIST - but the admin edit form offered only sentMailPath, so the other
// four were settable over PUT /v1/account/{account} alone. Four places have to name the same five now:
// the account schema, the form's own validation schema, the update loop that copies the submitted
// values onto the account, and the form markup.
//
// Pure filesystem read plus the schema modules - no Redis, no server. The route module is captured
// rather than booted, the templates are read as text.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { imapSchema, imapUpdateSchema } = require('../lib/schemas');

const ROOT = pathlib.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(pathlib.join(ROOT, ...parts), 'utf-8');

const ROUTES = read('lib', 'ui-routes', 'account-routes.js');
const EDIT_FORM = read('views', 'accounts', 'edit.hbs');
const ACCOUNT_PAGE = read('views', 'accounts', 'account.hbs');

// The names as the client consumes them, derived from the loop that builds the hints rather than
// listed again here: a sixth override added to the client has to reach the form too
const CLIENT_TYPES = (() => {
    const client = read('lib', 'email-client', 'imap-client.js');
    const loop = client.match(/for \(let type of (\[[^\]]*\])\) \{\s*\n\s*if \(accountData\.imap && accountData\.imap\[`\$\{type\}MailPath`\]\)/);
    assert.ok(loop, 'the specialUseHints loop was not found in imap-client.js');
    return JSON.parse(loop[1].replace(/'/g, '"'));
})();

const EXPECTED = CLIENT_TYPES.map(type => `${type}MailPath`);

test('the special-use folder overrides are offered everywhere they apply', async t => {
    await t.test('the client reads five of them', () => {
        assert.deepEqual(EXPECTED, ['sentMailPath', 'draftsMailPath', 'junkMailPath', 'trashMailPath', 'archiveMailPath']);
    });

    await t.test('the account schemas declare every one', () => {
        for (const key of EXPECTED) {
            assert.ok(imapSchema[key], `imapSchema is missing ${key}`);
            assert.ok(imapUpdateSchema[key], `imapUpdateSchema is missing ${key}`);
        }
    });

    await t.test('the route module names every one in one place', () => {
        const declared = [...ROUTES.matchAll(/\{ key: '([a-zA-Z]+MailPath)'/g)].map(match => match[1]);
        assert.deepEqual(declared, EXPECTED, 'SPECIAL_USE_PATH_FIELDS has to carry the client set, in order');

        // The update loop and the form schema both derive from that list rather than repeating it
        assert.match(ROUTES, /for \(let key of \['host', 'port', 'disabled', \.\.\.SPECIAL_USE_PATH_FIELDS\.map/);
        assert.match(ROUTES, /SPECIAL_USE_PATH_FIELDS\.map\(field => \[\s*`imap_\$\{field\.key\}`/);
    });

    await t.test('the edit form offers an input for every one', () => {
        for (const key of EXPECTED) {
            assert.match(EDIT_FORM, new RegExp(`id="imap_${key}"`), `the edit form is missing imap_${key}`);
            // The value and the error have to come from the matching key, or the field shows another
            // field's content - the kind of slip five near-identical lines invite
            assert.match(EDIT_FORM, new RegExp(`id="imap_${key}" [^\\n]*value=values\\.imap_${key} error=errors\\.imap_${key}`), `imap_${key} is wired wrong`);
        }
    });

    await t.test('the account page shows every one that is set', () => {
        for (const key of EXPECTED) {
            assert.match(ACCOUNT_PAGE, new RegExp(`\\{\\{#if account\\.imap\\.${key}\\}\\}`), `the account page is missing ${key}`);
            assert.match(ACCOUNT_PAGE, new RegExp(`<dd>\\{\\{account\\.imap\\.${key}\\}\\}</dd>`), `${key} is rendered from the wrong key`);
        }
    });
});
