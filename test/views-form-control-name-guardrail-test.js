'use strict';

// No form control may be named after a property of HTMLFormElement.
//
// A named control is exposed as a property of its form, and that lookup wins over the element's own
// properties: a `<input name="target">` makes `form.target` return the input rather than the string
// the form was declared with. The shared submit handler in static/js/ui.js reads both `method` and
// `target` on every POST form on the admin surface, so one such control does not break its own page
// alone - it throws inside a document-level listener and takes every busy button on that page with
// it. That is exactly how it was found: a hidden `name="target"` on the TLS page's delete form.
//
// The handlers read attributes now, so this is the second line rather than the only one. It stays
// because the collision has other victims (a control named `submit` breaks `form.submit()`, one
// named `elements` breaks any iteration over the controls) and because the failure is invisible
// until something reads the shadowed property.
//
// Pure: reads the templates, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');

const ROOT = pathlib.join(__dirname, '..');
const VIEWS = pathlib.join(ROOT, 'views');

// Properties of HTMLFormElement that first-party code reads, or that a browser API needs to work.
// Not the whole interface: `name` and `id` are shadowed harmlessly and are ordinary field names.
const RESERVED = ['action', 'method', 'target', 'submit', 'reset', 'elements', 'length', 'enctype', 'acceptCharset', 'noValidate'];

// Every name="..." on an input, select, textarea or button.
const CONTROL = /<(?:input|select|textarea|button)\b[^>]*?\bname\s*=\s*"([^"]+)"/gi;

test('no form control is named after an HTMLFormElement property', () => {
    const offenders = [];

    for (const file of listFiles(VIEWS, '.hbs')) {
        const source = fs.readFileSync(file, 'utf-8');

        let match;
        CONTROL.lastIndex = 0;
        while ((match = CONTROL.exec(source))) {
            const name = match[1].trim();
            if (!RESERVED.includes(name)) {
                continue;
            }
            const line = source.slice(0, match.index).split('\n').length;
            offenders.push(`${pathlib.relative(ROOT, file)}:${line} name="${name}"`);
        }
    }

    assert.deepEqual(
        offenders,
        [
            // The unsubscribe form posts which way the reader chose. `form.action` is never read by
            // first-party code, and renaming the field would break every unsubscribe link already
            // sitting in somebody's inbox.
            'views/unsubscribe.hbs:30 name="action"',
            'views/unsubscribe.hbs:66 name="action"'
        ],
        `these form controls shadow a property of their own form - rename the field:\n  ${offenders.join('\n  ')}`
    );
});
