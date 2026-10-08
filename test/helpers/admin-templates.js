'use strict';

// A Handlebars environment with the admin view helpers and every partial registered, for tests that
// render the real templates. Its own environment rather than the require('handlebars') singleton,
// so registering ~45 partials here cannot reach another test file.

const fs = require('node:fs');
const pathlib = require('node:path');
const handlebars = require('handlebars');

const { listFiles } = require('./list-files');
const { registerHandlebarsHelpers } = require('../../lib/handlebars-helpers');

const VIEWS_DIR = pathlib.join(__dirname, '..', '..', 'views');
const PARTIALS_DIR = pathlib.join(VIEWS_DIR, 'partials');

const hbs = handlebars.create();
registerHandlebarsHelpers(hbs, { gt: { gettext: s => s, ngettext: (a, b, n) => (n === 1 ? a : b) } });

for (const file of listFiles(PARTIALS_DIR, '.hbs')) {
    const name = pathlib
        .relative(PARTIALS_DIR, file)
        .replace(/\.hbs$/, '')
        .split(pathlib.sep)
        .join('/');
    hbs.registerPartial(name, fs.readFileSync(file, 'utf-8'));
}

/**
 * @param {string} view - template path relative to views/, e.g. 'partials/oauth_form.hbs'
 * @returns {Function} the compiled template
 */
function compileView(view) {
    return hbs.compile(fs.readFileSync(pathlib.join(VIEWS_DIR, view), 'utf-8'));
}

module.exports = { compileView };
