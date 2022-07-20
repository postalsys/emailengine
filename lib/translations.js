'use strict';

const fs = require('fs').promises;
const Path = require('path');
const Gettext = require('node-gettext');
const { mo } = require('gettext-parser');
const locales = require('../translations/locales.json');

const translationsDir = Path.join(__dirname, '..', 'translations');
const domain = 'messages';

const gt = new Gettext();

async function loadTranslations() {
    for (let locale of locales) {
        let fContent = await fs.readFile(Path.join(translationsDir, locale.file || `${locale.locale}.mo`));
        let parsedTranslations = mo.parse(fContent);
        gt.addTranslations(locale.locale, domain, parsedTranslations);
    }
}

module.exports = { loadTranslations, gt, locales };
