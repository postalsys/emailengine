'use strict';

const fs = require('fs').promises;
const Path = require('path');
const Gettext = require('node-gettext');
const { mo } = require('gettext-parser');
const locales = require('../translations/locales.json');
const joiMessages = require('@postalsys/joi-messages');

const translationsDir = Path.join(__dirname, '..', 'translations');
const domain = 'messages';

const joiLocales = {};

const gt = new Gettext();

async function loadTranslations() {
    // Joi translations

    let joiMessageLocales = await joiMessages.messages();
    for (let joiLocale of Object.keys(joiMessageLocales)) {
        joiLocales[joiLocale] = joiMessageLocales[joiLocale];
    }

    // Gettext translations
    for (let locale of locales) {
        let fContent = await fs.readFile(Path.join(translationsDir, locale.file || `${locale.locale}.mo`));
        let parsedTranslations = mo.parse(fContent);
        gt.addTranslations(locale.locale, domain, parsedTranslations);
    }
}

module.exports = { loadTranslations, gt, locales, joiLocales };
