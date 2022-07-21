/* eslint global-require: 0 */
'use strict';

const fs = require('fs').promises;
const Path = require('path');
const Gettext = require('node-gettext');
const { mo } = require('gettext-parser');
const locales = require('../translations/locales.json');

const translationsDir = Path.join(__dirname, '..', 'translations');
const domain = 'messages';

const joiLocales = {};

const joiLocaleKeys = ['de_DE', 'en_US', 'es_ES', 'fr_FR', 'pt_BR', 'ru_RU', 'tr_TR', 'et_EE'];

function unwrapLocale(localeObj) {
    let res = {};
    for (let key of Object.keys(localeObj)) {
        if (!localeObj[key] || typeof localeObj[key] !== 'object') {
            continue;
        }
        for (let subKey of Object.keys(localeObj[key])) {
            if (!localeObj[key][subKey] || typeof localeObj[key][subKey] !== 'string') {
                continue;
            }
            res[`${key}.${subKey}`] = localeObj[key][subKey].replace(/^./, c => c.toUpperCase());
        }
    }
    return res;
}

for (let joiLocale of joiLocaleKeys) {
    let localeObj;
    try {
        localeObj = require(`joi18n/locales/${joiLocale}.json`);
    } catch (err) {
        localeObj = require(`../translations/joi/${joiLocale}.json`);
    }
    joiLocales[joiLocale] = unwrapLocale(localeObj);
    let language = joiLocale.split('_').shift();
    if (!joiLocales[language]) {
        joiLocales[language] = unwrapLocale(localeObj);
    }
}

const gt = new Gettext();

async function loadTranslations() {
    for (let locale of locales) {
        let fContent = await fs.readFile(Path.join(translationsDir, locale.file || `${locale.locale}.mo`));
        let parsedTranslations = mo.parse(fContent);
        gt.addTranslations(locale.locale, domain, parsedTranslations);
    }
}

module.exports = { loadTranslations, gt, locales, joiLocales };
