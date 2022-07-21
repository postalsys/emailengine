'use strict';

const fs = require('fs').promises;
const Path = require('path');
const Gettext = require('node-gettext');
const { mo } = require('gettext-parser');
const logger = require('./logger');
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

const gt = new Gettext();

async function loadTranslations() {
    // Joi translations
    for (let joiLocale of joiLocaleKeys) {
        let localeObj;

        try {
            let fContent = await fs.readFile(Path.join(translationsDir, 'joi', `${joiLocale}.json`));
            localeObj = JSON.parse(fContent);
        } catch (err) {
            logger.error({ msg: 'Failed to load Joi locale', joiLocale, err });
            continue;
        }

        joiLocales[joiLocale] = unwrapLocale(localeObj);
        let language = joiLocale.split('_').shift();
        if (!joiLocales[language]) {
            joiLocales[language] = unwrapLocale(localeObj);
        }
    }

    // Gettext translations
    for (let locale of locales) {
        let fContent = await fs.readFile(Path.join(translationsDir, locale.file || `${locale.locale}.mo`));
        let parsedTranslations = mo.parse(fContent);
        gt.addTranslations(locale.locale, domain, parsedTranslations);
    }
}

module.exports = { loadTranslations, gt, locales, joiLocales };
