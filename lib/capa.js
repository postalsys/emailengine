'use strict';

const fs = require('fs').promises;
const Path = require('path');

// Capability listing source:
// https://www.iana.org/assignments/imap-capabilities/imap-capabilities-1.csv
// https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xhtml

let cachedValues;
let urlMap = new Map([
    ['draft-ietf-morg-inthread', 'https://datatracker.ietf.org/doc/html/draft-ietf-morg-inthread'],
    ['gmail-xlist', 'https://developers.google.com/gmail/imap/imap-extensions#xlist_is_deprecated'],
    ['gmail-ext-1', 'https://developers.google.com/gmail/imap/imap-extensions'],
    ['xapplepushservice', 'https://opensource.apple.com/source/dovecot/dovecot-293/dovecot/src/imap/cmd-x-apple-push-service.c.auto.html'],
    ['draft-ietf-extra-imap-messagelimit', 'https://datatracker.ietf.org/doc/html/draft-ietf-extra-imap-messagelimit'],
    ['draft-melnikov-imap-uidonly', 'https://datatracker.ietf.org/doc/html/draft-melnikov-imap-uidonly'],
    ['draft-ietf-extra-imap-partial', 'https://datatracker.ietf.org/doc/html/draft-ietf-extra-imap-partial'],
    ['draft-slusarz-imap-fetch-snippet', 'https://datatracker.ietf.org/doc/html/draft-slusarz-imap-fetch-snippet'],
    ['xoauth', 'https://developers.google.com/gmail/imap/xoauth2-protocol#the_sasl_xoauth2_mechanism'],
    ['rfc3501-login', 'https://www.rfc-editor.org/rfc/rfc3501#section-6.2.3'],
    ['RFC7628', 'https://www.rfc-editor.org/rfc/rfc7628.html']
]);

const reload = async () => {
    if (cachedValues) {
        return cachedValues;
    }

    let data = await fs.readFile(Path.join(__dirname, '..', 'static', 'imap-capabilities-1.csv'), 'utf-8');
    cachedValues = new Map(
        data
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line)
            .slice(1)
            .map(line => {
                let splitterPos = line.indexOf(',');
                let key = line
                    .substring(0, splitterPos)
                    .replace(/\([^)]*\)/g, '')
                    .trim();
                let matches = (line.substring(splitterPos + 1).match(/\[RFC[\d]+\]/g) || []).map(val => val.replace(/[[\]]/g, '').trim());
                if (matches.length > 1 && matches[matches.length - 1] === 'RFC9051') {
                    // prefer non-rev2 RFCs
                    matches.pop();
                }
                return [key, (matches.pop() || '').toString()];
            })
    );

    cachedValues.set('THREAD=REFS', 'draft-ietf-morg-inthread');
    cachedValues.set('SEARCH=INTHREAD', 'draft-ietf-morg-inthread');
    cachedValues.set('XLIST', 'gmail-xlist');
    cachedValues.set('X-GM-EXT-1', 'gmail-ext-1');
    cachedValues.set('XAPPLEPUSHSERVICE', 'xapplepushservice');
    cachedValues.set('MESSAGELIMIT', 'draft-ietf-extra-imap-messagelimit');
    cachedValues.set('UIDONLY', 'draft-melnikov-imap-uidonly');
    cachedValues.set('PARTIAL', 'draft-ietf-extra-imap-partial');
    cachedValues.set('SNIPPET=FUZZY', 'draft-slusarz-imap-fetch-snippet');

    cachedValues.set('AUTH=XOAUTH2', 'xoauth');
    cachedValues.set('AUTH=XOAUTH', 'xoauth');
    cachedValues.set('AUTH=OAUTHBEARER', 'RFC7628');

    cachedValues.set('LOGIN', 'rfc3501-login');

    return cachedValues;
};

const getCapabilityEntries = async (capabilities, lastUsed) => {
    let capabilityMap = await reload();

    let response = [];
    for (let capability of capabilities) {
        let cKey = capability.trim().toUpperCase();
        let qKey = cKey.split('=').shift();
        if (capabilityMap.has(cKey) || capabilityMap.has(qKey) || capabilityMap.has(`${qKey}=`)) {
            let rfc = capabilityMap.get(cKey) || capabilityMap.get(qKey) || capabilityMap.get(`${qKey}=`);
            response.push({
                capability,
                rfc,
                url: urlMap.has(rfc) ? urlMap.get(rfc) : `https://www.rfc-editor.org/rfc/${rfc.toLowerCase().trim()}`,
                lastUsed: lastUsed === capability
            });
        } else {
            response.push({
                capability,
                lastUsed: lastUsed === capability
            });
        }
    }

    return response;
};

module.exports = getCapabilityEntries;
