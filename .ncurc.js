module.exports = {
    upgrade: true,
    reject: [
        // Block package upgrades that moved to ESM
        'nanoid',
        'gettext-parser',
        'xgettext-template',
        'chai',
        'js-beautify',
        'ical.js',
        '@elastic/elasticsearch',

        'pino-pretty',

        // no support for Node 16
        'marked',

        // some kind of CVE in later versions. Only needed for license reference, so the actual version does not matter anyway
        'startbootstrap-sb-admin-2',

        // Keep joi at version 17.x for hapi-swagger compatibility
        'joi'
    ]
};
