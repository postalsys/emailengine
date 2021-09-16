module.exports = {
    upgrade: true,
    reject: [
        // v3 is ESM only
        'node-fetch',
        // Documentation required to use linkify-html package for latest versions but the package was not found.
        // Remove once resolved
        'linkifyjs'
    ]
};
