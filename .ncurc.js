module.exports = {
    upgrade: true,
    reject: [
        // v3 is ESM only. Node 18+ support native fetch so no reason to upgrade
        'node-fetch'
    ]
};
