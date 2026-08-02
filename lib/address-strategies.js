'use strict';

// The local-address selection strategies, shared by the joi schemas (which use the keys as
// the allowed value set), the admin UI (which shows the titles), and lib/enum-descriptions.js
// (which documents each value in the API reference). One table so a new strategy cannot be
// half-added.

const ADDRESS_STRATEGIES = [
    { key: 'default', title: 'Default', description: 'Let the operating system pick the source address' },
    {
        key: 'dedicated',
        title: 'Dedicated',
        description: 'Reuse the same local address for an account, so the remote server sees a stable IP'
    },
    { key: 'random', title: 'Random', description: 'Pick a random local address for every connection' }
];

module.exports = { ADDRESS_STRATEGIES };
