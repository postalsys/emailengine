'use strict';

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'quotaroot',
            type: 'string'
        },
        {
            name: 'limits',
            type: 'array'
        }
    ],

    handler(command, callback) {
        callback(null, {
            response: 'NO',
            code: 'CANNOT',
            message: 'Permission denied.'
        });
    }
};
