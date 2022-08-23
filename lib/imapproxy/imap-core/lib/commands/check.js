'use strict';

module.exports = {
    state: ['Selected'],
    handler(command, callback) {
        callback(null, {
            response: 'OK'
        });
    }
};
