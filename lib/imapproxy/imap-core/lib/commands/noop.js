'use strict';

module.exports = {
    handler(command, callback) {
        callback(null, {
            response: 'OK',
            message: 'Nothing done'
        });
    }
};
