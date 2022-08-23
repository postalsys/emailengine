'use strict';

module.exports = {
    state: ['Authenticated', 'Selected'],

    handler(command, callback) {
        // fixed structre
        this.send('* NAMESPACE (("" "/")) NIL NIL');

        callback(null, {
            response: 'OK'
        });
    }
};
