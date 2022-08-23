'use strict';

module.exports = {
    state: 'Selected',

    handler(command, callback) {
        this.session.selected = this.selected = false;
        this.state = 'Authenticated';

        callback(null, {
            response: 'OK'
        });
    }
};
