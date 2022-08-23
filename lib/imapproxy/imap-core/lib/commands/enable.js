'use strict';

module.exports = {
    state: ['Authenticated'],
    schema: false,

    handler(command, callback) {
        let enabled = [];

        command.attributes.map(attr => {
            if (((attr && attr.value) || '').toString().toUpperCase() === 'CONDSTORE') {
                this.condstoreEnabled = true;
                enabled.push('CONDSTORE');
            }

            if (((attr && attr.value) || '').toString().toUpperCase() === 'UTF8=ACCEPT') {
                this.acceptUTF8Enabled = true;
                enabled.push('UTF8=ACCEPT');
            }
        });

        this.send('* ENABLED' + (enabled.length ? ' ' : '') + enabled.join(' '));

        let responseMessage = 'Extensions enabled';
        if (enabled.length === 1) {
            responseMessage = 'Extension enabled';
        } else if (!enabled.length) {
            responseMessage = 'Success';
        }

        callback(null, {
            response: 'OK',
            message: responseMessage
        });
    }
};
