'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    handler(command, callback) {
        imapTools.sendCapabilityResponse(this);

        callback(null, {
            response: 'OK'
        });
    }
};
