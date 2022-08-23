'use strict';

module.exports = {
    state: 'Selected',

    handler(command, callback) {
        // Check if EXPUNGE method is set
        if (typeof this._server.onExpunge !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'EXPUNGE not implemented'
            });
        }

        // Just unselect if in read only mode
        if (this.selected.readOnly) {
            this.session.selected = this.selected = false;
            this.state = 'Authenticated';
            return callback(null, {
                response: 'OK'
            });
        }

        let mailbox = this.selected.mailbox;

        this.session.selected = this.selected = false;
        this.state = 'Authenticated';

        this._server.onExpunge(
            mailbox,
            {
                isUid: false,
                silent: true
            },
            this.session,
            () => {
                // don't care if expunging succeeded, the mailbox is now closed anyway
                callback(null, {
                    response: 'OK'
                });
            }
        );
    }
};
