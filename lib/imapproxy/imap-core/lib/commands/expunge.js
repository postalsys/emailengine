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

        // Do nothing if in read only mode
        if (this.selected.readOnly) {
            return callback(null, {
                response: 'OK'
            });
        }

        if (this.session.commandCounters[command.command.toUpperCase().trim()] > 1000) {
            this.session.selected = this.selected = false;
            this.state = 'Logout';

            this.clearNotificationListener();
            this.send(`* BYE Too many ${command.command.toUpperCase().trim()} commands issued, please reconnect`);
            return setImmediate(() => this.close());
        }

        let logdata = {
            short_message: '[EXPUNGE]',
            _mail_action: 'expunge',
            _mailbox: this.selected.mailbox,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        this._server.onExpunge(
            this.selected.mailbox,
            {
                isUid: false
            },
            this.session,
            (err, success) => {
                if (err) {
                    logdata._error = err.message;
                    logdata._code = err.code;
                    logdata._response = err.response;
                    this._server.loggelf(logdata);
                    // do not return actual error to user
                    return callback(null, {
                        response: 'NO',
                        code: 'TEMPFAIL'
                    });
                }

                logdata._response = success;
                //this._server.loggelf(logdata);

                callback(null, {
                    response: success === true ? 'OK' : 'NO',
                    code: typeof success === 'string' ? success.toUpperCase() : false
                });
            }
        );
    }
};
