'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: 'Not Authenticated',

    schema: [
        {
            name: 'username',
            type: 'string'
        },
        {
            name: 'password',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let username = Buffer.from((command.attributes[0].value || '').toString().trim(), 'binary').toString();
        let password = Buffer.from((command.attributes[1].value || '').toString().trim(), 'binary').toString();

        if (!this.secure && !this._server.options.disableSTARTTLS && !this._server.options.ignoreSTARTTLS) {
            // Only allow authentication using TLS
            return callback(null, {
                response: 'BAD',
                message: 'Run STARTTLS first'
            });
        }

        // Check if authentication method is set
        if (typeof this._server.onAuth !== 'function') {
            this._server.logger.info(
                {
                    tnx: 'auth',
                    username,
                    method: 'LOGIN',
                    action: 'fail',
                    cid: this.id
                },
                'Authentication failed for %s using %s',
                username,
                'LOGIN'
            );
            return callback(null, {
                response: 'NO',
                message: 'Authentication not implemented'
            });
        }

        // Do auth
        this._server.onAuth(
            {
                method: 'LOGIN',
                username,
                password,
                connection: this
            },
            this.session,
            (err, response) => {
                if (err) {
                    if (err.response) {
                        return callback(null, err);
                    }
                    this._server.logger.info(
                        {
                            err,
                            tnx: 'auth',
                            username,
                            method: 'LOGIN',
                            action: 'fail',
                            cid: this.id
                        },
                        'Authentication error for %s using %s: %s',
                        username,
                        'LOGIN',
                        err.message
                    );

                    return callback(null, {
                        response: 'NO',
                        code: 'TEMPFAIL'
                    });
                }

                if (!response || !response.user) {
                    this._server.logger.info(
                        {
                            tnx: 'auth',
                            username,
                            method: 'LOGIN',
                            action: 'fail',
                            cid: this.id
                        },
                        'Authentication failed for %s using %s',
                        username,
                        'LOGIN'
                    );
                    return callback(null, {
                        response: 'NO',
                        code: 'AUTHENTICATIONFAILED',
                        message: 'Invalid credentials'
                    });
                }

                this._server.logger.info(
                    {
                        tnx: 'auth',
                        username,
                        method: 'LOGIN',
                        action: 'success',
                        cid: this.id
                    },
                    '%s authenticated using %s',
                    username,
                    'LOGIN'
                );

                this.setUser(response.user);
                if (!this._server.options.proxyMode) {
                    this.state = 'Authenticated';
                    this.setupNotificationListener();
                    imapTools.sendCapabilityResponse(this);
                } else {
                    this.state = 'Proxy';
                }

                callback(null, {
                    response: 'OK',
                    message: Buffer.from(username + ' authenticated').toString('binary')
                });
            }
        );
    }
};
