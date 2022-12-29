'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: 'Not Authenticated',

    schema: [
        {
            name: 'token',
            type: 'string',
            optional: true
        }
    ],

    handler(command, callback, next) {
        let token = ((command.attributes && command.attributes[0] && command.attributes[0].value) || '').toString().trim();

        let requireClientToken = (command.command || '').toString().toUpperCase() === 'AUTHENTICATE PLAIN-CLIENTTOKEN' ? true : false;

        if (!this.secure && !this._server.options.disableSTARTTLS && !this._server.options.ignoreSTARTTLS) {
            // Only allow authentication using TLS
            return callback(null, {
                response: 'BAD',
                message: 'Run STARTTLS first'
            });
        }

        // Check if authentication method is set
        if (typeof this._server.onAuth !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'Authentication not implemented'
            });
        }

        if (!token) {
            this._nextHandler = (token, next) => {
                this._nextHandler = false;
                next(); // keep the parser flowing
                authenticate(this, token, requireClientToken, callback);
            };
            this.send('+');
            return next(); // resume input parser. Normally this is done by callback() but we need the next input sooner
        }

        authenticate(this, token, requireClientToken, callback);
    }
};

function authenticate(connection, token, requireClientToken, callback) {
    let data = Buffer.from(token, 'base64').toString().split('\x00');

    if ((!requireClientToken && data.length !== 3) || (requireClientToken && data.length !== 4)) {
        return callback(null, {
            response: 'BAD',
            message: 'Invalid SASL argument'
        });
    }

    let username = (data[1] || '').toString().trim();
    let password = (data[2] || '').toString().trim();
    let clientToken = (data[3] || '').toString().trim() || false;

    // Do auth
    connection._server.onAuth(
        {
            method: 'PLAIN',
            username,
            password,
            clientToken,
            connection
        },
        connection.session,
        (err, response) => {
            if (err) {
                connection._server.logger.info(
                    {
                        err,
                        tnx: 'auth',
                        username,
                        method: 'PLAIN',
                        action: 'fail',
                        cid: connection.id
                    },
                    'Authentication error for %s using %s\n%s',
                    username,
                    'PLAIN',
                    err.message
                );
                return callback(err);
            }

            if (!response || !response.user) {
                connection._server.logger.info(
                    {
                        tnx: 'auth',
                        username,
                        method: 'PLAIN',
                        action: 'fail',
                        cid: connection.id
                    },
                    'Authentication failed for %s using %s',
                    username,
                    'PLAIN'
                );
                return callback(null, {
                    response: 'NO',
                    code: 'AUTHENTICATIONFAILED',
                    message: 'Invalid credentials'
                });
            }

            connection._server.logger.info(
                {
                    tnx: 'auth',
                    username,
                    method: 'PLAIN',
                    action: 'success',
                    cid: connection.id,
                    clientToken
                },
                '%s authenticated using %s%s',
                username,
                'PLAIN' + (requireClientToken ? '-CLIENTTOKEN' : ''),
                clientToken ? ' with token "' + clientToken + '"' : ''
            );

            connection.setUser(response.user);

            if (!connection._server.options.proxyMode) {
                connection.state = 'Authenticated';
                connection.setupNotificationListener();
                imapTools.sendCapabilityResponse(connection);
            } else {
                connection.state = 'Proxy';
            }

            callback(null, {
                response: 'OK',
                message: Buffer.from(username + ' authenticated').toString('binary')
            });
        }
    );
}
