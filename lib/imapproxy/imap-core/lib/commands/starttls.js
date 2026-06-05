'use strict';

// openssl s_client -starttls imap -crlf -connect localhost:1143

const tls = require('tls');

const SOCKET_TIMEOUT = 30 * 60 * 1000;

module.exports = {
    handler(command, callback) {
        if (this.secure) {
            return callback(null, {
                response: 'NO',
                message: 'Connection is already secured'
            });
        }

        if (this._server.options.disableSTARTTLS) {
            // STARTTLS is not advertised in this mode (e.g. the EmailEngine proxy);
            // refuse it instead of upgrading against the built-in fallback cert.
            return callback(null, {
                response: 'NO',
                message: 'STARTTLS not available'
            });
        }

        // Block any further (possibly pipelined / injected) commands until the TLS
        // handshake completes. _onCommand ignores commands while _upgrading is set,
        // so a command sent in the same chunk as STARTTLS cannot be executed.
        this._upgrading = true;

        setImmediate(upgrade.bind(null, this));

        callback(null, {
            response: 'OK'
        });
    }
};

/**
 * Upgrades current socket to use TLS
 * @param {Object} connection IMAPConnection instance
 */
function upgrade(connection) {
    connection._socket.unpipe(connection._parser);
    connection.writeStream.unpipe(connection._socket);
    connection._upgrading = true;

    let secureContext = connection._server.secureContext.get('*');
    let socketOptions = {
        secureContext,
        isServer: true,
        server: connection._server.server,
        SNICallback: (servername, cb) => {
             
            connection._server.options.SNICallback(servername, (err, context) => {
                if (err) {
                    connection._server.logger.error(
                        {
                            tnx: 'sni',
                            servername,
                            err
                        },
                        'Failed to fetch SNI context for servername %s',
                        servername
                    );
                }
                return cb(null, context || connection._server.secureContext.get('*'));
            });
        }
    };

    // Apply additional socket options if these are set in the server options
    ['requestCert', 'rejectUnauthorized', 'NPNProtocols', 'SNICallback', 'session', 'requestOCSP'].forEach(key => {
        if (key in connection._server.options) {
            socketOptions[key] = connection._server.options[key];
        }
    });

    // remove all listeners from the original socket besides the error handler
    connection._socket.removeAllListeners();
    connection._socket.on('error', connection._onError.bind(connection));

    // upgrade connection
    let secureSocket = new tls.TLSSocket(connection._socket, socketOptions);

    secureSocket.once('close', () => connection._onClose());
    secureSocket.once('error', err => connection._onError(err));
    secureSocket.once('_tlsError', err => connection._onError(err));
    secureSocket.once('clientError', err => connection._onError(err));

    secureSocket.setTimeout(connection._server.options.socketTimeout || SOCKET_TIMEOUT, () => connection._onTimeout());

    secureSocket.on('secure', () => {
        connection.secure = true;
        connection._socket = secureSocket;
        connection._upgrading = false;

        let cipher = connection._socket.getCipher();
        connection._server.logger.info(
            {
                tnx: 'starttls',
                cid: connection.id,
                user: connection.session && connection.session.user && connection.session.user.username,
                cipher: cipher && cipher.name
            },
            'Connection upgraded to TLS using ',
            (cipher && cipher.name) || 'N/A'
        );

        // Discard any plaintext the parser buffered before the handshake so it
        // cannot be injected into the now-encrypted session.
        connection._parser.reset();

        connection._socket.pipe(connection._parser);
        connection.writeStream.pipe(connection._socket);
    });
}
