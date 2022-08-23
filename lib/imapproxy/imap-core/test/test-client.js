/*eslint no-console: 0 */

'use strict';

let net = require('net');
let tls = require('tls');

module.exports = runClientMockup;

function runClientMockup(options, callback) {
    options = options || {};

    let host = options.host || 'localhost';
    let port = options.port || 25;
    let commands = [].concat(options.commands || []);
    let debug = options.debug;

    let ignore_data = false;
    let responses = [];
    let command = '';
    let callbackSent = false;
    let delay;

    let socket = (options.secure ? tls : net).connect(
        {
            rejectUnauthorized: false,
            port,
            host
        },
        () => {
            socket.on('close', () => {
                if (callbackSent) {
                    return;
                }
                callbackSent = true;
                if (typeof callback === 'function') {
                    return callback(Buffer.concat(responses));
                }
            });

            let onData = function(chunk) {
                if (ignore_data) {
                    return;
                }

                responses.push(chunk);
                if (debug) {
                    console.log('S: ' + chunk.toString('binary').trim());
                }

                if (!commands.length) {
                    return;
                }

                if (typeof command === 'string' && command.match(/^[a-z0-9]+ STARTTLS$/i)) {
                    // wait until server sends response to the STARTTLS command
                    if (!/STARTTLS completed/.test(Buffer.concat(responses).toString())) {
                        return;
                    }

                    ignore_data = true;
                    if (debug) {
                        console.log('Initiated TLS connection');
                    }

                    socket.removeAllListeners('data');
                    let secureSocket = tls.connect(
                        {
                            rejectUnauthorized: false,
                            socket,
                            host
                        },
                        () => {
                            ignore_data = false;

                            socket = secureSocket;

                            if (debug) {
                                console.log('TLS connection secured');
                            }

                            secureSocket.on('data', onData);

                            secureSocket.on('close', () => {
                                if (callbackSent) {
                                    return;
                                }
                                callbackSent = true;
                                if (typeof callback === 'function') {
                                    return callback(Buffer.concat(responses));
                                }
                            });

                            command = commands.shift();
                            if (debug) {
                                console.log('(Secure) C: ' + command);
                            }
                            secureSocket.write(command + '\r\n');
                        }
                    );

                    secureSocket.on('error', err => {
                        console.log('SECURE ERR');
                        console.log(err.stack);
                    });
                } else {
                    if (!/\r?\n$/.test(chunk.toString('binary'))) {
                        return;
                    }
                    // only go forward with the next command if the last data ends with a newline
                    // and there is no activity in the socket for 10ms
                    let processCommand = () => {
                        clearTimeout(delay);
                        delay = setTimeout(() => {
                            command = commands.shift();
                            if (command === 'SLEEP') {
                                return setTimeout(processCommand, 5000);
                            }

                            if (Array.isArray(command)) {
                                let i = 0;
                                let send = function() {
                                    if (i >= command.length) {
                                        return;
                                    }

                                    let part = command[i++];

                                    socket.write(Buffer.from(part + (i >= command.length ? '\r\n' : ''), 'binary'));
                                    if (debug) {
                                        console.log('C: ' + part);
                                    }
                                    setTimeout(send, 10);
                                };

                                send();
                            } else {
                                socket.write(Buffer.from(command + '\r\n', 'binary'));
                                if (debug) {
                                    console.log('C: ' + command);
                                }
                            }
                        }, 100);
                    };
                    processCommand();
                }
            };

            socket.on('data', onData);
        }
    );
}
