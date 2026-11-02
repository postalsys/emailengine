'use strict';

// Keeps a failed type-of-service marking from ending the process.
//
// undici 7 (held there by the Node 20 floor, see .ncurc.js) calls socket.setTypeOfService() for
// every request on a Node that has it (24.x), unguarded, from the socket's connect handler. On macOS
// the underlying setsockopt() answers EINVAL once the peer has reset the connection, so a peer that
// went away right after accepting (an instance shutting down, a restart) threw an uncaughtException
// in whichever thread made the request. undici 8 wraps the call itself; marking is best effort
// there too. EmailEngine never sets a type of service, so nothing is lost by ignoring the failure.
// Remove this together with the undici 8 upgrade.

const net = require('net');

/**
 * Wraps setTypeOfService() of a socket prototype so a failure of the call itself is ignored
 * @param {Object} proto - net.Socket.prototype, or a stand-in in tests
 * @returns {boolean} Whether the prototype was wrapped (false without the method, or done before)
 */
function guardTypeOfService(proto) {
    const original = proto.setTypeOfService;
    if (typeof original !== 'function' || original.tosGuarded) {
        return false;
    }
    const guarded = function setTypeOfService(...args) {
        try {
            return original.apply(this, args);
        } catch (err) {
            if (err && err.syscall === 'setTypeOfService') {
                return this;
            }
            throw err;
        }
    };
    guarded.tosGuarded = true;
    proto.setTypeOfService = guarded;
    return true;
}

guardTypeOfService(net.Socket.prototype);

module.exports = { guardTypeOfService };
