'use strict';

// lib/net-tos-guard.js: undici 7 calls socket.setTypeOfService() unguarded from a connect handler,
// and on macOS a peer that reset the connection made it throw EINVAL as an uncaughtException

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('net');

const { guardTypeOfService } = require('../lib/net-tos-guard');

function failingProto(err) {
    return {
        setTypeOfService() {
            throw err;
        }
    };
}

test('a failed setTypeOfService() is ignored', () => {
    const proto = failingProto(Object.assign(new Error('setTypeOfService EINVAL'), { code: 'EINVAL', syscall: 'setTypeOfService' }));
    assert.equal(guardTypeOfService(proto), true);
    const socket = Object.create(proto);
    assert.equal(socket.setTypeOfService(0), socket);
});

test('any other error still throws, and a prototype is wrapped once', () => {
    const proto = failingProto(new TypeError('tos must be a number'));
    guardTypeOfService(proto);
    assert.equal(guardTypeOfService(proto), false);
    assert.throws(() => Object.create(proto).setTypeOfService('x'), TypeError);
});

test('a Node without the method is left alone, and net.Socket is guarded where it has it', () => {
    assert.equal(guardTypeOfService({}), false);
    if (typeof net.Socket.prototype.setTypeOfService === 'function') {
        assert.equal(net.Socket.prototype.setTypeOfService.tosGuarded, true);
    }
});
