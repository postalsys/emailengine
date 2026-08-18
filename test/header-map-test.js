'use strict';

// Unit coverage for pushHeaderValue() (lib/utils/header-map.js), the guarded accumulator the
// Gmail and Outlook clients build their header maps with.
//
// Header names arrive verbatim from the provider, so any sender can pick one that names an
// Object.prototype member. A bare `!headers[key]` probe finds the INHERITED value for
// "__proto__" or "constructor" and pushes onto something that is not an array, throwing on the
// first occurrence. No prototype pollution is possible either way - assigning to
// headers["__proto__"] hands the value to the prototype setter rather than storing it - so these
// tests are about availability and about not silently dropping real headers.

const test = require('node:test');
const assert = require('node:assert').strict;

const { pushHeaderValue } = require('../lib/utils/header-map');

// Names are fed in as an array rather than an object literal, since a literal keyed by
// "__proto__" would set the literal's prototype instead of a key and test nothing.
function collect(names) {
    const headers = {};
    const stored = [];
    for (const name of names) {
        stored.push(pushHeaderValue(headers, name.toLowerCase(), `v:${name}`));
    }
    return { headers, stored };
}

test('pushHeaderValue', async t => {
    await t.test('collects ordinary headers, including repeats, in order', () => {
        const { headers, stored } = collect(['Subject', 'X-Custom', 'X-Custom']);

        assert.deepEqual(headers, { subject: ['v:Subject'], 'x-custom': ['v:X-Custom', 'v:X-Custom'] });
        assert.deepEqual(stored, [true, true, true]);
    });

    await t.test('skips names that resolve to prototype members', () => {
        // These are the only two Object.prototype members that survive lowercasing
        const { headers, stored } = collect(['__proto__', 'constructor']);

        assert.deepEqual(Object.keys(headers), []);
        assert.deepEqual(stored, [false, false]);
        assert.equal(Object.getPrototypeOf(headers), Object.prototype);
    });

    await t.test('keeps collecting after a skipped name', () => {
        const { headers } = collect(['__proto__', 'Subject', 'constructor', 'Subject']);

        assert.deepEqual(headers, { subject: ['v:Subject', 'v:Subject'] });
    });

    await t.test('keeps names that only look dangerous before lowercasing', () => {
        // "toString" and "hasOwnProperty" are prototype members, but the map is keyed by the
        // lowercased name, so they cannot collide and must not be dropped as a side effect
        const { headers } = collect(['toString', 'hasOwnProperty']);

        assert.deepEqual(headers, { tostring: ['v:toString'], hasownproperty: ['v:hasOwnProperty'] });
    });

    await t.test('leaves the global prototype untouched', () => {
        collect(['__proto__', 'constructor', '__proto__']);

        assert.deepEqual(Object.keys(Object.prototype), []);
        assert.equal({}['v:__proto__'], undefined);
    });

    await t.test('produces a map that survives JSON and msgpack round-trips', () => {
        // An own "__proto__" key would encode but fail to decode, so the map has to stay free of
        // one for webhook payloads and stored logs to be readable back
        const msgpack = require('../lib/msgpack');
        const { headers } = collect(['Subject', '__proto__', 'constructor']);

        assert.deepEqual(JSON.parse(JSON.stringify(headers)), headers);
        assert.deepEqual(msgpack.decode(msgpack.encode(headers)), headers);
    });
});
