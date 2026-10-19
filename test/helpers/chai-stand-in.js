'use strict';

// A node:assert-backed stand-in for the part of chai's `expect` that the vendored WildDuck
// imap-core specs use, so those files can stay byte-identical to upstream without chai being a
// devDependency. It covers exactly these chains and nothing else:
//
//   expect(a).to.equal(b)            strict equality
//   expect(a).to.deep.equal(b)       deep strict equality
//   expect(a).to.be.true / .false    strictly true / false
//   expect(a).to.exist               neither null nor undefined
//   expect(a).to.not.exist           null or undefined
//   expect(fn).to.throw(Error)       fn throws an instance of the given class
//   expect(fn).to.not.throw(Error)   fn does not throw
//
// An unsupported chain reads as undefined, so a spec reaching for one fails loudly with a
// TypeError instead of passing silently. test/imap-core-vendored-test.js routes the vendored
// files' require('chai') here; nothing else should load it.

const assert = require('node:assert/strict');

const expect = actual => {
    let negate = false;
    let deep = false;

    const chain = {
        get to() {
            return chain;
        },
        get be() {
            return chain;
        },
        get not() {
            negate = !negate;
            return chain;
        },
        get deep() {
            deep = true;
            return chain;
        },
        get true() {
            (negate ? assert.notStrictEqual : assert.strictEqual)(actual, true);
            return chain;
        },
        get false() {
            (negate ? assert.notStrictEqual : assert.strictEqual)(actual, false);
            return chain;
        },
        get exist() {
            if (negate) {
                assert.ok(actual === null || actual === undefined, `expected ${actual} to not exist`);
            } else {
                assert.ok(actual !== null && actual !== undefined, `expected ${actual} to exist`);
            }
            return chain;
        },
        equal(expected) {
            if (deep) {
                (negate ? assert.notDeepStrictEqual : assert.deepStrictEqual)(actual, expected);
            } else {
                (negate ? assert.notStrictEqual : assert.strictEqual)(actual, expected);
            }
            return chain;
        },
        throw(errorClass) {
            if (negate) {
                assert.doesNotThrow(actual);
            } else {
                assert.throws(actual, errorClass || Error);
            }
            return chain;
        }
    };

    return chain;
};

module.exports = { expect, config: {} };
