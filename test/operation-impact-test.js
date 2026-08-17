'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { IMPACT, DECLARABLE_IMPACTS, resolveImpact } = require('../lib/api-routes/operation-impact');

// This derivation used to be duplicated: lib/api-reference/model.js carried its own copy of the
// method default, so a route could be weighted one way for the Try it warning and another way for
// anything else reading the classification. The point of these tests is that one function answers
// for every reader.

describe('operation impact', () => {
    describe('resolveImpact', () => {
        it('returns a declared impact unchanged', () => {
            assert.equal(resolveImpact(IMPACT.DESTRUCTIVE, 'put'), IMPACT.DESTRUCTIVE);
            assert.equal(resolveImpact(IMPACT.SENDS, 'post'), IMPACT.SENDS);
            // The whole reason declarations exist: the method is a bad proxy for POST /v1/unified/search
            assert.equal(resolveImpact(IMPACT.READONLY, 'post'), IMPACT.READONLY);
        });

        it('defaults an undeclared GET to readonly and everything else to write', () => {
            assert.equal(resolveImpact(undefined, 'get'), IMPACT.READONLY);
            assert.equal(resolveImpact(undefined, 'post'), IMPACT.WRITE);
            assert.equal(resolveImpact(undefined, 'put'), IMPACT.WRITE);
            assert.equal(resolveImpact(undefined, 'delete'), IMPACT.WRITE);
        });

        it('accepts the method in any case', () => {
            // Hapi lowercases route methods at registration, but the OpenAPI document is keyed by
            // lowercase method while a caller may hold either
            assert.equal(resolveImpact(undefined, 'GET'), IMPACT.READONLY);
            assert.equal(resolveImpact(undefined, 'Get'), IMPACT.READONLY);
        });

        it('returns null for a value that is not a declarable impact', () => {
            // Fail closed on a typo rather than silently falling back to the method default, which
            // is how a route meaning "destructive" would lose its warning
            assert.equal(resolveImpact('readOnly', 'post'), null);
            assert.equal(resolveImpact('deletes', 'delete'), null);
            assert.equal(resolveImpact('read', 'get'), null);
        });

        it('does not accept the derived default as a declaration', () => {
            // `write` is what an undeclared non-GET resolves TO, not something a route may say.
            // Accepting it would give one classification two spellings.
            assert.equal(resolveImpact(IMPACT.WRITE, 'post'), null);
            assert.ok(!DECLARABLE_IMPACTS.has(IMPACT.WRITE));
        });
    });

    describe('DECLARABLE_IMPACTS', () => {
        it('is every impact except the derived default', () => {
            const derived = [IMPACT.WRITE];
            assert.deepEqual(
                [...DECLARABLE_IMPACTS].sort(),
                Object.values(IMPACT)
                    .filter(impact => !derived.includes(impact))
                    .sort()
            );
        });

        it('covers every value an undeclared route can resolve to, plus the declarable ones', () => {
            // Guards the totality that anything switching on an impact depends on: a fifth IMPACT
            // member that is neither declarable nor derived would be unreachable, which is a sign
            // it was added without wiring.
            const reachable = new Set([...DECLARABLE_IMPACTS, resolveImpact(undefined, 'get'), resolveImpact(undefined, 'post')]);
            assert.deepEqual([...reachable].sort(), Object.values(IMPACT).sort());
        });
    });
});
