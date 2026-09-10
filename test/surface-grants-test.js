'use strict';

// The surface grant tables and the predicates over them (lib/api-routes/permission-map.js): what
// each MCP scope may reach, and how a token's scope list is turned into a bound on one operation.
// The tables are policy that several places read - the api-token strategy, tools/list, the admin
// pages - so the shape of each is asserted here rather than discovered at a customer's.
//
// No Redis and no teardown hook: permission-map.js reaches only two dependency-free modules.

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const {
    ACTION,
    GROUP,
    NEVER_GRANTABLE,
    SURFACE_GRANTS,
    PER_REQUEST_SURFACES,
    surfaceAdmits,
    perRequestSurfaceAdmits,
    surfaceBoundAdmits
} = require('../lib/api-routes/permission-map');

const READ_SETTINGS = { action: ACTION.READ, group: GROUP.SETTINGS };
const READ_MESSAGE = { action: ACTION.READ, group: GROUP.MESSAGE };
const READ_ACCOUNT = { action: ACTION.READ, group: GROUP.ACCOUNT };
const SEND = { action: ACTION.SEND, group: GROUP.SUBMIT };

describe('surface grants', () => {
    describe('the two MCP tables', () => {
        it('are the two per-request surfaces, and nothing else is', () => {
            assert.deepEqual([...PER_REQUEST_SURFACES].sort(), ['mcp', 'mcp-manage']);
            for (const scope of PER_REQUEST_SURFACES) {
                assert.ok(Array.isArray(SURFACE_GRANTS[scope]) && SURFACE_GRANTS[scope].length, `${scope} has no table`);
            }
        });

        it('never name a never-grantable group', () => {
            for (const [scope, grants] of Object.entries(SURFACE_GRANTS)) {
                for (const grant of grants) {
                    assert.ok(!NEVER_GRANTABLE.has(grant.group), `${scope} lists ${grant.action}/${grant.group}`);
                }
            }
        });

        it('keep sending, exports and the change stream out of the management surface', () => {
            // A management credential operates the instance; it does not deliver mail, archive a
            // mailbox or drink the firehose. Those stay with the mail scope or with REST.
            const manage = SURFACE_GRANTS['mcp-manage'];
            assert.ok(!manage.some(grant => grant.action === ACTION.SEND), 'the management surface must not send');
            assert.ok(!manage.some(grant => grant.group === GROUP.EXPORT), 'the management surface must not export');
            assert.ok(!manage.some(grant => grant.group === GROUP.EVENTS), 'the management surface must not stream events');
            assert.ok(!manage.some(grant => grant.group === GROUP.MESSAGE || grant.group === GROUP.MAILBOX), 'the management surface must not reach mail');
            // Removing the license has no agent use case, only harm
            assert.ok(!manage.some(grant => grant.action === ACTION.DESTRUCTIVE && grant.group === GROUP.LICENSE));
        });

        it('keep the mail surface exactly as it was, so no issued full-access mail token widened', () => {
            // The consent page's "Full access" level used to mint a token with no permissions
            // record, bounded by this table alone. It is the reason the management tools got a
            // second scope rather than a longer list here, and the reason this list is pinned.
            assert.deepEqual(
                SURFACE_GRANTS.mcp.map(grant => `${grant.action}:${grant.group}`),
                ['read:account', 'read:mailbox', 'read:message', 'write:message', 'destructive:message', 'send:submit', 'read:outbox', 'read:template']
            );
        });

        it('share the account read, so either kind of agent can list accounts', () => {
            assert.ok(surfaceAdmits('mcp', READ_ACCOUNT));
            assert.ok(surfaceAdmits('mcp-manage', READ_ACCOUNT));
        });
    });

    describe('perRequestSurfaceAdmits', () => {
        it('admits an operation when any held per-request scope covers it', () => {
            assert.ok(perRequestSurfaceAdmits(['mcp-manage'], READ_SETTINGS));
            assert.ok(perRequestSurfaceAdmits(['mcp', 'mcp-manage'], READ_SETTINGS));
            assert.ok(perRequestSurfaceAdmits(['smtp', 'mcp'], READ_MESSAGE));
        });

        it('refuses an operation outside every held table', () => {
            assert.ok(!perRequestSurfaceAdmits(['mcp'], READ_SETTINGS));
            assert.ok(!perRequestSurfaceAdmits(['mcp-manage'], READ_MESSAGE));
            assert.ok(!perRequestSurfaceAdmits(['mcp-manage'], SEND));
        });

        it('ignores scopes that are not per-request surfaces, and tolerates no list', () => {
            // `api` and `*` are handled by the scope check itself, not by the surface tables;
            // here they count for nothing, so the strategy's own clauses stay the only path in
            assert.ok(!perRequestSurfaceAdmits(['api'], READ_SETTINGS));
            assert.ok(!perRequestSurfaceAdmits(['*'], READ_SETTINGS));
            assert.ok(!perRequestSurfaceAdmits(['smtp'], SEND));
            assert.ok(!perRequestSurfaceAdmits(undefined, READ_SETTINGS));
            assert.ok(!perRequestSurfaceAdmits('mcp', READ_MESSAGE));
        });
    });

    describe('surfaceBoundAdmits', () => {
        // The advertisement predicate is the per-request one plus two clauses of its own
        it('does not bound a token that reaches the whole API', () => {
            for (const tokenData of [{ scopes: ['api'] }, { scopes: ['*'] }, { scopes: ['api', 'mcp'] }, {}, { scopes: null }, undefined]) {
                assert.ok(surfaceBoundAdmits(tokenData, READ_SETTINGS), `${JSON.stringify(tokenData)} should not be bounded`);
                assert.ok(surfaceBoundAdmits(tokenData, SEND));
            }
        });

        it('bounds every other token by the tables of the per-request scopes it holds', () => {
            assert.ok(surfaceBoundAdmits({ scopes: ['mcp-manage'] }, READ_SETTINGS));
            assert.ok(!surfaceBoundAdmits({ scopes: ['mcp'] }, READ_SETTINGS));
            // a token holding only login-time scopes reaches nothing over MCP
            assert.ok(!surfaceBoundAdmits({ scopes: ['smtp'] }, SEND));
            assert.ok(!surfaceBoundAdmits({ scopes: ['metrics'] }, { action: ACTION.READ, group: GROUP.DIAGNOSTICS }));
        });
    });
});
