'use strict';

// Unit tests for the token narrowing check.
//
// No Redis and no teardown hook: lib/token-permissions.js reaches only lib/api-routes/permission-map.js
// and from there two dependency-free modules, so nothing here opens a connection.

const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { check, isNarrowed, REASON } = require('../lib/token-permissions');
const { ACTION, GROUP, GRANTABLE_GROUPS } = require('../lib/api-routes/permission-map');

// A read of a message, which is the operation most of these narrow around
const READ_MESSAGE = { action: ACTION.READ, group: GROUP.MESSAGE };

const allow = (permissions, operation) => check({ tokenData: permissions === undefined ? {} : { permissions }, operation });

describe('token permissions', () => {
    describe('a token with no permissions is not narrowed', () => {
        it('allows anything the scope and account binding already allowed', () => {
            // Every token issued before this feature shipped takes this path. If it ever stops
            // doing so, the change is no longer additive and existing deployments break.
            for (const group of [...GRANTABLE_GROUPS, GROUP.ADMIN]) {
                for (const action of Object.values(ACTION)) {
                    const result = check({ tokenData: {}, operation: { action, group } });
                    assert.ok(result.allowed, `${action} on ${group} was denied for an un-narrowed token`);
                }
            }
        });

        it('treats an explicitly null record as absent', () => {
            assert.ok(check({ tokenData: { permissions: null }, operation: READ_MESSAGE }).allowed);
            assert.ok(!isNarrowed({ permissions: null }));
            assert.ok(!isNarrowed({}));
            assert.ok(!isNarrowed(undefined));
        });
    });

    describe('the actions axis', () => {
        it('allows a listed action and denies an unlisted one', () => {
            const readOnly = { actions: [ACTION.READ] };
            assert.ok(allow(readOnly, READ_MESSAGE).allowed);

            const denied = allow(readOnly, { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE });
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.ACTION);
        });

        it('separates destructive from write, which is the point of the axis', () => {
            // "an agent that can file and reply but not delete" is the single most requested shape
            const fileAndReply = { actions: [ACTION.READ, ACTION.WRITE, ACTION.SEND] };
            assert.ok(allow(fileAndReply, { action: ACTION.WRITE, group: GROUP.MESSAGE }).allowed);
            assert.ok(allow(fileAndReply, { action: ACTION.SEND, group: GROUP.SUBMIT }).allowed);
            assert.ok(!allow(fileAndReply, { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE }).allowed);
        });

        it('reports what the operation required, so a 403 can say which grant was missing', () => {
            const denied = allow({ actions: [ACTION.READ] }, { action: ACTION.WRITE, group: GROUP.MAILBOX });
            assert.deepEqual(denied.required, { action: ACTION.WRITE, group: GROUP.MAILBOX });
        });
    });

    describe('the groups axis', () => {
        it('allows a listed group and denies an unlisted one', () => {
            const mailOnly = { groups: [GROUP.MESSAGE, GROUP.MAILBOX] };
            assert.ok(allow(mailOnly, READ_MESSAGE).allowed);

            const denied = allow(mailOnly, { action: ACTION.READ, group: GROUP.TEMPLATE });
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.GROUP);
        });

        it('denies the export group unless it is named, so a message grant does not archive the account', () => {
            // One export call bundles the whole account, which is why it is not part of `message`
            assert.ok(!allow({ groups: [GROUP.MESSAGE] }, { action: ACTION.WRITE, group: GROUP.EXPORT }).allowed);
            assert.ok(allow({ groups: [GROUP.EXPORT] }, { action: ACTION.WRITE, group: GROUP.EXPORT }).allowed);
        });

        it('denies the instance-wide event stream unless it is named', () => {
            assert.ok(!allow({ groups: [GROUP.MESSAGE] }, { action: ACTION.READ, group: GROUP.EVENTS }).allowed);
        });
    });

    describe('the axes intersect rather than union', () => {
        it('requires both to pass', () => {
            const permissions = { actions: [ACTION.READ], groups: [GROUP.MESSAGE] };
            assert.ok(allow(permissions, READ_MESSAGE).allowed);
            // right group, wrong action
            assert.ok(!allow(permissions, { action: ACTION.WRITE, group: GROUP.MESSAGE }).allowed);
            // right action, wrong group
            assert.ok(!allow(permissions, { action: ACTION.READ, group: GROUP.GATEWAY }).allowed);
        });

        it('applies an axis to every group, since actions are not per group', () => {
            // Documented limitation rather than an oversight: `groups` may later accept an object
            // for per-group actions, and an array keeps meaning "these actions apply to all of
            // these groups".
            const permissions = { actions: [ACTION.READ], groups: [GROUP.MESSAGE, GROUP.TEMPLATE] };
            assert.ok(!allow(permissions, { action: ACTION.WRITE, group: GROUP.TEMPLATE }).allowed);
        });
    });

    describe('the admin group is never grantable', () => {
        it('is denied even when the record names it explicitly', () => {
            // The whole safety property. While this holds, a narrowed token cannot read the settings
            // blob, cannot read a stored OAuth2 credential and cannot mint a token, so it cannot
            // widen itself and every other rule here means something.
            const denied = allow({ groups: [GROUP.ADMIN] }, { action: ACTION.READ, group: GROUP.ADMIN });
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.RESTRICTED);
        });

        it('is denied when only the actions axis is set', () => {
            // Presence of `permissions` at all is what triggers the denial, not the groups axis
            const denied = allow({ actions: Object.values(ACTION) }, { action: ACTION.READ, group: GROUP.ADMIN });
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.RESTRICTED);
        });

        it('outranks the ordinary axis denials', () => {
            // A denial that reported "group not in your list" would invite someone to add it
            const denied = allow({ actions: [ACTION.WRITE], groups: [GROUP.MESSAGE] }, { action: ACTION.READ, group: GROUP.ADMIN });
            assert.equal(denied.reason, REASON.RESTRICTED);
        });
    });

    describe('absent, empty and malformed are three different answers', () => {
        it('treats an empty allowlist as granting nothing', () => {
            // Opposite of the axis being absent, and consistent with how `scopes: []` already
            // denies every scope
            const denied = allow({ actions: [] }, READ_MESSAGE);
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.ACTION);

            assert.ok(!allow({ groups: [] }, READ_MESSAGE).allowed);
        });

        it('denies a record that is not an object', () => {
            for (const permissions of ['read', 42, true, ['read']]) {
                const denied = allow(permissions, READ_MESSAGE);
                assert.ok(!denied.allowed, `${JSON.stringify(permissions)} was allowed`);
                assert.equal(denied.reason, REASON.MALFORMED);
            }
        });

        it('denies an empty object, which is ambiguous', () => {
            const denied = allow({}, READ_MESSAGE);
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.MALFORMED);
        });

        it('denies an unknown axis rather than ignoring it', () => {
            // What makes adding a third axis later safe: an older release that cannot apply a
            // narrowing refuses the request instead of honouring a subset of it
            const denied = allow({ actions: [ACTION.READ], mailboxes: ['INBOX'] }, READ_MESSAGE);
            assert.ok(!denied.allowed);
            assert.equal(denied.reason, REASON.MALFORMED);
        });

        it('denies an axis that is not an array, or holds a value outside the vocabulary', () => {
            for (const permissions of [{ actions: ACTION.READ }, { groups: GROUP.MESSAGE }, { actions: ['readonly'] }, { groups: ['messages'] }]) {
                const denied = allow(permissions, READ_MESSAGE);
                assert.ok(!denied.allowed, `${JSON.stringify(permissions)} was allowed`);
                assert.equal(denied.reason, REASON.MALFORMED);
            }
        });

        it('does not accept an impact name where an action is expected', () => {
            // `readonly` and `sends` describe a route; `read` and `send` describe a grant. Accepting
            // both spellings would make the vocabulary ambiguous.
            assert.equal(allow({ actions: ['sends'] }, READ_MESSAGE).reason, REASON.MALFORMED);
        });

        it('counts a malformed record as narrowed, so the UI can flag it', () => {
            assert.ok(isNarrowed({ permissions: { nonsense: true } }));
        });
    });

    describe('an operation the vocabulary does not describe', () => {
        it('is denied rather than waved through', () => {
            // Reached when the route table and permission-map.js diverge, which
            // test/api-routes-table-test.js exists to prevent. Fails closed either way.
            for (const operation of [{ action: null, group: GROUP.MESSAGE }, { action: ACTION.READ, group: null }, {}, undefined]) {
                const denied = check({ tokenData: { permissions: { actions: [ACTION.READ] } }, operation });
                assert.ok(!denied.allowed, `${JSON.stringify(operation)} was allowed`);
                assert.equal(denied.reason, REASON.UNCLASSIFIED);
            }
        });

        it('is still allowed for a token that is not narrowed', () => {
            // An un-narrowed token behaves exactly as it does today, including on a route this
            // vocabulary has nothing to say about
            assert.ok(check({ tokenData: {}, operation: { action: null, group: null } }).allowed);
        });
    });
});

// The record reaches check() from Redis via msgpack, and tokens.setRawData() writes whatever its
// input carries with no joi schema at all - it is the import path for EENGINE_PREPARED_TOKEN. So the
// check has to hold against shapes no route validation ever saw.
describe('a hostile record cannot widen a token', () => {
    const denied = permissions => check({ tokenData: { permissions }, operation: READ_MESSAGE });

    it('does not read an axis off the prototype chain', () => {
        // An `in` check would find the inherited `groups` and apply a narrowing the record does not
        // own. Only the own key counts, so this record narrows on actions and not on groups.
        const hostile = Object.create({ groups: [GROUP.MESSAGE] });
        hostile.actions = [ACTION.READ];

        assert.ok(check({ tokenData: { permissions: hostile }, operation: READ_MESSAGE }).allowed, 'the own actions axis should still allow a read');

        assert.ok(
            check({ tokenData: { permissions: hostile }, operation: { action: ACTION.READ, group: GROUP.TEMPLATE } }).allowed,
            'the inherited groups axis must not restrict anything - reading it would mean honouring a narrowing the record never set'
        );
    });

    it('refuses a record whose own keys include a prototype name', () => {
        const hostile = {};
        Object.defineProperty(hostile, '__proto__', { value: { groups: [GROUP.ADMIN] }, enumerable: true, configurable: true });
        assert.equal(denied(hostile).reason, REASON.MALFORMED);
    });

    it('refuses a null-prototype record with no recognised axis', () => {
        const bare = Object.create(null);
        bare.nonsense = true;
        assert.equal(denied(bare).reason, REASON.MALFORMED);
    });

    it('honours a null-prototype record that is otherwise valid', () => {
        const bare = Object.create(null);
        bare.actions = [ACTION.READ];
        assert.ok(check({ tokenData: { permissions: bare }, operation: READ_MESSAGE }).allowed);
    });

    it('refuses non-string entries in an axis rather than coercing them', () => {
        for (const permissions of [{ actions: [1] }, { actions: [null] }, { groups: [{ toString: () => 'message' }] }, { groups: [['message']] }]) {
            assert.equal(denied(permissions).reason, REASON.MALFORMED, `${JSON.stringify(permissions)} was not refused`);
        }
    });

    it('never throws, whatever it is handed', () => {
        // A throw inside the api-token strategy is a 500, not a 403, so it would turn a denial into
        // an outage rather than a refusal
        for (const permissions of [Object.create(null), [], [[]], 0, -1, NaN, Infinity, () => {}, Symbol.iterator, new Date(), new Map(), new Set()]) {
            assert.doesNotThrow(() => check({ tokenData: { permissions }, operation: READ_MESSAGE }));
        }
        assert.doesNotThrow(() => check({}));
        assert.doesNotThrow(() => check({ tokenData: null, operation: null }));
    });
});
