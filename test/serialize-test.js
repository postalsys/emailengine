'use strict';

// Round-trip tests for tools.serialize / tools.unserialize, the binary codec
// for stored IMAP message index entries:
//   < [4B UInt32LE UID] [1B flag bits] [8B BigUInt64LE MODSEQ] [msgpack meta] >
// A regression here corrupts the sync state of every account (duplicate or
// dropped messages and webhooks), and it previously had no test coverage.

const test = require('node:test');
const assert = require('node:assert').strict;

const tools = require('../lib/tools');
const enumMessageFlags = require('../lib/enum-message-flags');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

// Serialize then unserialize and return the decoded entry.
function roundTrip(entry) {
    return tools.unserialize(tools.serialize(entry));
}

const flagArray = formatted => Array.from(formatted.flags).sort();

test('tools.serialize / unserialize', async t => {
    await t.test('round-trips uid and standard flags', () => {
        const entry = { uid: 42, flags: new Set(['\\Seen', '\\Flagged']) };
        const out = roundTrip(entry);
        assert.strictEqual(out.uid, 42);
        assert.deepStrictEqual(flagArray(out), ['\\Flagged', '\\Seen']);
        assert.ok(!('modseq' in out), 'no modseq when not provided');
    });

    await t.test('round-trips every standard enum flag via the bit field', () => {
        const entry = { uid: 7, flags: new Set(enumMessageFlags) };
        const out = roundTrip(entry);
        assert.deepStrictEqual(flagArray(out), [...enumMessageFlags].sort());
    });

    await t.test('round-trips empty flag set', () => {
        const out = roundTrip({ uid: 1, flags: new Set() });
        assert.strictEqual(out.uid, 1);
        assert.deepStrictEqual(flagArray(out), []);
    });

    await t.test('round-trips a BigInt modseq', () => {
        const modseq = 12345678901234n;
        const out = roundTrip({ uid: 99, flags: new Set(['\\Seen']), modseq });
        assert.strictEqual(out.modseq, modseq);
        assert.strictEqual(typeof out.modseq, 'bigint');
    });

    await t.test('round-trips a near-max UInt64 modseq', () => {
        const modseq = 18446744073709551615n; // 2^64 - 1
        const out = roundTrip({ uid: 5, flags: new Set(), modseq });
        assert.strictEqual(out.modseq, modseq);
    });

    await t.test('round-trips a max UInt32 uid', () => {
        const out = roundTrip({ uid: 4294967295, flags: new Set() });
        assert.strictEqual(out.uid, 4294967295);
    });

    await t.test('round-trips emailId', () => {
        const out = roundTrip({ uid: 10, flags: new Set(), emailId: 'abc123emailid' });
        assert.strictEqual(out.emailId, 'abc123emailid');
    });

    await t.test('round-trips Gmail labels as a Set', () => {
        const entry = { uid: 11, flags: new Set(['\\Seen']), labels: new Set(['\\Inbox', 'Work', '\\Important']) };
        const out = roundTrip(entry);
        assert.ok(out.labels instanceof Set);
        // Default JS sort is by code unit; '\\' (92) sorts after letters.
        assert.deepStrictEqual(Array.from(out.labels).sort(), ['Work', '\\Important', '\\Inbox']);
    });

    await t.test('round-trips non-standard flags via the msgpack meta', () => {
        // Flags outside enumMessageFlags must survive via the extra-flags array.
        const entry = { uid: 12, flags: new Set(['\\Seen', '$CustomLabel', 'NonStandard']) };
        const out = roundTrip(entry);
        assert.deepStrictEqual(flagArray(out), ['$CustomLabel', 'NonStandard', '\\Seen']);
    });

    await t.test('round-trips a fully populated entry', () => {
        const entry = {
            uid: 123456,
            flags: new Set(['\\Seen', '\\Answered', '$Forwarded', 'Custom']),
            modseq: 987654321n,
            emailId: 'gmail-msg-id-987',
            labels: new Set(['\\Inbox', 'Receipts'])
        };
        const out = roundTrip(entry);
        assert.strictEqual(out.uid, entry.uid);
        assert.strictEqual(out.modseq, entry.modseq);
        assert.strictEqual(out.emailId, entry.emailId);
        assert.deepStrictEqual(flagArray(out), ['$Forwarded', 'Custom', '\\Answered', '\\Seen']);
        assert.deepStrictEqual(Array.from(out.labels).sort(), ['Receipts', '\\Inbox']);
    });

    await t.test('decodes the deleted (D) sentinel', () => {
        assert.deepStrictEqual(tools.unserialize(Buffer.from('D')), { deleted: true });
    });

    await t.test('decodes the placeholder (N) sentinel', () => {
        assert.deepStrictEqual(tools.unserialize(Buffer.from('N')), { placeholder: true });
    });

    await t.test('returns empty object for an unknown single-byte marker', () => {
        assert.deepStrictEqual(tools.unserialize(Buffer.from('X')), {});
    });

    await t.test('standard flags map to independent bit positions', () => {
        // Serializing a single flag must set exactly one distinct bit in byte 4,
        // and the bit must differ per flag (no collisions).
        const seenBits = new Set();
        for (const flag of enumMessageFlags) {
            const buf = tools.serialize({ uid: 1, flags: new Set([flag]) });
            const flagByte = buf[4];
            assert.notStrictEqual(flagByte, 0, `${flag} should set a bit`);
            assert.ok(!seenBits.has(flagByte), `${flag} should map to a unique bit`);
            seenBits.add(flagByte);
        }
        assert.strictEqual(seenBits.size, enumMessageFlags.length);
    });
});
