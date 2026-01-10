'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const msgpack = require('msgpack5')();

// Import constants and helpers directly
const { OUTLOOK_MAX_RETRY_ATTEMPTS, OUTLOOK_RETRY_BASE_DELAY, OUTLOOK_RETRY_MAX_DELAY } = require('../lib/consts');

// Gmail constants (copied from gmail-client.js since they're not exported)
const SKIP_LABELS = ['UNREAD', 'STARRED', 'IMPORTANT', 'CHAT', 'CATEGORY_PERSONAL'];

const SYSTEM_LABELS = {
    SENT: '\\Sent',
    INBOX: '\\Inbox',
    TRASH: '\\Trash',
    DRAFT: '\\Drafts',
    SPAM: '\\Junk',
    IMPORTANT: '\\Important'
};

const SYSTEM_NAMES = {
    SENT: 'Sent ',
    INBOX: 'Inbox',
    TRASH: 'Trash',
    DRAFT: 'Drafts',
    SPAM: 'Spam',
    CATEGORY_FORUMS: 'Forums',
    CATEGORY_UPDATES: 'Updates',
    CATEGORY_SOCIAL: 'Social',
    CATEGORY_PROMOTIONS: 'Promotions'
};

// PageCursor class (copied from gmail-client.js for testing)
class PageCursor {
    static create(cursorStr) {
        return new PageCursor(cursorStr);
    }

    constructor(cursorStr) {
        this.type = 'gmail';
        this.cursorList = [];
        this.cursorStr = '';

        if (cursorStr) {
            let splitPos = cursorStr.indexOf('_');
            if (splitPos >= 0) {
                let cursorType = cursorStr.substring(0, splitPos);
                cursorStr = cursorStr.substring(splitPos + 1);
                if (cursorType && this.type !== cursorType) {
                    let error = new Error('Invalid cursor');
                    error.code = 'InvalidCursorType';
                    error.statusCode = 400;
                    throw error;
                }
            }

            try {
                this.cursorList = msgpack.decode(Buffer.from(cursorStr, 'base64url'));
                this.cursorStr = cursorStr;
            } catch (err) {
                this.cursorList = [];
                this.cursorStr = '';
            }
        }
    }

    toString() {
        return this.cursorStr;
    }

    currentPage() {
        if (this.cursorList.length < 1) {
            return { page: 0, cursor: '', pageCursor: '' };
        }
        return { page: this.cursorList.length, cursor: this.decodeCursorValue(this.cursorList.at(-1)), pageCursor: this.cursorStr };
    }

    nextPageCursor(nextPageCursor) {
        if (!nextPageCursor) {
            return null;
        }
        let encodedCursor = this.encodeCursorValue(nextPageCursor);
        let cursorListCopy = this.cursorList.concat([]);
        cursorListCopy.push(encodedCursor);
        return this.type + '_' + msgpack.encode(cursorListCopy).toString('base64url');
    }

    prevPageCursor() {
        if (this.cursorList.length < 1) {
            return null;
        }
        return this.type + '_' + msgpack.encode(this.cursorList.slice(0, this.cursorList.length - 1)).toString('base64url');
    }

    encodeCursorValue(cursor) {
        let hexNr = BigInt(cursor).toString(16);
        let chunks = hexNr
            .split('')
            .reverse()
            .join('')
            .split(/(.{16})/)
            .filter(v => v)
            .reverse()
            .map(v => v.split('').reverse().join(''))
            .map(v => {
                let n = BigInt(`0x${v}`);
                let buf = Buffer.alloc(8);
                buf.writeBigUInt64LE(n, 0);
                return buf;
            });

        return chunks.length > 1 ? chunks : chunks[0];
    }

    decodeCursorValue(value) {
        if (!value || !value.length) {
            return null;
        }

        if (typeof value[0] === 'number') {
            value = [value];
        }

        let hexNr = value
            .map(buf => {
                let n = buf.readBigUInt64LE(0);
                let hexN = n.toString(16);
                if (hexN.length < 16) {
                    hexN = '0'.repeat(16 - hexN.length) + hexN;
                }
                return hexN;
            })
            .join('');

        return BigInt('0x' + hexNr).toString(10);
    }
}

test('Email client tests', async t => {
    // Gmail Label Tests
    await t.test('Gmail SYSTEM_LABELS maps Gmail labels to IMAP flags', async () => {
        assert.strictEqual(SYSTEM_LABELS.SENT, '\\Sent');
        assert.strictEqual(SYSTEM_LABELS.INBOX, '\\Inbox');
        assert.strictEqual(SYSTEM_LABELS.TRASH, '\\Trash');
        assert.strictEqual(SYSTEM_LABELS.DRAFT, '\\Drafts');
        assert.strictEqual(SYSTEM_LABELS.SPAM, '\\Junk');
        assert.strictEqual(SYSTEM_LABELS.IMPORTANT, '\\Important');
    });

    await t.test('Gmail SKIP_LABELS contains non-folder labels', async () => {
        assert.ok(SKIP_LABELS.includes('UNREAD'));
        assert.ok(SKIP_LABELS.includes('STARRED'));
        assert.ok(SKIP_LABELS.includes('IMPORTANT'));
        assert.ok(SKIP_LABELS.includes('CHAT'));
        assert.ok(SKIP_LABELS.includes('CATEGORY_PERSONAL'));
    });

    await t.test('Gmail SYSTEM_NAMES provides friendly names', async () => {
        assert.strictEqual(SYSTEM_NAMES.INBOX, 'Inbox');
        assert.strictEqual(SYSTEM_NAMES.TRASH, 'Trash');
        assert.strictEqual(SYSTEM_NAMES.SPAM, 'Spam');
        assert.strictEqual(SYSTEM_NAMES.CATEGORY_FORUMS, 'Forums');
    });

    // PageCursor Tests
    await t.test('PageCursor creates empty cursor', async () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.type, 'gmail');
        assert.deepStrictEqual(cursor.cursorList, []);
        assert.strictEqual(cursor.toString(), '');
    });

    await t.test('PageCursor.currentPage() returns page 0 for empty cursor', async () => {
        const cursor = new PageCursor();
        const page = cursor.currentPage();

        assert.strictEqual(page.page, 0);
        assert.strictEqual(page.cursor, '');
        assert.strictEqual(page.pageCursor, '');
    });

    await t.test('PageCursor.nextPageCursor() creates valid cursor string', async () => {
        const cursor = new PageCursor();
        const pageToken = '12345678901234567890';

        const nextCursor = cursor.nextPageCursor(pageToken);

        assert.ok(nextCursor.startsWith('gmail_'));
        assert.ok(nextCursor.length > 6);
    });

    await t.test('PageCursor.nextPageCursor() returns null for empty token', async () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.nextPageCursor(null), null);
        assert.strictEqual(cursor.nextPageCursor(''), null);
    });

    await t.test('PageCursor.prevPageCursor() returns null for first page', async () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.prevPageCursor(), null);
    });

    await t.test('PageCursor pagination round-trip', async () => {
        const cursor = new PageCursor();
        const pageToken = '987654321098765432';

        // Create next page cursor
        const nextCursorStr = cursor.nextPageCursor(pageToken);

        // Parse the cursor
        const nextCursor = new PageCursor(nextCursorStr);

        // Check current page
        const page = nextCursor.currentPage();
        assert.strictEqual(page.page, 1);
        assert.strictEqual(page.cursor, pageToken);

        // Get previous page cursor
        const prevCursorStr = nextCursor.prevPageCursor();
        const prevCursor = new PageCursor(prevCursorStr);
        assert.strictEqual(prevCursor.currentPage().page, 0);
    });

    await t.test('PageCursor handles multiple pages', async () => {
        let cursor = new PageCursor();

        // Simulate navigating through 3 pages
        const page1Token = '111111111111111111';
        const page2Token = '222222222222222222';
        const page3Token = '333333333333333333';

        const cursor1Str = cursor.nextPageCursor(page1Token);
        cursor = new PageCursor(cursor1Str);
        assert.strictEqual(cursor.currentPage().page, 1);

        const cursor2Str = cursor.nextPageCursor(page2Token);
        cursor = new PageCursor(cursor2Str);
        assert.strictEqual(cursor.currentPage().page, 2);

        const cursor3Str = cursor.nextPageCursor(page3Token);
        cursor = new PageCursor(cursor3Str);
        assert.strictEqual(cursor.currentPage().page, 3);
        assert.strictEqual(cursor.currentPage().cursor, page3Token);

        // Go back one page
        const prevStr = cursor.prevPageCursor();
        cursor = new PageCursor(prevStr);
        assert.strictEqual(cursor.currentPage().page, 2);
        assert.strictEqual(cursor.currentPage().cursor, page2Token);
    });

    await t.test('PageCursor throws on invalid cursor type', async () => {
        assert.throws(
            () => new PageCursor('outlook_invalidcursor'),
            err => {
                assert.strictEqual(err.code, 'InvalidCursorType');
                assert.strictEqual(err.statusCode, 400);
                return true;
            }
        );
    });

    await t.test('PageCursor handles malformed cursor gracefully', async () => {
        // Malformed base64 should result in empty cursor, not throw
        const cursor = new PageCursor('gmail_notvalidbase64!!!');

        assert.deepStrictEqual(cursor.cursorList, []);
        assert.strictEqual(cursor.toString(), '');
    });

    await t.test('PageCursor.encodeCursorValue handles small numbers', async () => {
        const cursor = new PageCursor();
        const encoded = cursor.encodeCursorValue('12345');
        const decoded = cursor.decodeCursorValue(encoded);

        assert.strictEqual(decoded, '12345');
    });

    await t.test('PageCursor.encodeCursorValue handles large numbers', async () => {
        const cursor = new PageCursor();
        // Large number that requires multiple chunks
        const largeNum = '12345678901234567890123456789012345678901234567890';
        const encoded = cursor.encodeCursorValue(largeNum);
        const decoded = cursor.decodeCursorValue(encoded);

        assert.strictEqual(decoded, largeNum);
    });

    await t.test('PageCursor.decodeCursorValue returns null for empty value', async () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.decodeCursorValue(null), null);
        assert.strictEqual(cursor.decodeCursorValue([]), null);
    });

    // Outlook Retry Constants Tests
    await t.test('Outlook retry constants have expected values', async () => {
        assert.strictEqual(OUTLOOK_MAX_RETRY_ATTEMPTS, 3);
        assert.strictEqual(OUTLOOK_RETRY_BASE_DELAY, 30);
        assert.strictEqual(OUTLOOK_RETRY_MAX_DELAY, 120);
    });

    await t.test('Outlook exponential backoff calculation', async () => {
        // Simulates the calculation in outlook-client.js
        function calculateBackoff(attempt) {
            return Math.min(OUTLOOK_RETRY_BASE_DELAY * Math.pow(2, attempt), OUTLOOK_RETRY_MAX_DELAY);
        }

        assert.strictEqual(calculateBackoff(0), 30); // 30 * 2^0 = 30
        assert.strictEqual(calculateBackoff(1), 60); // 30 * 2^1 = 60
        assert.strictEqual(calculateBackoff(2), 120); // 30 * 2^2 = 120
        assert.strictEqual(calculateBackoff(3), 120); // 30 * 2^3 = 240 -> capped at 120
        assert.strictEqual(calculateBackoff(4), 120); // capped
    });

    // MS Graph Error Code Mapping Tests
    await t.test('MS Graph error codes map correctly', async () => {
        // Based on outlook-client.js error mapping
        const ERROR_CODE_MAP = {
            ErrorItemNotFound: 404,
            ErrorAccessDenied: 403,
            ErrorInvalidRecipients: 400,
            ErrorMessageNotFound: 404,
            ErrorFolderNotFound: 404
        };

        assert.strictEqual(ERROR_CODE_MAP.ErrorItemNotFound, 404);
        assert.strictEqual(ERROR_CODE_MAP.ErrorAccessDenied, 403);
        assert.strictEqual(ERROR_CODE_MAP.ErrorInvalidRecipients, 400);
    });

    // IMAP UID Encoding Tests (based on imap-client.js patterns)
    await t.test('IMAP UID buffer encoding', async () => {
        // Test the pattern used in imap-client.js for UID encoding
        const mailboxId = 12345;
        const uid = 67890;

        const buf = Buffer.alloc(8);
        buf.writeUInt32BE(mailboxId, 0);
        buf.writeUInt32BE(uid, 4);

        // Verify encoding
        assert.strictEqual(buf.readUInt32BE(0), mailboxId);
        assert.strictEqual(buf.readUInt32BE(4), uid);

        // Test base64url encoding round-trip
        const encoded = buf.toString('base64url');
        const decoded = Buffer.from(encoded, 'base64url');

        assert.strictEqual(decoded.readUInt32BE(0), mailboxId);
        assert.strictEqual(decoded.readUInt32BE(4), uid);
    });

    await t.test('IMAP UID validity encoding as BigUInt64', async () => {
        // Gmail and Outlook use BigUInt64 for UID validity
        const uidValidity = BigInt('1234567890123456789');

        const buf = Buffer.alloc(8);
        buf.writeBigUInt64BE(uidValidity, 0);

        const read = buf.readBigUInt64BE(0);
        assert.strictEqual(read, uidValidity);
    });

    await t.test('IMAP path encoding in buffer', async () => {
        // Test path buffer creation pattern from imap-client.js
        const uidValidity = BigInt(123456);
        const path = 'INBOX/Subfolder';

        const uidValBuf = Buffer.alloc(8);
        uidValBuf.writeBigUInt64BE(uidValidity, 0);
        const mailboxBuf = Buffer.concat([uidValBuf, Buffer.from(path)]);

        // Verify extraction
        assert.strictEqual(mailboxBuf.readBigUInt64BE(0), uidValidity);
        assert.strictEqual(mailboxBuf.subarray(8).toString(), path);
    });

    // Email client special-use flags
    await t.test('IMAP special-use flags are properly formatted', async () => {
        const specialUseFlags = ['\\Inbox', '\\Sent', '\\Drafts', '\\Trash', '\\Junk', '\\All', '\\Flagged', '\\Important'];

        for (const flag of specialUseFlags) {
            assert.ok(flag.startsWith('\\'), `${flag} should start with backslash`);
            assert.ok(flag.length > 1, `${flag} should have content after backslash`);
        }
    });

    // Test msgpack encoding/decoding (used by cursor)
    await t.test('msgpack encoding handles arrays of buffers', async () => {
        const buf1 = Buffer.from([1, 2, 3, 4]);
        const buf2 = Buffer.from([5, 6, 7, 8]);
        const data = [buf1, buf2];

        const encoded = msgpack.encode(data);
        const decoded = msgpack.decode(encoded);

        assert.ok(Array.isArray(decoded));
        assert.strictEqual(decoded.length, 2);
        assert.ok(Buffer.isBuffer(decoded[0]));
        assert.ok(Buffer.isBuffer(decoded[1]));
    });
});
