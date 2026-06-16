'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Exercise the real Gmail client building blocks instead of copies. PageCursor
// and the label maps are the actual implementations from gmail-client.js, so a
// regression in pagination or label mapping now fails this suite.
const { PageCursor, SKIP_LABELS, SYSTEM_LABELS, SYSTEM_NAMES } = require('../lib/email-client/gmail-client');
const { redis } = require('../lib/db');

test.after(async () => {
    // gmail-client transitively opens a Redis connection via base-client -> lib/db.
    try {
        await redis.quit();
    } catch (err) {
        // ignore - connection may already be closing
    }
});

test('Gmail client building blocks', async t => {
    // Gmail Label Tests
    await t.test('SYSTEM_LABELS maps Gmail labels to IMAP flags', () => {
        assert.strictEqual(SYSTEM_LABELS.SENT, '\\Sent');
        assert.strictEqual(SYSTEM_LABELS.INBOX, '\\Inbox');
        assert.strictEqual(SYSTEM_LABELS.TRASH, '\\Trash');
        assert.strictEqual(SYSTEM_LABELS.DRAFT, '\\Drafts');
        assert.strictEqual(SYSTEM_LABELS.SPAM, '\\Junk');
        assert.strictEqual(SYSTEM_LABELS.IMPORTANT, '\\Important');
    });

    await t.test('SKIP_LABELS contains non-folder labels', () => {
        assert.ok(SKIP_LABELS.includes('UNREAD'));
        assert.ok(SKIP_LABELS.includes('STARRED'));
        assert.ok(SKIP_LABELS.includes('IMPORTANT'));
        assert.ok(SKIP_LABELS.includes('CHAT'));
        assert.ok(SKIP_LABELS.includes('CATEGORY_PERSONAL'));
    });

    await t.test('SYSTEM_NAMES provides friendly names', () => {
        assert.strictEqual(SYSTEM_NAMES.INBOX, 'Inbox');
        assert.strictEqual(SYSTEM_NAMES.TRASH, 'Trash');
        assert.strictEqual(SYSTEM_NAMES.SPAM, 'Spam');
        assert.strictEqual(SYSTEM_NAMES.CATEGORY_FORUMS, 'Forums');
    });

    // PageCursor Tests
    await t.test('PageCursor creates empty cursor', () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.type, 'gmail');
        assert.deepStrictEqual(cursor.cursorList, []);
        assert.strictEqual(cursor.toString(), '');
    });

    await t.test('PageCursor.currentPage() returns page 0 for empty cursor', () => {
        const cursor = new PageCursor();
        const page = cursor.currentPage();

        assert.strictEqual(page.page, 0);
        assert.strictEqual(page.cursor, '');
        assert.strictEqual(page.pageCursor, '');
    });

    await t.test('PageCursor.nextPageCursor() creates valid cursor string', () => {
        const cursor = new PageCursor();
        const pageToken = '12345678901234567890';

        const nextCursor = cursor.nextPageCursor(pageToken);

        assert.ok(nextCursor.startsWith('gmail_'));
        assert.ok(nextCursor.length > 6);
    });

    await t.test('PageCursor.nextPageCursor() returns null for empty token', () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.nextPageCursor(null), null);
        assert.strictEqual(cursor.nextPageCursor(''), null);
    });

    await t.test('PageCursor.prevPageCursor() returns null for first page', () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.prevPageCursor(), null);
    });

    await t.test('PageCursor pagination round-trip', () => {
        const cursor = new PageCursor();
        const pageToken = '987654321098765432';

        const nextCursorStr = cursor.nextPageCursor(pageToken);
        const nextCursor = new PageCursor(nextCursorStr);

        const page = nextCursor.currentPage();
        assert.strictEqual(page.page, 1);
        assert.strictEqual(page.cursor, pageToken);

        const prevCursorStr = nextCursor.prevPageCursor();
        const prevCursor = new PageCursor(prevCursorStr);
        assert.strictEqual(prevCursor.currentPage().page, 0);
    });

    await t.test('PageCursor handles multiple pages', () => {
        let cursor = new PageCursor();

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

        const prevStr = cursor.prevPageCursor();
        cursor = new PageCursor(prevStr);
        assert.strictEqual(cursor.currentPage().page, 2);
        assert.strictEqual(cursor.currentPage().cursor, page2Token);
    });

    await t.test('PageCursor throws on invalid cursor type', () => {
        assert.throws(
            () => new PageCursor('outlook_invalidcursor'),
            err => {
                assert.strictEqual(err.code, 'InvalidCursorType');
                assert.strictEqual(err.statusCode, 400);
                return true;
            }
        );
    });

    await t.test('PageCursor handles malformed cursor gracefully', () => {
        // Malformed base64 should result in empty cursor, not throw
        const cursor = new PageCursor('gmail_notvalidbase64!!!');

        assert.deepStrictEqual(cursor.cursorList, []);
        assert.strictEqual(cursor.toString(), '');
    });

    await t.test('PageCursor.encodeCursorValue handles small numbers', () => {
        const cursor = new PageCursor();
        const encoded = cursor.encodeCursorValue('12345');
        const decoded = cursor.decodeCursorValue(encoded);

        assert.strictEqual(decoded, '12345');
    });

    await t.test('PageCursor.encodeCursorValue handles large numbers', () => {
        const cursor = new PageCursor();
        // Large number that requires multiple chunks
        const largeNum = '12345678901234567890123456789012345678901234567890';
        const encoded = cursor.encodeCursorValue(largeNum);
        const decoded = cursor.decodeCursorValue(encoded);

        assert.strictEqual(decoded, largeNum);
    });

    await t.test('PageCursor.decodeCursorValue returns null for empty value', () => {
        const cursor = new PageCursor();

        assert.strictEqual(cursor.decodeCursorValue(null), null);
        assert.strictEqual(cursor.decodeCursorValue([]), null);
    });
});
