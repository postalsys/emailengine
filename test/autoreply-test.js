'use strict';

// Test fixtures in fixtures/autoreply/ are from:
// https://github.com/sisimai/set-of-emails/
// Licensed under BSD 2-Clause License, Copyright (C) 2014, azumakuniyuki

const test = require('node:test');
const assert = require('node:assert').strict;

const { simpleParser } = require('mailparser');
const fs = require('fs');
const Path = require('path');

const path = fname => Path.join(__dirname, 'fixtures', 'autoreply', fname);

// Replicate isAutoreply logic from base-client.js for testing
function isAutoreply(messageData) {
    // Check subject patterns - these are strong autoreply indicators
    // Note: "Automatic reply:" and "Auto reply:" (with space) are common variants
    // "Out of the Office" is also valid (with "the")
    if (/^(auto(matic)?\s*(reply|response)|Out of(?: the)? Office|OOF:|OOO:)/i.test(messageData.subject)) {
        return true;
    }

    // Weaker subject patterns require inReplyTo as confirmation
    if (/^auto:/i.test(messageData.subject) && messageData.inReplyTo) {
        return true;
    }

    if (!messageData.headers) {
        return false;
    }

    // Check Precedence header
    if (messageData.headers.precedence && messageData.headers.precedence.some(e => /auto[_-]?reply/.test(e))) {
        return true;
    }

    // Check Auto-Submitted header (RFC 3834)
    if (messageData.headers['auto-submitted'] && messageData.headers['auto-submitted'].some(e => /auto[_-]?replied/.test(e))) {
        return true;
    }

    // Check X-Auto-Response-Suppress header (Microsoft Exchange)
    // Values like "All", "OOF", "AutoReply" indicate this is an autoreply
    if (messageData.headers['x-auto-response-suppress'] && messageData.headers['x-auto-response-suppress'].length) {
        return true;
    }

    // Check various vendor-specific headers
    for (let headerKey of ['x-autoresponder', 'x-autorespond', 'x-autoreply']) {
        if (messageData.headers[headerKey] && messageData.headers[headerKey].length) {
            return true;
        }
    }

    return false;
}

// Convert parsed email headers to the format expected by isAutoreply
function convertHeaders(parsed) {
    const headers = {};
    if (parsed.headers) {
        for (let [key, value] of parsed.headers) {
            let normalizedKey = key.toLowerCase();
            if (!headers[normalizedKey]) {
                headers[normalizedKey] = [];
            }
            headers[normalizedKey].push(value);
        }
    }
    return headers;
}

// Helper to parse email and prepare messageData for isAutoreply
async function parseForAutoreply(filePath) {
    const content = await fs.promises.readFile(filePath);
    const parsed = await simpleParser(content);

    return {
        subject: parsed.subject || '',
        inReplyTo: parsed.inReplyTo || null,
        headers: convertHeaders(parsed)
    };
}

test('RFC 3834 autoreply detection tests', async t => {
    await t.test('Auto-Submitted header detection (rfc3834-01)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-01.eml'));
        const result = isAutoreply(messageData);

        // Has Auto-Submitted: auto-replied header
        assert.strictEqual(result, true);
        assert.ok(messageData.headers['auto-submitted']);
        assert.ok(messageData.headers['auto-submitted'].some(e => /auto-replied/.test(e)));
    });

    await t.test('Automatic reply subject with X-Auto-Response-Suppress (rfc3834-02)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-02.eml'));
        const result = isAutoreply(messageData);

        // Has subject "Automatic reply:" and X-Auto-Response-Suppress: All
        assert.strictEqual(result, true);
        assert.ok(/^Automatic reply:/i.test(messageData.subject));
    });

    await t.test('Auto reply subject with In-Reply-To (rfc3834-03)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-03.eml'));
        const result = isAutoreply(messageData);

        // Has subject "Auto reply:" with In-Reply-To header
        assert.strictEqual(result, true);
        assert.ok(/^Auto reply:/i.test(messageData.subject));
        assert.ok(messageData.inReplyTo);
    });

    await t.test('Microsoft Exchange automatic reply (rfc3834-04)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-04.eml'));
        const result = isAutoreply(messageData);

        // Has subject "Automatic reply:" and X-Auto-Response-Suppress: All
        assert.strictEqual(result, true);
        assert.ok(messageData.headers['x-auto-response-suppress']);
    });

    await t.test('Auto-Submitted with random subject (rfc3834-05)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-05.eml'));
        const result = isAutoreply(messageData);

        // Has Auto-Submitted: auto-replied with non-standard subject
        assert.strictEqual(result, true);
        assert.ok(messageData.headers['auto-submitted']);
    });

    await t.test('Mimecast auto-response (rfc3834-06)', async () => {
        const messageData = await parseForAutoreply(path('rfc3834-06.eml'));
        const result = isAutoreply(messageData);

        // Has Auto-Submitted and X-Auto-Response-Suppress headers
        assert.strictEqual(result, true);
        assert.ok(messageData.headers['auto-submitted']);
        assert.ok(messageData.headers['x-auto-response-suppress']);
    });
});

test('isAutoreply heuristics', async t => {
    await t.test('Detects Out of Office subject', async () => {
        const messageData = {
            subject: 'Out of Office: I am away',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Out of the Office subject (with "the")', async () => {
        const messageData = {
            subject: 'Out of the Office: Mailtrain Newsletter',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects OOF prefix', async () => {
        const messageData = {
            subject: 'OOF: Automatic Reply',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects OOO prefix', async () => {
        const messageData = {
            subject: 'OOO: Out of Office',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Automatic reply subject', async () => {
        const messageData = {
            subject: 'Automatic reply: Your message',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Auto reply subject (with space)', async () => {
        const messageData = {
            subject: 'Auto reply: Thanks',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Automatic response subject', async () => {
        const messageData = {
            subject: 'Automatic response: Meeting',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Requires inReplyTo for weak auto: subject', async () => {
        const messageData = {
            subject: 'auto: Something',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), false);

        messageData.inReplyTo = '<some-message-id@example.com>';
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Precedence: auto_reply header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                precedence: ['auto_reply']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Precedence: auto-reply header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                precedence: ['auto-reply']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects Auto-Submitted: auto-replied header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                'auto-submitted': ['auto-replied']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects X-Auto-Response-Suppress header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                'x-auto-response-suppress': ['All']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects X-Autoresponder header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                'x-autoresponder': ['true']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects X-Autorespond header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                'x-autorespond': ['yes']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Detects X-Autoreply header', async () => {
        const messageData = {
            subject: 'Some subject',
            inReplyTo: null,
            headers: {
                'x-autoreply': ['yes']
            }
        };
        assert.strictEqual(isAutoreply(messageData), true);
    });

    await t.test('Rejects regular email', async () => {
        const messageData = {
            subject: 'Weekly Newsletter',
            inReplyTo: null,
            headers: {
                from: ['newsletter@example.com']
            }
        };
        assert.strictEqual(isAutoreply(messageData), false);
    });

    await t.test('Rejects email with similar but non-matching subject', async () => {
        const messageData = {
            subject: 'Automatic update notification',
            inReplyTo: null,
            headers: {}
        };
        assert.strictEqual(isAutoreply(messageData), false);
    });

    await t.test('Handles missing headers gracefully', async () => {
        const messageData = {
            subject: 'Test',
            inReplyTo: null,
            headers: null
        };
        assert.strictEqual(isAutoreply(messageData), false);
    });
});
