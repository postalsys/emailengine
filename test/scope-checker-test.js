'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    checkAccountScopes,
    checkGmailScopes,
    checkOutlookScopes,
    isSendOnlyByScopes,
    normalizeMsGraphScope,
    GMAIL_API_SCOPES,
    OUTLOOK_API_SCOPES,
    MS_GRAPH_DOMAINS
} = require('../lib/oauth/scope-checker');

test('OAuth Scope Checker tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // Constants tests
    await t.test('GMAIL_API_SCOPES contains expected scopes', async () => {
        assert.ok(GMAIL_API_SCOPES.send);
        assert.ok(GMAIL_API_SCOPES.modify || GMAIL_API_SCOPES.readonly);
    });

    await t.test('OUTLOOK_API_SCOPES contains expected scopes', async () => {
        assert.ok(OUTLOOK_API_SCOPES.send);
        assert.ok(OUTLOOK_API_SCOPES.read || OUTLOOK_API_SCOPES.readWrite);
    });

    await t.test('MS_GRAPH_DOMAINS contains all cloud endpoints', async () => {
        assert.ok(MS_GRAPH_DOMAINS.includes('graph.microsoft.com'));
        assert.ok(MS_GRAPH_DOMAINS.includes('graph.microsoft.us'));
        assert.ok(MS_GRAPH_DOMAINS.includes('dod-graph.microsoft.us'));
        assert.ok(MS_GRAPH_DOMAINS.includes('microsoftgraph.chinacloudapi.cn'));
    });

    // normalizeMsGraphScope tests
    await t.test('normalizeMsGraphScope() passes through plain scope names', async () => {
        assert.strictEqual(normalizeMsGraphScope('offline_access'), 'offline_access');
        assert.strictEqual(normalizeMsGraphScope('openid'), 'openid');
        assert.strictEqual(normalizeMsGraphScope('profile'), 'profile');
    });

    await t.test('normalizeMsGraphScope() extracts scope from global cloud URL', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.com/Mail.Send'), 'Mail.Send');
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.com/Mail.ReadWrite'), 'Mail.ReadWrite');
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.com/Mail.Read'), 'Mail.Read');
    });

    await t.test('normalizeMsGraphScope() extracts scope from GCC-High cloud URL', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.us/Mail.Send'), 'Mail.Send');
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.us/Mail.ReadWrite'), 'Mail.ReadWrite');
    });

    await t.test('normalizeMsGraphScope() extracts scope from DoD cloud URL', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://dod-graph.microsoft.us/Mail.Send'), 'Mail.Send');
        assert.strictEqual(normalizeMsGraphScope('https://dod-graph.microsoft.us/Mail.ReadWrite'), 'Mail.ReadWrite');
    });

    await t.test('normalizeMsGraphScope() extracts scope from China cloud URL', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://microsoftgraph.chinacloudapi.cn/Mail.Send'), 'Mail.Send');
        assert.strictEqual(normalizeMsGraphScope('https://microsoftgraph.chinacloudapi.cn/Mail.ReadWrite'), 'Mail.ReadWrite');
    });

    await t.test('normalizeMsGraphScope() handles URL with trailing slash', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://graph.microsoft.com/Mail.Send/'), 'Mail.Send');
    });

    await t.test('normalizeMsGraphScope() returns original for unrecognized domain', async () => {
        assert.strictEqual(normalizeMsGraphScope('https://unknown.domain.com/Mail.Send'), 'https://unknown.domain.com/Mail.Send');
    });

    await t.test('normalizeMsGraphScope() returns original for non-https URL', async () => {
        assert.strictEqual(normalizeMsGraphScope('http://graph.microsoft.com/Mail.Send'), 'http://graph.microsoft.com/Mail.Send');
    });

    // checkAccountScopes tests - Gmail
    await t.test('checkAccountScopes() returns false for null/undefined scopes', async () => {
        assert.deepStrictEqual(checkAccountScopes('gmail', null), { hasSendScope: false, hasReadScope: false });
        assert.deepStrictEqual(checkAccountScopes('gmail', undefined), { hasSendScope: false, hasReadScope: false });
    });

    await t.test('checkAccountScopes() returns false for non-array scopes', async () => {
        assert.deepStrictEqual(checkAccountScopes('gmail', 'string'), { hasSendScope: false, hasReadScope: false });
        assert.deepStrictEqual(checkAccountScopes('gmail', {}), { hasSendScope: false, hasReadScope: false });
    });

    await t.test('checkAccountScopes() detects Gmail send scope', async () => {
        const scopes = ['https://www.googleapis.com/auth/gmail.send'];
        const result = checkAccountScopes('gmail', scopes);
        assert.strictEqual(result.hasSendScope, true);
        assert.strictEqual(result.hasReadScope, false);
    });

    await t.test('checkAccountScopes() detects Gmail read scopes (modify)', async () => {
        const scopes = ['https://www.googleapis.com/auth/gmail.modify'];
        const result = checkAccountScopes('gmail', scopes);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() detects Gmail read scopes (readonly)', async () => {
        const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];
        const result = checkAccountScopes('gmail', scopes);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() detects Gmail full mail access', async () => {
        const scopes = ['https://mail.google.com/'];
        const result = checkAccountScopes('gmail', scopes);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() detects Gmail send and read scopes together', async () => {
        const scopes = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'];
        const result = checkAccountScopes('gmail', scopes);
        assert.strictEqual(result.hasSendScope, true);
        assert.strictEqual(result.hasReadScope, true);
    });

    // checkAccountScopes tests - Outlook
    await t.test('checkAccountScopes() detects Outlook send scope (global)', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send', 'offline_access'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, true);
        assert.strictEqual(result.hasReadScope, false);
    });

    await t.test('checkAccountScopes() detects Outlook read scope (global)', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Read', 'offline_access'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, false);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() detects Outlook readWrite scope (global)', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.ReadWrite', 'offline_access'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() detects Outlook send and read scopes together', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send', 'https://graph.microsoft.com/Mail.ReadWrite'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, true);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() handles GCC-High Outlook scopes', async () => {
        const scopes = ['https://graph.microsoft.us/Mail.Send', 'https://graph.microsoft.us/Mail.ReadWrite'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, true);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkAccountScopes() handles DoD Outlook scopes', async () => {
        const scopes = ['https://dod-graph.microsoft.us/Mail.Send'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, true);
    });

    await t.test('checkAccountScopes() handles China cloud Outlook scopes', async () => {
        const scopes = ['https://microsoftgraph.chinacloudapi.cn/Mail.Send'];
        const result = checkAccountScopes('outlook', scopes);
        assert.strictEqual(result.hasSendScope, true);
    });

    // checkAccountScopes tests - Unknown provider
    await t.test('checkAccountScopes() returns false for unknown provider', async () => {
        const scopes = ['some.scope'];
        const result = checkAccountScopes('unknown', scopes);
        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    // checkGmailScopes tests
    await t.test('checkGmailScopes() extracts scopes from oauth2.scope', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://www.googleapis.com/auth/gmail.send']
            }
        };
        const result = checkGmailScopes(accountData);
        assert.strictEqual(result.hasSendScope, true);
    });

    await t.test('checkGmailScopes() extracts scopes from oauth2.accessToken.scope', async () => {
        const accountData = {
            oauth2: {
                accessToken: {
                    scope: ['https://www.googleapis.com/auth/gmail.modify']
                }
            }
        };
        const result = checkGmailScopes(accountData);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkGmailScopes() handles missing oauth2 data', async () => {
        const result = checkGmailScopes({});
        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('checkGmailScopes() handles null accountData', async () => {
        const result = checkGmailScopes(null);
        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    // checkOutlookScopes tests
    await t.test('checkOutlookScopes() extracts scopes from oauth2.scope', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://graph.microsoft.com/Mail.Send']
            }
        };
        const result = checkOutlookScopes(accountData);
        assert.strictEqual(result.hasSendScope, true);
    });

    await t.test('checkOutlookScopes() extracts scopes from oauth2.accessToken.scope', async () => {
        const accountData = {
            oauth2: {
                accessToken: {
                    scope: ['https://graph.microsoft.com/Mail.ReadWrite']
                }
            }
        };
        const result = checkOutlookScopes(accountData);
        assert.strictEqual(result.hasReadScope, true);
    });

    await t.test('checkOutlookScopes() handles missing oauth2 data', async () => {
        const result = checkOutlookScopes({});
        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    // isSendOnlyByScopes tests
    await t.test('isSendOnlyByScopes() returns true for send-only Gmail account', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://www.googleapis.com/auth/gmail.send']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('gmail', accountData), true);
    });

    await t.test('isSendOnlyByScopes() returns false for Gmail account with read scope', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('gmail', accountData), false);
    });

    await t.test('isSendOnlyByScopes() returns true for send-only Outlook account', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://graph.microsoft.com/Mail.Send', 'offline_access']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('outlook', accountData), true);
    });

    await t.test('isSendOnlyByScopes() returns false for Outlook account with read scope', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://graph.microsoft.com/Mail.Send', 'https://graph.microsoft.com/Mail.ReadWrite']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('outlook', accountData), false);
    });

    await t.test('isSendOnlyByScopes() returns false for account with no send scope', async () => {
        const accountData = {
            oauth2: {
                scope: ['https://www.googleapis.com/auth/gmail.readonly']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('gmail', accountData), false);
    });

    await t.test('isSendOnlyByScopes() returns false for unknown provider', async () => {
        const accountData = {
            oauth2: {
                scope: ['some.scope']
            }
        };
        assert.strictEqual(isSendOnlyByScopes('unknown', accountData), false);
    });
});
