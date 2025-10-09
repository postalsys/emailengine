'use strict';

require('dotenv').config({ quiet: true });

const test = require('node:test');
const assert = require('node:assert').strict;

const { formatExtraScopes } = require('../lib/oauth2-apps');
const { Account } = require('../lib/account');

test('formatExtraScopes', async t => {
    t.after(async () => {
        // force close because we loaded ../lib/oauth2-apps that spawns the db connection and queues
        setTimeout(() => process.exit(), 5000).unref();
    });

    await t.test('should filter out Gmail scopes using short form', async () => {
        const defaultScopes = [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.labels'
        ];

        const result = formatExtraScopes([], null, defaultScopes, ['gmail.modify'], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels']);
    });

    await t.test('should filter out Gmail scopes using full URL', async () => {
        const defaultScopes = [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.labels'
        ];

        const result = formatExtraScopes([], null, defaultScopes, ['https://www.googleapis.com/auth/gmail.modify'], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels']);
    });

    await t.test('should filter multiple Gmail scopes', async () => {
        const defaultScopes = [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.labels'
        ];

        const result = formatExtraScopes([], null, defaultScopes, ['gmail.modify', 'gmail.readonly', 'gmail.labels'], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send']);
    });

    await t.test('should add extra Gmail scopes', async () => {
        const defaultScopes = ['https://www.googleapis.com/auth/gmail.modify'];

        const result = formatExtraScopes(['https://www.googleapis.com/auth/gmail.send'], null, defaultScopes, [], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify']);
    });

    await t.test('should add extra scopes and filter out unwanted ones', async () => {
        const defaultScopes = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.labels'];

        const result = formatExtraScopes(['https://www.googleapis.com/auth/gmail.send'], null, defaultScopes, ['gmail.modify'], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels']);
    });

    await t.test('should handle send-only configuration', async () => {
        const defaultScopes = ['https://www.googleapis.com/auth/gmail.modify'];

        const result = formatExtraScopes(['https://www.googleapis.com/auth/gmail.send'], null, defaultScopes, ['gmail.modify'], null);

        assert.deepStrictEqual(result, ['https://www.googleapis.com/auth/gmail.send']);
    });

    await t.test('should filter out Outlook scopes using short form', async () => {
        const defaultScopes = [
            'https://outlook.office.com/IMAP.AccessAsUser.All',
            'https://outlook.office.com/SMTP.Send',
            'https://outlook.office.com/User.Read'
        ];

        const result = formatExtraScopes([], null, defaultScopes, ['IMAP.AccessAsUser.All'], null);

        assert.deepStrictEqual(result, ['https://outlook.office.com/SMTP.Send', 'https://outlook.office.com/User.Read']);
    });

    await t.test('should filter out Microsoft Graph scopes', async () => {
        const defaultScopes = ['https://graph.microsoft.com/Mail.ReadWrite', 'https://graph.microsoft.com/Mail.Send', 'https://graph.microsoft.com/User.Read'];

        const result = formatExtraScopes([], null, defaultScopes, ['Mail.ReadWrite'], null);

        assert.deepStrictEqual(result, ['https://graph.microsoft.com/Mail.Send', 'https://graph.microsoft.com/User.Read']);
    });

    await t.test('should filter out full URL Outlook scopes', async () => {
        const defaultScopes = ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send'];

        const result = formatExtraScopes([], null, defaultScopes, ['https://outlook.office.com/IMAP.AccessAsUser.All'], null);

        assert.deepStrictEqual(result, ['https://outlook.office.com/SMTP.Send']);
    });

    await t.test('should return default scopes when no extras or skips', async () => {
        const defaultScopes = ['scope1', 'scope2'];

        const result = formatExtraScopes(null, null, defaultScopes, [], null);

        assert.deepStrictEqual(result, ['scope1', 'scope2']);
    });

    await t.test('should handle empty skipScopes array', async () => {
        const defaultScopes = ['scope1', 'scope2'];

        const result = formatExtraScopes(['scope3'], null, defaultScopes, [], null);

        assert.deepStrictEqual(result, ['scope3', 'scope1', 'scope2']);
    });

    await t.test('should not duplicate scopes already in defaults', async () => {
        const defaultScopes = ['scope1', 'scope2'];

        const result = formatExtraScopes(['scope1', 'scope3'], null, defaultScopes, [], null);

        assert.deepStrictEqual(result, ['scope3', 'scope1', 'scope2']);
    });

    await t.test('should handle scopePrefix correctly', async () => {
        const defaultScopes = ['prefix/scope1', 'prefix/scope2'];

        const result = formatExtraScopes(['scope1', 'scope3'], null, defaultScopes, [], 'prefix');

        assert.deepStrictEqual(result, ['scope3', 'prefix/scope1', 'prefix/scope2']);
    });
});

test('checkAccountScopes - Outlook', async t => {
    let account;

    t.beforeEach(() => {
        // Create a mock account instance with minimal required properties
        account = new Account({
            redis: {},
            account: 'test-account',
            secret: 'test-secret',
            logger: {
                warn: () => {},
                error: () => {},
                info: () => {},
                debug: () => {}
            }
        });
    });

    await t.test('should detect send-only Outlook account (global cloud)', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should detect full-access Outlook account (global cloud)', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.ReadWrite', 'https://graph.microsoft.com/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: true });
    });

    await t.test('should detect send-only Outlook account (GCC-High cloud)', async () => {
        const scopes = ['https://graph.microsoft.us/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should detect full-access Outlook account (GCC-High cloud)', async () => {
        const scopes = ['https://graph.microsoft.us/Mail.ReadWrite', 'https://graph.microsoft.us/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: true });
    });

    await t.test('should detect send-only Outlook account (DoD cloud)', async () => {
        const scopes = ['https://dod-graph.microsoft.us/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should detect full-access Outlook account (DoD cloud)', async () => {
        const scopes = ['https://dod-graph.microsoft.us/Mail.ReadWrite', 'https://dod-graph.microsoft.us/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: true });
    });

    await t.test('should detect send-only Outlook account (China cloud)', async () => {
        const scopes = ['https://microsoftgraph.chinacloudapi.cn/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should detect full-access Outlook account (China cloud)', async () => {
        const scopes = ['https://microsoftgraph.chinacloudapi.cn/Mail.ReadWrite', 'https://microsoftgraph.chinacloudapi.cn/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: true });
    });

    await t.test('should detect read-only Outlook account with Mail.Read', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Read', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: true });
    });

    await t.test('should handle scopes with trailing slashes', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send/', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should handle scopes with query parameters', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send?foo=bar', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should handle scopes with fragments', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send#section', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: false });
    });

    await t.test('should handle plain scope names', async () => {
        const scopes = ['offline_access', 'openid', 'profile'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle invalid protocol (http instead of https)', async () => {
        const scopes = ['http://graph.microsoft.com/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle non-Microsoft Graph domains', async () => {
        const scopes = ['https://evil.com/Mail.Send', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle malformed URLs', async () => {
        const scopes = ['not-a-url', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle empty scopes array', async () => {
        const scopes = [];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle null scopes', async () => {
        const result = account.checkAccountScopes('outlook', null);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle undefined scopes', async () => {
        const result = account.checkAccountScopes('outlook', undefined);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });

    await t.test('should handle mixed cloud scopes', async () => {
        const scopes = ['https://graph.microsoft.com/Mail.Send', 'https://graph.microsoft.us/Mail.ReadWrite', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: true, hasReadScope: true });
    });

    await t.test('should handle User.Read scope (not mail-related)', async () => {
        const scopes = ['https://graph.microsoft.com/User.Read', 'offline_access'];
        const result = account.checkAccountScopes('outlook', scopes);

        assert.deepStrictEqual(result, { hasSendScope: false, hasReadScope: false });
    });
});
