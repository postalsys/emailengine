'use strict';

require('dotenv').config({ quiet: true });

const test = require('node:test');
const assert = require('node:assert').strict;

const { formatExtraScopes } = require('../lib/oauth2-apps');

test('formatExtraScopes', async t => {
    t.after(async () => {
        // force close because we loaded ../lib/oauth2-apps that spwans the db connection and queues
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
