'use strict';

// The IDLE restart interval of an IMAP connection (ImapFlow's maxIdleTime). A few providers get a
// built-in value, and an account can set imap.maxIdleTime for a server, or a proxy or firewall in
// front of it, that drops a connection left in IDLE for a few minutes without sending BYE. The
// account value has to win over the built-in one, and it has to reach OAuth2 accounts too, whose
// connection config is built without the stored imap object.

const test = require('node:test');
const assert = require('node:assert').strict;
const Joi = require('joi');

const { applyIdleSettings } = require('../lib/email-client/imap/idle-settings');
const { imapSchema, imapUpdateSchema } = require('../lib/schemas');
const { IMAP_MAX_IDLE_TIME_MIN, IMAP_MAX_IDLE_TIME_MAX } = require('../lib/consts');

// applyIdleSettings() works in place, like the connection config it is called on
const applied = (imapConfig, accountImap) => {
    applyIdleSettings(imapConfig, accountImap);
    return imapConfig;
};

test('applyIdleSettings()', async t => {
    await t.test('a host with no workaround gets nothing', () => {
        const config = applied({ host: 'imap.example.com' });
        assert.equal(config.maxIdleTime, undefined);
        assert.equal(config.missingIdleCommand, undefined);
    });

    await t.test('the provider workarounds are kept', () => {
        assert.equal(applied({ host: 'imap.mail.yahoo.com' }).maxIdleTime, 3 * 60 * 1000);
        assert.equal(applied({ host: 'imap.rambler.ru' }).maxIdleTime, 55 * 1000);
        assert.deepEqual(applied({ host: 'imap.163.com' }), { host: 'imap.163.com', maxIdleTime: 55 * 1000, missingIdleCommand: 'STATUS' });
    });

    await t.test('the account interval applies to any host', () => {
        assert.equal(applied({ host: 'mail.zxcs.nl' }, { maxIdleTime: 120000 }).maxIdleTime, 120000);
    });

    await t.test('the account interval outranks a provider workaround, which keeps its keepalive command', () => {
        const config = applied({ host: 'imap.163.com' }, { maxIdleTime: 30000 });
        assert.equal(config.maxIdleTime, 30000);
        assert.equal(config.missingIdleCommand, 'STATUS');
    });

    await t.test('a cleared account interval falls back to the provider value', () => {
        // A password account's stored imap object is merged into the config, so the null that clears
        // the setting arrives in both arguments
        assert.equal(applied({ host: 'imap.mail.yahoo.com', maxIdleTime: null }, { maxIdleTime: null }).maxIdleTime, 3 * 60 * 1000);
    });

    await t.test('an OAuth2 config built without the imap object still gets the account value', () => {
        const config = applied({ host: 'outlook.office365.com', auth: { user: 'u', accessToken: 't' } }, { maxIdleTime: 240000 });
        assert.equal(config.maxIdleTime, 240000);
    });
});

test('imap.maxIdleTime schema', async t => {
    const create = Joi.object(imapSchema);
    const update = Joi.object(imapUpdateSchema);
    const base = { host: 'imap.example.com', port: 993, auth: { user: 'u', pass: 'p' } };

    await t.test('a value inside the bounds is accepted', () => {
        assert.ifError(create.validate(Object.assign({}, base, { maxIdleTime: 120000 })).error);
        assert.ifError(update.validate({ partial: true, maxIdleTime: 120000 }).error);
        assert.ifError(create.validate(Object.assign({}, base, { maxIdleTime: IMAP_MAX_IDLE_TIME_MIN })).error);
        assert.ifError(create.validate(Object.assign({}, base, { maxIdleTime: IMAP_MAX_IDLE_TIME_MAX })).error);
    });

    await t.test('a value outside the bounds is refused', () => {
        for (const value of [IMAP_MAX_IDLE_TIME_MIN - 1, IMAP_MAX_IDLE_TIME_MAX + 1, 0, 1.5]) {
            assert.ok(create.validate(Object.assign({}, base, { maxIdleTime: value })).error, `create refuses ${value}`);
            assert.ok(update.validate({ partial: true, maxIdleTime: value }).error, `update refuses ${value}`);
        }
    });

    await t.test('an update can clear it, a create has nothing to clear', () => {
        assert.ifError(update.validate({ partial: true, maxIdleTime: null }).error);
        assert.ok(create.validate(Object.assign({}, base, { maxIdleTime: null })).error);
    });
});

test('commandSocketTimeout', async t => {
    const { commandSocketTimeout, COMMAND_SOCKET_TIMEOUT } = require('../lib/email-client/imap/idle-settings');
    const { forAll, gen } = require('./helpers/property');

    await t.test('keeps the one minute default when no IDLE interval is set', () => {
        for (const value of [undefined, null, 0, false]) {
            assert.strictEqual(commandSocketTimeout(value), COMMAND_SOCKET_TIMEOUT);
        }
    });

    await t.test('a 20 second interval (TransIP) closes the command connection by then', () => {
        assert.strictEqual(commandSocketTimeout(20 * 1000), 20 * 1000);
    });

    await t.test('property: never longer than the interval or the default, never zero', () => {
        forAll(
            gen.withEdges(gen.integer(IMAP_MAX_IDLE_TIME_MIN, IMAP_MAX_IDLE_TIME_MAX), [
                IMAP_MAX_IDLE_TIME_MIN,
                IMAP_MAX_IDLE_TIME_MAX,
                COMMAND_SOCKET_TIMEOUT
            ]),
            maxIdleTime => {
                const timeout = commandSocketTimeout(maxIdleTime);
                assert.ok(timeout > 0);
                assert.ok(timeout <= maxIdleTime);
                assert.ok(timeout <= COMMAND_SOCKET_TIMEOUT);
                assert.strictEqual(timeout, Math.min(maxIdleTime, COMMAND_SOCKET_TIMEOUT));
            }
        );
    });

    await t.test('the command connection is built with it', () => {
        const source = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'lib', 'email-client', 'imap-client.js'), 'utf-8');
        assert.match(source, /socketTimeout: commandSocketTimeout\(imapConfig\.maxIdleTime\)/);
    });
});
