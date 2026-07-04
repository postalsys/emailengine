'use strict';

// Unit tests for lib/autodetect-imap-settings.js, which discovers a domain's
// IMAP/SMTP settings. The module's only network-free, deterministic surface is
// split across three pure helpers (XML escaping, app-password matching, and
// Mozilla-autoconfig XML parsing) plus the MX-driven resolver, which picks a
// hard-coded provider config from the primary MX exchange.
//
// The pure helpers are exercised directly. The resolver is exercised through the
// public autodetectImapSettings() with dns.promises mocked, staying on the MX
// branch (and the Gmail -> SRV branch) so no real DNS or HTTP is performed - the
// HTTP-based fallback resolvers (autoconfig/well-known/mozilla/autodiscover) are
// intentionally out of scope here.

const test = require('node:test');
const { mock } = require('node:test');
const assert = require('node:assert').strict;

const dns = require('dns').promises;

const { autodetectImapSettings, processAutoconfigFile, getAppPassword, escapeXml } = require('../lib/autodetect-imap-settings');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

// Minimal gettext stub - only the Microsoft app-password entry calls gt.gettext().
const gt = { gettext: s => s };

test('escapeXml', async t => {
    await t.test('escapes the five XML metacharacters', () => {
        assert.strictEqual(escapeXml(`<>&'"`), '&lt;&gt;&amp;&apos;&quot;');
    });

    await t.test('leaves ordinary characters untouched', () => {
        assert.strictEqual(escapeXml('user.name+tag@example.com'), 'user.name+tag@example.com');
    });

    await t.test('neutralizes an attempted XML injection in an email address', () => {
        const escaped = escapeXml('a@b.com</EMailAddress><injected>x');
        assert.doesNotMatch(escaped, /</);
        assert.doesNotMatch(escaped, />/);
        assert.match(escaped, /&lt;injected&gt;/);
    });

    await t.test('escapes each character independently (ampersand is not special-cased)', () => {
        assert.strictEqual(escapeXml('&lt;'), '&amp;lt;');
    });
});

test('getAppPassword', async t => {
    await t.test('matches by recipient domain (AOL)', () => {
        const result = getAppPassword('user@aol.com', 'whatever.example.com', gt);
        assert.strictEqual(result.provider, 'AOL');
        assert.strictEqual(result.required, true);
    });

    await t.test('matches the domain case-insensitively', () => {
        assert.strictEqual(getAppPassword('User@AOL.COM', null, gt).provider, 'AOL');
    });

    await t.test('matches the canonical provider domains without an exchange lookup', () => {
        // The hosted form's failAction re-render resolves the hint with exchange=false (no MX
        // lookup, no probe budget), so the big providers must match by domain alone.
        for (const [email, provider] of [
            ['user@gmail.com', 'Gmail'],
            ['user@googlemail.com', 'Gmail'],
            ['user@icloud.com', 'iCloud'],
            ['user@me.com', 'iCloud'],
            ['user@mac.com', 'iCloud'],
            ['user@outlook.com', 'Microsoft'],
            ['user@hotmail.com', 'Microsoft'],
            ['user@live.com', 'Microsoft'],
            ['user@t-online.de', 'T-Online']
        ]) {
            assert.strictEqual(getAppPassword(email, false, gt).provider, provider, `${email} should match ${provider} by domain`);
        }
    });

    await t.test('matches by MX exchange when the domain does not match (iCloud)', () => {
        const result = getAppPassword('user@customdomain.com', 'mx01.mail.icloud.com', gt);
        assert.strictEqual(result.provider, 'iCloud');
    });

    await t.test('matches Yahoo by its yahoodns.net exchange for a custom domain', () => {
        const result = getAppPassword('user@customdomain.com', 'mta5.am0.yahoodns.net', gt);
        assert.strictEqual(result.provider, 'Yahoo');
    });

    await t.test('matches Gmail by its l.google.com exchange', () => {
        assert.strictEqual(getAppPassword('user@customdomain.com', 'gmail-smtp-in.l.google.com', gt).provider, 'Gmail');
    });

    await t.test('returns the Microsoft warning for outlook.com exchanges', () => {
        const result = getAppPassword('user@customdomain.com', 'customdomain.mail.protection.outlook.com', gt);
        assert.strictEqual(result.provider, 'Microsoft');
        assert.match(result.warning, /password-based sign-ins/i);
    });

    await t.test('matches T-Online by exchange', () => {
        assert.strictEqual(getAppPassword('user@customdomain.com', 'mx00.t-online.de', gt).provider, 'T-Online');
    });

    await t.test('returns false when nothing matches', () => {
        assert.strictEqual(getAppPassword('user@example.com', 'mx.example.com', gt), false);
    });

    await t.test('returns false when there is no exchange and no domain match', () => {
        assert.strictEqual(getAppPassword('user@example.com', null, gt), false);
    });
});

test('processAutoconfigFile', async t => {
    const xml = (incoming, outgoing) => `<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="example.com">
    ${incoming}
    ${outgoing}
  </emailProvider>
</clientConfig>`;

    await t.test('parses IMAP and SMTP servers with placeholder substitution', async () => {
        const text = xml(
            `<incomingServer type="imap">
        <hostname>imap.example.com</hostname>
        <port>993</port>
        <socketType>SSL</socketType>
        <username>%EMAILADDRESS%</username>
      </incomingServer>`,
            `<outgoingServer type="smtp">
        <hostname>smtp.example.com</hostname>
        <port>587</port>
        <socketType>STARTTLS</socketType>
        <username>%EMAILLOCALPART%</username>
      </outgoingServer>`
        );

        const res = await processAutoconfigFile('john.doe@example.com', null, text, 'autoconfig');

        assert.deepStrictEqual(res.imap, {
            host: 'imap.example.com',
            port: 993,
            secure: true,
            auth: { user: 'john.doe@example.com' }
        });
        assert.deepStrictEqual(res.smtp, {
            host: 'smtp.example.com',
            port: 587,
            // Only "SSL" maps to secure:true; STARTTLS is secure:false.
            secure: false,
            auth: { user: 'john.doe' }
        });
        assert.strictEqual(res._source, 'autoconfig');
    });

    await t.test('substitutes %EMAILDOMAIN% in hostname and username', async () => {
        const text = xml(
            `<incomingServer type="imap">
        <hostname>%EMAILDOMAIN%</hostname>
        <port>143</port>
        <socketType>plain</socketType>
        <username>%EMAILDOMAIN%</username>
      </incomingServer>`,
            ''
        );
        const res = await processAutoconfigFile('john@sub.example.com', null, text, 'mozilla');
        assert.strictEqual(res.imap.host, 'sub.example.com');
        assert.strictEqual(res.imap.secure, false);
        assert.strictEqual(res.imap.auth.user, 'sub.example.com');
    });

    await t.test('returns false for imap/smtp when no matching servers are present', async () => {
        const res = await processAutoconfigFile('john@example.com', null, xml('', ''), 'autoconfig');
        assert.strictEqual(res.imap, false);
        assert.strictEqual(res.smtp, false);
    });

    await t.test('skips a POP3 incoming server and selects the IMAP one', async () => {
        const text = xml(
            `<incomingServer type="pop3">
        <hostname>pop.example.com</hostname>
        <port>995</port>
        <socketType>SSL</socketType>
      </incomingServer>
      <incomingServer type="imap">
        <hostname>imap.example.com</hostname>
        <port>993</port>
        <socketType>SSL</socketType>
      </incomingServer>`,
            ''
        );
        const res = await processAutoconfigFile('john@example.com', null, text, 'autoconfig');
        assert.strictEqual(res.imap.host, 'imap.example.com');
        // No <username> element -> no auth block is added.
        assert.strictEqual(res.imap.auth, undefined);
    });
});

test('autodetectImapSettings (MX resolver, mocked DNS)', async t => {
    t.afterEach(() => mock.restoreAll());

    const mockMx = exchange => mock.method(dns, 'resolveMx', async () => [{ priority: 10, exchange }]);

    // Each entry: the primary MX exchange and the static config the resolver returns.
    const staticProviders = [
        {
            name: 'Microsoft 365',
            exchange: 'contoso.mail.protection.outlook.com',
            imap: { host: 'outlook.office365.com', port: 993, secure: true },
            smtp: { host: 'smtp.office365.com', port: 587, secure: false },
            appPassword: 'Microsoft'
        },
        {
            name: 'Zoho EU',
            exchange: 'mx.zoho.eu',
            imap: { host: 'imappro.zoho.eu', port: 993, secure: true },
            smtp: { host: 'smtppro.zoho.eu', port: 465, secure: true }
        },
        {
            name: 'Zoho international',
            exchange: 'mx2.zoho.com',
            imap: { host: 'imappro.zoho.com', port: 993, secure: true },
            smtp: { host: 'smtppro.zoho.com', port: 465, secure: true }
        },
        {
            name: 'Zone.ee',
            exchange: 'mx1.zone.eu',
            imap: { host: 'mail.zone.ee', port: 993, secure: true },
            smtp: { host: 'smtp.zone.ee', port: 465, secure: true }
        },
        {
            name: 'AWS WorkMail',
            exchange: 'inbound-smtp.eu-west-1.amazonaws.com',
            imap: { host: 'imap.mail.eu-west-1.awsapps.com', port: 993, secure: true },
            smtp: { host: 'smtp.mail.eu-west-1.awsapps.com', port: 465, secure: true }
        },
        {
            name: 'Lark Mail',
            exchange: 'mailfwd.larksuite.com',
            imap: { host: 'imap.larksuite.com', port: 993, secure: true },
            smtp: { host: 'smtp.larksuite.com', port: 465, secure: true }
        },
        {
            name: 'Naver',
            exchange: 'mx1.naver.com',
            imap: { host: 'imap.naver.com', port: 993, secure: true },
            smtp: { host: 'smtp.naver.com', port: 587, secure: false }
        },
        {
            name: 'QQ enterprise',
            exchange: 'mxbiz1.qq.com',
            imap: { host: 'imap.exmail.qq.com', port: 993, secure: true },
            smtp: { host: 'smtp.exmail.qq.com', port: 465, secure: true }
        },
        {
            name: 'Alibaba Mail',
            exchange: 'mx1.sg.aliyun.com',
            imap: { host: 'imap.sg.aliyun.com', port: 993, secure: true },
            smtp: { host: 'smtp.sg.aliyun.com', port: 465, secure: true }
        },
        {
            name: 'AT&T',
            exchange: 'mx-vip1.prodigy.net',
            imap: { host: 'imap.mail.att.net', port: 993, secure: true },
            smtp: { host: 'smtp.mail.att.net', port: 465, secure: true }
        },
        {
            name: 'Inbox.com',
            exchange: 'mx.dka.mailcore.net',
            imap: { host: 'imap.dka.mailcore.net', port: 993, secure: true },
            smtp: { host: 'smtp.dka.mailcore.net', port: 587, secure: false }
        },
        {
            name: 'Ekiri',
            exchange: 'ekiri.ee',
            imap: { host: 'turvaline.ekiri.ee', port: 993, secure: true },
            smtp: { host: 'turvaline.ekiri.ee', port: 465, secure: true }
        }
    ];

    for (const provider of staticProviders) {
        await t.test(`maps the ${provider.name} MX exchange to a fixed config`, async () => {
            mockMx(provider.exchange);
            const res = await autodetectImapSettings('user@customdomain.com', gt);

            assert.deepStrictEqual(res.imap, provider.imap);
            assert.deepStrictEqual(res.smtp, provider.smtp);
            assert.strictEqual(res._source, 'mx');

            if (provider.appPassword) {
                assert.strictEqual(res.appPassword.provider, provider.appPassword);
            } else {
                assert.strictEqual(res.appPassword, undefined);
            }
        });
    }

    await t.test('picks the lowest-priority MX record as the exchange', async () => {
        mock.method(dns, 'resolveMx', async () => [
            { priority: 50, exchange: 'backup.example.com' },
            { priority: 10, exchange: 'mx1.naver.com' }
        ]);
        const res = await autodetectImapSettings('user@customdomain.com', gt);
        assert.strictEqual(res.imap.host, 'imap.naver.com');
    });

    await t.test('resolves Gmail via SRV and attaches the Gmail app password', async () => {
        mockMx('gmail-smtp-in.l.google.com');
        mock.method(dns, 'resolveSrv', async name => {
            switch (name) {
                case '_imaps._tcp.gmail.com':
                    return [{ name: 'imap.gmail.com', port: 993, priority: 5, weight: 1 }];
                case '_submissions._tcp.gmail.com':
                    return [{ name: 'smtp.gmail.com', port: 465, priority: 5, weight: 1 }];
                default:
                    throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
            }
        });

        const res = await autodetectImapSettings('user@gmail.com', gt);
        assert.deepStrictEqual(res.imap, { host: 'imap.gmail.com', port: 993, secure: true });
        assert.deepStrictEqual(res.smtp, { host: 'smtp.gmail.com', port: 465, secure: true });
        assert.strictEqual(res._source, 'mx');
        assert.strictEqual(res.appPassword.provider, 'Gmail');
    });

    await t.test('falls back from _imaps to _imap and from _submissions to _submission', async () => {
        mockMx('alt.l.google.com');
        mock.method(dns, 'resolveSrv', async name => {
            switch (name) {
                case '_imap._tcp.gmail.com':
                    return [{ name: 'imap.legacy.gmail.com', port: 143, priority: 1, weight: 1 }];
                case '_submission._tcp.gmail.com':
                    // Some providers invalidly use _submission for an implicit-TLS port.
                    return [{ name: 'smtp.legacy.gmail.com', port: 465, priority: 1, weight: 1 }];
                default:
                    // _imaps and _submissions are absent.
                    throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
            }
        });

        const res = await autodetectImapSettings('user@gmail.com', gt);
        // _imap (non-implicit-TLS) -> secure:false
        assert.deepStrictEqual(res.imap, { host: 'imap.legacy.gmail.com', port: 143, secure: false });
        // _submission on port 465 -> treated as secure:true
        assert.deepStrictEqual(res.smtp, { host: 'smtp.legacy.gmail.com', port: 465, secure: true });
    });
});
