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
// network halves of the HTTP-based fallback resolvers (autoconfig/well-known/
// mozilla) are intentionally out of scope here, while their response processing is
// covered via processAutoconfigFile/processAutodiscoverResponse.
//
// Exchange autodiscovery is the exception: its request sequence is what the whole
// feature turns on, so runAutodiscovery() is driven with an injected fetch that
// records what would have gone on the wire.

const test = require('node:test');
const { mock } = require('node:test');
const assert = require('node:assert').strict;

const dns = require('dns').promises;

const {
    autodetectImapSettings,
    processAutoconfigFile,
    processAutodiscoverResponse,
    processAutodiscoverSoapResponse,
    buildAutodiscoverRequest,
    buildAutodiscoverSoapRequest,
    runAutodiscovery,
    hasResolvedHost,
    getAppPassword,
    escapeXml
} = require('../lib/autodetect-imap-settings');
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

    await t.test('a server element with an empty hostname is not a server', async () => {
        // The entry used to be built anyway, with `host: undefined` - truthy, naming nothing, and
        // read as an answer by the resolver race and by GET /v1/autoconfig alike.
        const text = xml(
            `<incomingServer type="imap">
        <hostname></hostname>
        <port>993</port>
        <socketType>SSL</socketType>
      </incomingServer>`,
            `<outgoingServer type="smtp">
        <hostname>smtp.example.com</hostname>
        <port>587</port>
        <socketType>STARTTLS</socketType>
      </outgoingServer>`
        );

        const res = await processAutoconfigFile('john@example.com', null, text, 'autoconfig');

        assert.strictEqual(res.imap, false);
        assert.strictEqual(res.smtp.host, 'smtp.example.com', 'the half that does name a server stands');
        assert.strictEqual(hasResolvedHost(res), true);
    });

    await t.test('rejects a malformed document (HTML error page)', async () => {
        await assert.rejects(processAutoconfigFile('john@example.com', null, '<html><body><p>Not found<br></body></html>', 'autoconfig'));
    });

    await t.test('decodes XML entities in element values', async () => {
        const text = xml(
            `<incomingServer type="imap">
        <hostname>imap.example.com</hostname>
        <port>993</port>
        <socketType>SSL</socketType>
        <username>john&amp;doe@example.com</username>
      </incomingServer>`,
            ''
        );
        const res = await processAutoconfigFile('john&doe@example.com', null, text, 'autoconfig');
        assert.strictEqual(res.imap.auth.user, 'john&doe@example.com');
    });
});

// The POX autodiscovery envelope, shared by the response-parsing tests and the request-sequence
// ones, so the two differ only in the <Protocol> children that matter to each.
const pox = accounts => `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    ${accounts}
  </Response>
</Autodiscover>`;

test('processAutodiscoverResponse', async t => {
    const emailAccount = `<Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>imap.example.com</Server>
        <Port>993</Port>
        <LoginName>john@example.com</LoginName>
        <SSL>on</SSL>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>smtp.example.com</Server>
        <Port>587</Port>
        <LoginName>john@example.com</LoginName>
        <SSL>off</SSL>
      </Protocol>
    </Account>`;

    await t.test('parses IMAP and SMTP protocol entries of an email account', async () => {
        const res = await processAutodiscoverResponse(pox(emailAccount), 'autodiscover');
        assert.deepStrictEqual(res, {
            imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'john@example.com' } },
            smtp: { host: 'smtp.example.com', port: 587, secure: false, auth: { user: 'john@example.com' } },
            _source: 'autodiscover'
        });
    });

    await t.test('defaults the source label', async () => {
        const res = await processAutodiscoverResponse(pox(emailAccount));
        assert.strictEqual(res._source, 'autodiscover');
    });

    await t.test('ignores accounts that are not of type email', async () => {
        const res = await processAutodiscoverResponse(pox(emailAccount.replace(/email/, 'notes')), 'autodiscover');
        assert.strictEqual(res.imap, false);
        assert.strictEqual(res.smtp, false);
    });

    await t.test('returns false entries for an empty response body', async () => {
        const res = await processAutodiscoverResponse('', 'autodiscover');
        assert.strictEqual(res.imap, false);
        assert.strictEqual(res.smtp, false);
    });

    await t.test('rejects a malformed document', () => {
        assert.throws(() => processAutodiscoverResponse('<Autodiscover><Response>', 'autodiscover'));
    });

    await t.test('a protocol block with no Server names nothing, so it is not an entry', () => {
        // The parser used to build the entry out of whatever elements were present, which made
        // this one an object that was truthy and named no server at all.
        const res = processAutodiscoverResponse(
            pox(`<Account>
              <AccountType>email</AccountType>
              <Protocol><Type>IMAP</Type><Port>993</Port><SSL>on</SSL></Protocol>
            </Account>`),
            'autodiscover'
        );
        assert.strictEqual(res.imap, false);
        assert.strictEqual(hasResolvedHost(res), false, 'and it is not an answer');
    });
});

test('hasResolvedHost', async t => {
    // The predicate every resolver result is judged by. A truthy `imap`/`smtp` entry is not the
    // same thing as a resolved server: an autoconfig file with an empty <hostname> and an
    // autodiscover <Protocol> without a <Server> both build one that names nothing, and treating
    // that as an answer both won the resolver race against the branch that had the real settings
    // and rendered the hosted setup form with empty server fields.
    await t.test('accepts a result that names an IMAP host', () => {
        assert.strictEqual(hasResolvedHost({ imap: { host: 'imap.example.com' }, smtp: false }), true);
    });

    await t.test('accepts a result that names only an SMTP host', () => {
        assert.strictEqual(hasResolvedHost({ imap: false, smtp: { host: 'smtp.example.com' } }), true);
    });

    await t.test('rejects entries that carry everything but a host', () => {
        assert.strictEqual(hasResolvedHost({ imap: { port: 993, secure: true }, smtp: {} }), false);
    });

    await t.test('rejects an undefined host', () => {
        // What processAutoconfigFile() builds from an empty <hostname> element
        assert.strictEqual(hasResolvedHost({ imap: { host: undefined, port: 993, secure: true }, smtp: false }), false);
    });

    await t.test('rejects a result with no entries at all', () => {
        assert.strictEqual(hasResolvedHost({ imap: false, smtp: false }), false);
        assert.strictEqual(hasResolvedHost(false), false);
        assert.strictEqual(hasResolvedHost(undefined), false);
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

// A SOAP GetUserSettings response shaped like the one hosted Exchange returns: namespace prefixes
// throughout, and the same connection repeated once per client access server.
const soapResponse = settings => `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetUserSettingsResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response>
        <ErrorCode>NoError</ErrorCode>
        <UserResponses>
          <UserResponse>
            <ErrorCode>NoError</ErrorCode>
            <UserSettings>${settings}</UserSettings>
          </UserResponse>
        </UserResponses>
      </Response>
    </GetUserSettingsResponseMessage>
  </s:Body>
</s:Envelope>`;

const connectionSetting = (name, connections) => `
  <UserSetting i:type="ProtocolConnectionCollectionSetting" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <Name>${name}</Name>
    <ProtocolConnections>${connections
        .map(
            ([hostname, port, encryption]) =>
                `<ProtocolConnection><Hostname>${hostname}</Hostname><Port>${port}</Port><EncryptionMethod>${encryption}</EncryptionMethod></ProtocolConnection>`
        )
        .join('')}</ProtocolConnections>
  </UserSetting>`;

// The shape hosted Exchange actually answers with: IMAP on the implicit-TLS and the STARTTLS port,
// SMTP on the submission port only, every entry repeated.
const ovhStyleSettings =
    connectionSetting('ExternalImap4Connections', [
        ['pro2.mail.ovh.net', 993, 'SSL'],
        ['pro2.mail.ovh.net', 143, 'TLS'],
        ['pro2.mail.ovh.net', 993, 'SSL'],
        ['pro2.mail.ovh.net', 143, 'TLS']
    ]) +
    connectionSetting('ExternalSmtpConnections', [
        ['pro2.mail.ovh.net', 587, 'TLS'],
        ['pro2.mail.ovh.net', 587, 'TLS']
    ]);

test('buildAutodiscoverRequest', async t => {
    await t.test('puts EMailAddress ahead of AcceptableResponseSchema', () => {
        const body = buildAutodiscoverRequest('user@example.com');
        // Exchange answers ErrorCode 600 ("Invalid Request") when these arrive the other way round
        assert.ok(body.indexOf('<EMailAddress>') < body.indexOf('<AcceptableResponseSchema>'), 'the request schema declares a sequence');
    });

    await t.test('escapes the address', () => {
        const body = buildAutodiscoverRequest('a<b>@example.com');
        assert.ok(body.includes('<EMailAddress>a&lt;b&gt;@example.com</EMailAddress>'));
    });
});

test('buildAutodiscoverSoapRequest', async t => {
    await t.test('asks for the external IMAP and SMTP endpoints', () => {
        const body = buildAutodiscoverSoapRequest('user@example.com');
        assert.ok(body.includes('<a:Setting>ExternalImap4Connections</a:Setting>'));
        assert.ok(body.includes('<a:Setting>ExternalSmtpConnections</a:Setting>'));
        assert.ok(body.includes('<a:Mailbox>user@example.com</a:Mailbox>'));
    });

    await t.test('escapes the address', () => {
        assert.ok(buildAutodiscoverSoapRequest('a&b@example.com').includes('<a:Mailbox>a&amp;b@example.com</a:Mailbox>'));
    });
});

test('processAutodiscoverSoapResponse', async t => {
    await t.test('reads IMAP and SMTP out of a hosted Exchange response', () => {
        const res = processAutodiscoverSoapResponse(soapResponse(ovhStyleSettings));
        // SSL is implicit TLS, so the 993 entry wins over the 143 STARTTLS one
        assert.deepStrictEqual(res.imap, { host: 'pro2.mail.ovh.net', port: 993, secure: true });
        // Only STARTTLS is offered for submission, which is secure:false for our purposes
        assert.deepStrictEqual(res.smtp, { host: 'pro2.mail.ovh.net', port: 587, secure: false });
        assert.strictEqual(res._source, 'autodiscover');
    });

    await t.test('falls back to the STARTTLS entry when no implicit-TLS port is offered', () => {
        const res = processAutodiscoverSoapResponse(soapResponse(connectionSetting('ExternalImap4Connections', [['mail.example.com', 143, 'TLS']])));
        assert.deepStrictEqual(res.imap, { host: 'mail.example.com', port: 143, secure: false });
        assert.strictEqual(res.smtp, false);
    });

    await t.test('reports false for a setting the server did not list', () => {
        const res = processAutodiscoverSoapResponse(soapResponse(connectionSetting('ExternalSmtpConnections', [['mail.example.com', 587, 'TLS']])));
        assert.strictEqual(res.imap, false);
        assert.deepStrictEqual(res.smtp, { host: 'mail.example.com', port: 587, secure: false });
    });

    await t.test('ignores an entry with no usable host or port', () => {
        const res = processAutodiscoverSoapResponse(
            soapResponse(
                connectionSetting('ExternalImap4Connections', [
                    ['', 993, 'SSL'],
                    ['mail.example.com', 0, 'SSL']
                ])
            )
        );
        assert.strictEqual(res.imap, false);
    });

    await t.test('survives an empty settings block', () => {
        const res = processAutodiscoverSoapResponse(soapResponse(''));
        assert.deepStrictEqual(res, { imap: false, smtp: false, _source: 'autodiscover' });
    });

    await t.test('survives a document that is not a settings response at all', () => {
        const res = processAutodiscoverSoapResponse('<?xml version="1.0"?><nothing/>');
        assert.deepStrictEqual(res, { imap: false, smtp: false, _source: 'autodiscover' });
    });
});

test('runAutodiscovery', async t => {
    // Records every request and answers from a table keyed by path, so a test states only what the
    // endpoints return and then asserts what went out.
    const stubFetch = handlers => {
        const calls = [];
        const fetchResource = async (url, opts) => {
            const path = new URL(url).pathname;
            calls.push({ url, path, headers: opts.headers });
            const handler = handlers[path];
            // Awaited, so a test can hand back a promise and hold an endpoint open
            const answer = (await (typeof handler === 'function' ? handler(calls.length) : handler)) || { status: 404 };
            // A 401 carries the Basic challenge a real Exchange sends, unless a test says otherwise
            const wwwAuthenticate = 'wwwAuthenticate' in answer ? answer.wwwAuthenticate : answer.status === 401 ? 'Basic realm="test", Negotiate, NTLM' : null;
            return {
                ok: answer.status >= 200 && answer.status < 300,
                status: answer.status,
                // fetch reports where the request ended up, which is what a redirect changes
                url: answer.url || url,
                headers: { get: name => (name.toLowerCase() === 'www-authenticate' ? wwwAuthenticate : null) },
                text: async () => answer.body || ''
            };
        };
        return { calls, fetchResource };
    };

    const POX = '/autodiscover/autodiscover.xml';
    const SOAP = '/autodiscover/autodiscover.svc';

    // A POX response carrying real IMAP settings, as a server that answers anonymously would
    const poxWithImap = pox(`<Account>
      <AccountType>email</AccountType>
      <Protocol><Type>IMAP</Type><Server>imap.example.com</Server><Port>993</Port><SSL>on</SSL><LoginName>real-login</LoginName></Protocol>
      <Protocol><Type>SMTP</Type><Server>smtp.example.com</Server><Port>587</Port><SSL>off</SSL></Protocol>
    </Account>`);

    // What hosted Exchange answers an authenticated POX request with: webmail only, no IMAP
    const poxWebOnly = pox(`<Account>
      <AccountType>email</AccountType>
      <Protocol><Type>WEB</Type></Protocol>
    </Account>`);

    const credentials = { user: 'user@example.com', pass: 'secret' };

    await t.test('announces every request as text/xml', async () => {
        // Exchange answers application/xml with 415 before it ever looks at the body
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 200, body: poxWithImap } });
        await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', undefined, fetchResource);
        assert.strictEqual(calls[0].headers['Content-type'], 'text/xml; charset=utf-8');
    });

    await t.test('never sends credentials to a server that answers anonymously', async () => {
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 200, body: poxWithImap } });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap, { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'real-login' } });
        assert.strictEqual(calls.length, 1, 'one request is enough when it is answered');
        assert.ok(!calls[0].headers.Authorization, 'the password must not be offered before it is asked for');
    });

    await t.test('asks anonymously first, then repeats the request with credentials', async () => {
        const { calls, fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : { status: 200, body: poxWithImap }),
            [SOAP]: { status: 401 }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.smtp, { host: 'smtp.example.com', port: 587, secure: false });
        assert.ok(!calls[0].headers.Authorization, 'the first request is anonymous');
        const authorization = calls.find(call => call.headers.Authorization).headers.Authorization;
        assert.strictEqual(authorization, `Basic ${Buffer.from('user@example.com:secret').toString('base64')}`);
    });

    await t.test('a protocol block without a Server is not a usable answer', async () => {
        // The parser builds an entry from whatever elements were there, so this one is truthy and
        // names no host. Answering the caller with it produced a form with empty server fields.
        const poxNoServer = pox(`<Account>
          <AccountType>email</AccountType>
          <Protocol><Type>IMAP</Type><Port>993</Port><SSL>on</SSL></Protocol>
        </Account>`);
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 200, body: poxNoServer }, [SOAP]: { status: 401 } });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1, 'and it still counts as an anonymous answer, so no password is offered');
    });

    await t.test('does not offer the password to a host that answered anonymously with nothing usable', async () => {
        // A 200 is not a request for credentials, however unhelpful its body
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 200, body: poxWebOnly }, [SOAP]: { status: 401 } });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1, 'an answer without a challenge ends the lookup');
    });

    await t.test('ignores a challenge that does not offer Basic', async () => {
        // Basic is the only scheme implemented, and a server that never offered it would reject it
        const { calls, fetchResource } = stubFetch({
            [POX]: { status: 401, wwwAuthenticate: 'Negotiate, NTLM' },
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1);
    });

    await t.test('falls back to the SOAP endpoint when the legacy one carries no IMAP settings', async () => {
        // The hosted Exchange case: both endpoints challenge, and only SOAP knows about IMAP
        const { calls, fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : { status: 200, body: poxWebOnly }),
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap, { host: 'pro2.mail.ovh.net', port: 993, secure: true });
        assert.deepStrictEqual(res.smtp, { host: 'pro2.mail.ovh.net', port: 587, secure: false });
        assert.ok(
            calls.some(call => call.path === SOAP && call.headers.Authorization),
            'the SOAP endpoint refuses anonymous requests too'
        );
    });

    await t.test('prefers the legacy endpoint when both answer, because only it names the login', async () => {
        const { calls, fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : { status: 200, body: poxWithImap }),
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap.auth, { user: 'real-login' });
        assert.strictEqual(calls.filter(call => call.path === SOAP).length, 1, 'both are asked at once rather than one after the other');
    });

    await t.test('answers from the endpoint that replied, without waiting for the other one', async () => {
        // Both requests are in flight together, but collecting them - `[await pox, await soap]` -
        // awaited both before either was looked at. The resolver runs against a five second budget
        // shared with four other lookups, so a stalled endpoint could spend it while the settings
        // sat in a promise that had already resolved.
        let releaseSoap;
        const { fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : { status: 200, body: poxWithImap }),
            [SOAP]: () => new Promise(resolve => (releaseSoap = resolve))
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap, { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'real-login' } });
        assert.ok(releaseSoap, 'the SOAP endpoint was asked, and had still not answered');
        releaseSoap({ status: 500 });
    });

    await t.test('answers from SOAP while the legacy endpoint is still stalled', async () => {
        // The same the other way round: hosted Exchange keeps its IMAP settings in the SOAP
        // response, so POX is as able to be the slow one as it is to be the useful one.
        let releasePox;
        const { fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : new Promise(resolve => (releasePox = resolve))),
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap, { host: 'pro2.mail.ovh.net', port: 993, secure: true });
        assert.ok(releasePox, 'the legacy endpoint was asked, and had still not answered');
        releasePox({ status: 500 });
    });

    await t.test('gives up without credentials rather than guessing', async () => {
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 401 }, [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) } });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', undefined, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1, 'nothing is asked that cannot be answered without a password');
    });

    await t.test('does not offer the password to a host that answered something other than a challenge', async () => {
        // Wildcard DNS makes "something answers at autodiscover.<domain>" common, and a 404 from a
        // parking host is not a request for credentials
        const { calls, fetchResource } = stubFetch({ [POX]: { status: 404 }, [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) } });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1, 'no credentialed retry against a host that never challenged');
    });

    await t.test('sends the credentials to the host that issued the challenge, not the one that redirected', async () => {
        // fetchWithVettedRedirects strips Authorization on a cross-origin hop, so retrying from the
        // original URL would arrive without the very header the retry exists to carry
        const { calls, fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401, url: 'https://mail.example.net/autodiscover/autodiscover.xml' } : { status: 401 }),
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);

        assert.deepStrictEqual(res.imap, { host: 'pro2.mail.ovh.net', port: 993, secure: true });
        for (let call of calls.slice(1)) {
            assert.ok(call.url.startsWith('https://mail.example.net/'), `retry went to ${call.url}`);
        }
    });

    await t.test('refuses to answer a challenge that arrived over plain http', async () => {
        // A redirect may lead to http - the anonymous lookup carries nothing worth protecting - so
        // the challenging host is not necessarily on https, and Basic there is a cleartext password
        const { calls, fetchResource } = stubFetch({
            [POX]: { status: 401, url: 'http://downgraded.example.net/autodiscover/autodiscover.xml' },
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
        assert.strictEqual(calls.length, 1, 'no credential is sent anywhere once the challenge came over http');
    });

    await t.test('gives up when the credentials are refused', async () => {
        const { fetchResource } = stubFetch({ [POX]: { status: 401 }, [SOAP]: { status: 401 } });

        await assert.rejects(() => runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource), /Invalid response/);
    });

    await t.test('survives one endpoint throwing outright', async () => {
        const { fetchResource } = stubFetch({
            [POX]: callNr => {
                if (callNr > 1) {
                    throw new Error('connection reset');
                }
                return { status: 401 };
            },
            [SOAP]: { status: 200, body: soapResponse(ovhStyleSettings) }
        });

        const res = await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', credentials, fetchResource);
        assert.deepStrictEqual(res.imap, { host: 'pro2.mail.ovh.net', port: 993, secure: true });
    });

    await t.test('uses the address as the login name when no separate one is configured', async () => {
        const { calls, fetchResource } = stubFetch({
            [POX]: callNr => (callNr === 1 ? { status: 401 } : { status: 200, body: poxWithImap }),
            [SOAP]: { status: 401 }
        });

        await runAutodiscovery('https://autodiscover.example.com', 'user@example.com', { pass: 'secret' }, fetchResource);

        const authorization = calls.find(call => call.headers.Authorization).headers.Authorization;
        assert.strictEqual(authorization, `Basic ${Buffer.from('user@example.com:secret').toString('base64')}`);
    });
});
