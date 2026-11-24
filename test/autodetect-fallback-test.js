'use strict';

// Unit tests for the last autodiscovery stage (resolveUsingFallbacks() in
// lib/autodetect-imap-settings.js) and the TLS probe it uses (lib/mail-probe.js).
//
// The stage runs for a domain that publishes nothing about its mail: no SRV records, no
// autoconfig document, no autodiscovery, nothing in the Thunderbird directory under its own name.
// The resolver tests below describe only what differs from that silent domain, with DNS, HTTP
// and the probe replaced by stand-ins. The probe tests connect to real local TLS servers.

const test = require('node:test');
const assert = require('node:assert').strict;
const tls = require('tls');

const { resolver, exchangeParents, probeCandidates, getProviderHint, isConsumerMailbox, MAX_PROBE_CANDIDATES } = require('../lib/autodetect-imap-settings');
const { probeMailServer } = require('../lib/mail-probe');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { notFound, textResponse, autoconfigDoc } = require('./helpers/autodetect-stand-ins');
const { startProxyServer } = require('./helpers/http-proxy-server');

registerRedisTeardown(redis);

const gt = { gettext: s => s };

/**
 * Runs detection for user@example.com against a described world.
 *
 * @param {Object} world
 * @param {string} world.mx - The domain's MX host
 * @param {Object} [world.cnames] - Alias name to target
 * @param {string[]} [world.txt] - The domain's TXT records
 * @param {Object} [world.thunderbird] - Directory entries, domain to mail host
 * @param {string[]} [world.imapServers] - Hosts that greet as IMAP on 993
 * @param {string[]} [world.smtpServers] - Hosts that greet as SMTP on 465
 * @param {boolean} [world.autodiscoverAsksForPassword] - autodiscover.example.com answers with a Basic challenge
 * @param {boolean} [world.rootDomainNeverAnswers] - https://example.com never responds
 * @param {number} [world.timeout] - Budget of each stage
 * @returns {Promise<Object>} `{ settings, error, probed }`, probed listing every `host:port` probed
 */
async function detect(world) {
    const probed = [];
    const dnsStandIn = {
        resolveMx: async () => [{ priority: 10, exchange: world.mx }],
        resolveSrv: notFound,
        resolveCname: async name => ((world.cnames || {})[name] ? [world.cnames[name]] : notFound()),
        resolveTxt: async () => (world.txt || []).map(record => [record])
    };
    const fetchResource = async url => {
        const { hostname, pathname } = new URL(url);
        if (hostname === 'autoconfig.thunderbird.net') {
            const listed = (world.thunderbird || {})[pathname.split('/').pop()];
            return listed ? textResponse(200, autoconfigDoc(listed)) : textResponse(404);
        }
        if (world.autodiscoverAsksForPassword && hostname === 'autodiscover.example.com' && url.startsWith('https:')) {
            return { ok: false, status: 401, url, headers: { get: () => 'Basic realm="Exchange"' }, text: async () => '' };
        }
        if (world.rootDomainNeverAnswers && hostname === 'example.com') {
            return new Promise(() => {});
        }
        return textResponse(404);
    };
    const probe = async (host, port) => {
        probed.push(`${host}:${port}`);
        return (port === 993 ? world.imapServers || [] : world.smtpServers || []).includes(host);
    };

    try {
        const settings = await resolver('user@example.com', gt, null, {
            dns: dnsStandIn,
            fetchResource,
            probe,
            mailProxyUrl: async () => null,
            timeout: world.timeout || 2000
        });
        return { settings, probed };
    } catch (error) {
        return { error, probed };
    }
}

test('fallback stage: domains that publish no mail settings', async t => {
    await t.test('OVH: the directory is asked for the domain the MX host sits under', async () => {
        const { settings } = await detect({ mx: 'mx1.mail.ovh.net', thunderbird: { 'ovh.net': 'ssl0.ovh.net' } });

        assert.equal(settings.imap.host, 'ssl0.ovh.net');
        assert.equal(settings._source, 'mozilla-mx');
    });

    await t.test('a directory entry wins over a host the probe would find', async () => {
        const { settings, probed } = await detect({ mx: 'mx1.mail.ovh.net', thunderbird: { 'ovh.net': 'ssl0.ovh.net' }, imapServers: ['imap.ovh.net'] });

        assert.equal(settings.imap.host, 'ssl0.ovh.net');
        assert.deepEqual(probed, [], 'nothing is probed once the directory answered');
    });

    await t.test('the MX host itself, when it also serves IMAP and SMTP', async () => {
        const { settings } = await detect({ mx: 'wo36.adwinfrance.com', imapServers: ['wo36.adwinfrance.com'], smtpServers: ['wo36.adwinfrance.com'] });

        assert.deepEqual(settings.imap, { host: 'wo36.adwinfrance.com', port: 993, secure: true });
        assert.deepEqual(settings.smtp, { host: 'wo36.adwinfrance.com', port: 465, secure: true });
        assert.equal(settings._source, 'probe');
    });

    await t.test('imap. and smtp. under the MX host domain', async () => {
        const { settings } = await detect({ mx: 'mx.axecibles.com', imapServers: ['imap.axecibles.com'], smtpServers: ['smtp.axecibles.com'] });

        assert.equal(settings.imap.host, 'imap.axecibles.com');
        assert.equal(settings.smtp.host, 'smtp.axecibles.com');
    });

    await t.test("the domain's own mail host is preferred over the provider's", async () => {
        const { settings } = await detect({ mx: 'mta-gw.infomaniak.ch', imapServers: ['imap.infomaniak.ch', 'mail.example.com'] });

        assert.equal(settings.imap.host, 'mail.example.com');
    });

    await t.test('an alias is probed under the name it points to', async () => {
        // smtp.example.com carries the provider's certificate, so only the target's own name can pass
        const { settings } = await detect({
            mx: 'mail.example.com',
            cnames: { 'smtp.example.com': 'wo39.adwinfrance.com' },
            imapServers: ['wo39.adwinfrance.com'],
            smtpServers: ['wo39.adwinfrance.com']
        });

        assert.equal(settings.imap.host, 'wo39.adwinfrance.com');
        assert.equal(settings.smtp.host, 'wo39.adwinfrance.com');
    });

    await t.test('an IMAP server is returned even when no SMTP server answers', async () => {
        const { settings } = await detect({ mx: 'mx.provider.net', imapServers: ['imap.example.com'] });

        assert.equal(settings.imap.host, 'imap.example.com');
        assert.equal(settings.smtp, false);
    });

    await t.test('Microsoft 365 behind a mail filter, from the autodiscover alias, without probing', async () => {
        const { settings, probed } = await detect({
            mx: 'mx-mibc-fr-02.mailinblack.com',
            cnames: { 'autodiscover.example.com': 'autodiscover.outlook.com' }
        });

        assert.equal(settings.imap.host, 'outlook.office365.com');
        assert.equal(settings.smtp.host, 'smtp.office365.com');
        assert.equal(settings._source, 'microsoft365');
        assert.equal(settings.appPassword.provider, 'Microsoft');
        assert.deepEqual(probed, []);
    });

    await t.test('Microsoft 365 is recognized although its autodiscovery asks for a password', async () => {
        const { settings } = await detect({
            mx: 'mx-mibc-fr-02.mailinblack.com',
            cnames: { 'autodiscover.example.com': 'autodiscover.outlook.com.' },
            autodiscoverAsksForPassword: true
        });

        assert.equal(settings._source, 'microsoft365');
    });

    await t.test('an SPF record including Microsoft is the last resort', async () => {
        const { settings } = await detect({ mx: 'vade-mx-fr01.hornetsecurity.com', txt: ['v=spf1 include:spf.protection.outlook.com -all'] });

        assert.equal(settings._source, 'microsoft365');
    });

    await t.test('an SPF record including Microsoft does not override a server the domain has', async () => {
        const { settings } = await detect({
            mx: 'vade-mx-fr01.hornetsecurity.com',
            txt: ['v=spf1 include:spf.protection.outlook.com -all'],
            imapServers: ['imap.example.com']
        });

        assert.equal(settings.imap.host, 'imap.example.com');
    });

    await t.test('an SPF include that only starts like Microsoft is not Microsoft', async () => {
        const { error } = await detect({ mx: 'mx.provider.net', txt: ['v=spf1 include:spf.protection.outlook.com.attacker.example -all'] });

        assert.ok(error);
    });
});

test('fallback stage: what it must leave alone', async t => {
    await t.test('hosted Exchange asking for the password gets no guessed server', async () => {
        const { error, probed } = await detect({
            mx: 'mx1.mail.ovh.net',
            autodiscoverAsksForPassword: true,
            thunderbird: { 'ovh.net': 'ssl0.ovh.net' },
            imapServers: ['imap.example.com']
        });

        assert.ok(error, 'nothing is returned');
        assert.deepEqual(probed, []);
    });

    await t.test('the password request is noticed even when another lookup runs out of time', async () => {
        const { error, probed } = await detect({
            mx: 'mx1.mail.ovh.net',
            autodiscoverAsksForPassword: true,
            rootDomainNeverAnswers: true,
            timeout: 200,
            imapServers: ['imap.example.com']
        });

        assert.ok(error, 'nothing is returned');
        assert.deepEqual(probed, []);
    });

    await t.test('a domain with no server anywhere fails as before', async () => {
        const { error } = await detect({ mx: 'mx.provider.net' });

        assert.equal(error._is_last, true);
    });

    await t.test('a domain the MX table knows never reaches the stage', async () => {
        const { settings, probed } = await detect({ mx: 'example-com.mail.protection.outlook.com', imapServers: ['imap.example.com'] });

        assert.equal(settings._source, 'mx');
        assert.deepEqual(probed, []);
    });
});

test('fallback stage: bounds', async t => {
    await t.test('exchangeParents stops at the registrable domain', () => {
        assert.deepEqual(exchangeParents('mx1.mail.ovh.net'), ['mail.ovh.net', 'ovh.net']);
        assert.deepEqual(exchangeParents('mx.example.co.uk'), ['example.co.uk']);
        assert.deepEqual(exchangeParents('example.com'), []);
        assert.deepEqual(exchangeParents(null), []);
    });

    await t.test('candidates are capped per protocol, most likely first', () => {
        const many = Array.from({ length: 10 }, (v, i) => `host${i}.provider.net`);
        const { imap, smtp } = probeCandidates({
            domain: 'example.com',
            exchange: 'mx.provider.net',
            parents: ['provider.net'],
            aliases: { imap: many, mail: many, smtp: many, webmail: many }
        });

        assert.equal(imap.length, MAX_PROBE_CANDIDATES);
        assert.equal(smtp.length, MAX_PROBE_CANDIDATES);
        assert.deepEqual(imap.slice(0, 3), ['mx.provider.net', 'imap.example.com', 'mail.example.com']);
        assert.equal(smtp[0], 'smtp.example.com');
    });

    await t.test('IMAP and SMTP are probed in two rounds, SMTP only after an IMAP server answered', async () => {
        const rounds = [];
        let inFlight = 0;
        let peak = 0;
        const cnames = {};
        for (const name of ['imap', 'mail', 'smtp', 'webmail']) {
            cnames[`${name}.example.com`] = `${name}-target.provider.net`;
        }
        const dnsStandIn = {
            resolveMx: async () => [{ priority: 10, exchange: 'mx.provider.net' }],
            resolveSrv: notFound,
            resolveCname: async name => (cnames[name] ? [cnames[name]] : notFound()),
            resolveTxt: async () => []
        };
        const run = imapServers =>
            resolver('user@example.com', gt, null, {
                dns: dnsStandIn,
                fetchResource: async () => textResponse(404),
                mailProxyUrl: async () => 'socks5://proxy.example:1080',
                probe: async (host, port, opts) => {
                    rounds.push({ port, proxyUrl: opts.proxyUrl });
                    inFlight++;
                    peak = Math.max(peak, inFlight);
                    await new Promise(resolve => setTimeout(resolve, 20));
                    inFlight--;
                    return port === 993 && imapServers.includes(host);
                },
                timeout: 2000
            });

        await assert.rejects(run([]));
        assert.ok(rounds.length > 1 && rounds.every(entry => entry.port === 993), 'no SMTP probe without an IMAP server');
        assert.ok(peak <= MAX_PROBE_CANDIDATES, `peak ${peak} exceeds the limit`);
        assert.ok(
            rounds.every(entry => entry.proxyUrl === 'socks5://proxy.example:1080'),
            'every probe takes the mail proxy'
        );

        rounds.length = 0;
        peak = 0;
        const settings = await run(['imap.example.com']);
        assert.equal(settings.imap.host, 'imap.example.com');
        const firstSmtp = rounds.findIndex(entry => entry.port === 465);
        assert.ok(firstSmtp > 0 && rounds.slice(firstSmtp).every(entry => entry.port === 465), 'SMTP round follows the IMAP round');
        assert.ok(peak <= MAX_PROBE_CANDIDATES);
    });

    await t.test('the fallback lookups are cancelled once the race wins', async () => {
        let directorySignal = null;
        const dnsStandIn = {
            resolveMx: async () => [{ priority: 10, exchange: 'mx1.mail.ovh.net' }],
            resolveSrv: notFound,
            resolveCname: notFound,
            resolveTxt: async () => []
        };
        const fetchResource = async (url, opts) => {
            const { hostname, pathname } = new URL(url);
            if (hostname === 'autoconfig.thunderbird.net' && pathname.endsWith('/ovh.net')) {
                directorySignal = opts.signal;
                return new Promise(() => {});
            }
            if (hostname === 'autoconfig.example.com') {
                return textResponse(200, autoconfigDoc('imap.example.com'));
            }
            return textResponse(404);
        };

        const settings = await resolver('user@example.com', gt, null, { dns: dnsStandIn, fetchResource, probe: async () => false, timeout: 2000 });
        assert.equal(settings._source, 'autoconfig');
        assert.ok(directorySignal, 'the directory was asked while the race ran');
        assert.equal(directorySignal.aborted, true);
    });

    await t.test('the DNS facts are read while the resolver race still runs', async () => {
        let firstCnameAt = null;
        let firstFetchAnsweredAt = null;
        const dnsStandIn = {
            resolveMx: async () => [{ priority: 10, exchange: 'mx.provider.net' }],
            resolveSrv: notFound,
            resolveCname: async () => {
                firstCnameAt = firstCnameAt || Date.now();
                return notFound();
            },
            resolveTxt: async () => []
        };
        const fetchResource = async () => {
            await new Promise(resolve => setTimeout(resolve, 150));
            firstFetchAnsweredAt = firstFetchAnsweredAt || Date.now();
            return textResponse(404);
        };

        await assert.rejects(
            resolver('user@example.com', gt, null, { dns: dnsStandIn, fetchResource, probe: async () => false, mailProxyUrl: async () => null, timeout: 2000 })
        );
        assert.ok(firstCnameAt && firstFetchAnsweredAt && firstCnameAt < firstFetchAnsweredAt, 'aliases were looked up before the race was over');
    });
});

// ---------------------------------------------------------------------------------------------
// The probe against real TLS servers on loopback
// ---------------------------------------------------------------------------------------------

const MAIL_HOST = 'mail.probe.test';

async function startTlsServer(certificate, onSocket) {
    const sockets = new Set();
    let connections = 0;
    const server = tls.createServer({ key: certificate.privateKey, cert: certificate.cert }, socket => {
        sockets.add(socket);
        socket.on('error', () => false);
        socket.on('close', () => sockets.delete(socket));
        onSocket(socket);
    });
    // Counted at TCP accept, so a connection that never completes the handshake still shows
    server.on('connection', () => connections++);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return {
        port: server.address().port,
        connections: () => connections,
        close: () => {
            for (const socket of sockets) {
                socket.destroy();
            }
            return new Promise(resolve => server.close(resolve));
        }
    };
}

test('mail server probe', async t => {
    const certificate = await createSelfSignedCertificate({ hostnames: [MAIL_HOST], keyType: 'ec' });
    const otherCertificate = await createSelfSignedCertificate({ hostnames: ['other.probe.test'], keyType: 'ec' });

    const loopback = async () => [{ address: '127.0.0.1', family: 4 }];
    const probeCtx = (port, extra) =>
        Object.assign(
            { resolve: loopback, egressPolicy: 'link-local', tlsOptions: { ca: [certificate.cert] }, ports: { 993: port, 465: port }, timeout: 500 },
            extra
        );

    await t.test('takes a host that greets as IMAP on 993', async () => {
        const server = await startTlsServer(certificate, socket => socket.write('* OK [CAPABILITY IMAP4rev1] ready\r\n'));
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(server.port)), true);
        } finally {
            await server.close();
        }
    });

    await t.test('refuses an SMTP banner on the IMAP port', async () => {
        const server = await startTlsServer(certificate, socket => socket.write('220 mail.probe.test ESMTP\r\n'));
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(server.port)), false);
            assert.equal(await probeMailServer(MAIL_HOST, 465, probeCtx(server.port)), true);
        } finally {
            await server.close();
        }
    });

    await t.test('refuses a certificate issued for another name', async () => {
        const server = await startTlsServer(otherCertificate, socket => socket.write('* OK ready\r\n'));
        try {
            const ctx = probeCtx(server.port, { tlsOptions: { ca: [otherCertificate.cert] } });
            assert.equal(await probeMailServer(MAIL_HOST, 993, ctx), false);
        } finally {
            await server.close();
        }
    });

    await t.test('a silent server passes on 465 after a good handshake, never on 993', async () => {
        const server = await startTlsServer(certificate, () => false);
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 465, probeCtx(server.port)), true);
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(server.port)), false);
        } finally {
            await server.close();
        }
    });

    await t.test('an abort ends the probe without waiting for its timeout', async () => {
        const server = await startTlsServer(certificate, () => false);
        try {
            const controller = new AbortController();
            const started = Date.now();
            const probing = probeMailServer(MAIL_HOST, 993, probeCtx(server.port, { signal: controller.signal, timeout: 5000 }));
            setTimeout(() => controller.abort(), 50);
            assert.equal(await probing, false);
            assert.ok(Date.now() - started < 2000);
        } finally {
            await server.close();
        }
    });

    await t.test('refuses an address the egress policy blocks without connecting', async () => {
        const server = await startTlsServer(certificate, socket => socket.write('* OK ready\r\n'));
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(server.port, { egressPolicy: 'private' })), false);
            assert.equal(server.connections(), 0);
        } finally {
            await server.close();
        }
    });

    await t.test('refuses a blocked address literal, which no lookup would see', async () => {
        // An MX or CNAME record can name an address outright; net.connect skips the lookup for it
        const server = await startTlsServer(certificate, socket => socket.write('* OK ready\r\n'));
        try {
            const ctx = probeCtx(server.port, { egressPolicy: 'private', resolve: () => assert.fail('a literal is not resolved') });
            assert.equal(await probeMailServer('127.0.0.1', 993, ctx), false);
            assert.equal(server.connections(), 0);
        } finally {
            await server.close();
        }
    });

    await t.test('behind a proxy, a blocked address is refused before the proxy is asked', async () => {
        const proxy = await startProxyServer({ targetHost: '127.0.0.1' });
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(1, { proxyUrl: proxy.url, egressPolicy: 'private' })), false);
            assert.equal(proxy.getConnectCount(), 0);
        } finally {
            await proxy.close();
        }
    });

    await t.test('a name that does not resolve is not probed', async () => {
        const ctx = probeCtx(1, { resolve: () => notFound() });
        assert.equal(await probeMailServer(MAIL_HOST, 993, ctx), false);
    });

    await t.test('goes through the configured proxy, which is asked for the name', async () => {
        const server = await startTlsServer(certificate, socket => socket.write('* OK ready\r\n'));
        const proxy = await startProxyServer({ targetHost: '127.0.0.1' });
        try {
            assert.equal(await probeMailServer(MAIL_HOST, 993, probeCtx(server.port, { proxyUrl: proxy.url })), true);
            assert.deepEqual(proxy.getRequested(), [`${MAIL_HOST}:${server.port}`]);
        } finally {
            await proxy.close();
            await server.close();
        }
    });
});

test('provider hint', async t => {
    await t.test('names the OAuth2 provider from the domain or the MX exchange', () => {
        assert.equal(getProviderHint('user@gmail.com'), 'gmail');
        assert.equal(getProviderHint('user@GoogleMail.com'), 'gmail');
        assert.equal(getProviderHint('user@hotmail.com'), 'outlook');
        assert.equal(getProviderHint('user@msn.com'), 'outlook');
        assert.equal(getProviderHint('user@example.com', 'aspmx.l.google.com'), 'gmail');
        assert.equal(getProviderHint('user@example.com', 'smtp.google.com'), 'gmail');
        assert.equal(getProviderHint('user@example.com', 'example-com.mail.protection.outlook.com'), 'outlook');
        assert.equal(getProviderHint('user@example.com', 'mx.example.com'), false);
        assert.equal(getProviderHint('user@example.com'), false);
    });

    await t.test('tells consumer mailboxes from organization ones', () => {
        assert.equal(isConsumerMailbox('user@outlook.com'), true);
        assert.equal(isConsumerMailbox('user@gmail.com'), true);
        assert.equal(isConsumerMailbox('user@example.com'), false);
    });

    await t.test('carried by every path that knows the provider', async () => {
        const viaMx = await detect({ mx: 'example-com.mail.protection.outlook.com' });
        assert.equal(viaMx.settings.provider, 'outlook');

        const viaFilter = await detect({ mx: 'mx-mibc-fr-02.mailinblack.com', cnames: { 'autodiscover.example.com': 'autodiscover.outlook.com' } });
        assert.equal(viaFilter.settings.provider, 'outlook');

        const viaSpf = await detect({ mx: 'vade-mx-fr01.hornetsecurity.com', txt: ['v=spf1 include:spf.protection.outlook.com -all'] });
        assert.equal(viaSpf.settings.provider, 'outlook');

        const viaProbe = await detect({ mx: 'mx.provider.net', imapServers: ['imap.example.com'] });
        assert.equal(viaProbe.settings.provider, undefined);
    });
});
