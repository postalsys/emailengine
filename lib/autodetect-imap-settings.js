'use strict';

const punycode = require('punycode.js');
const dns = require('dns').promises;
const { getDomain } = require('tldts');
const { XMLParser, XMLValidator } = require('fast-xml-parser');
const packageData = require('../package.json');

// Configured to produce the same tree shape as the xml2js options this module was written
// against: lowercased tag names, child elements always as arrays (but not the root), attributes
// grouped under `$`, text of an attributed element under `_`, and entity references decoded.
// The `isArray` jpath check is what keeps the root an object: only the root's jpath has no dot.
const xmlParser = new XMLParser({
    ignoreDeclaration: true,
    ignoreAttributes: false,
    attributesGroupName: '$',
    attributeNamePrefix: '',
    textNodeName: '_',
    isArray: (name, jpath, isLeafNode, isAttribute) => !isAttribute && jpath.includes('.'),
    transformTagName: tag => tag.toLowerCase(),
    parseTagValue: false,
    trimValues: true,
    htmlEntities: true
});

// Exchange repeats a connection entry once per client access server, and returns a lone
// `usersetting` object when only one setting was asked for; both have to read as lists
const SOAP_ARRAY_TAGS = new Set(['usersetting', 'protocolconnection']);

// The SOAP autodiscovery response prefixes almost every element (`s:Envelope`, `a:Request`), and
// the settings are read by name rather than by shape, so this parser strips the prefixes instead of
// mirroring xml2js. Kept separate from `xmlParser` so the Mozilla-autoconfig and POX trees, which
// several callers and their tests depend on, keep the shape they have always had.
const soapXmlParser = new XMLParser({
    ignoreDeclaration: true,
    ignoreAttributes: true,
    removeNSPrefix: true,
    transformTagName: tag => tag.toLowerCase(),
    parseTagValue: false,
    trimValues: true,
    htmlEntities: true,
    isArray: name => SOAP_ARRAY_TAGS.has(name)
});

function parseWith(parser, text) {
    if (!text || !text.trim()) {
        // xml2js resolved an empty document to null instead of erroring, callers check for it
        return null;
    }

    const validation = XMLValidator.validate(text);
    if (validation !== true) {
        let err = new Error(`Failed to parse XML: ${validation.err.msg}`);
        err.code = 'EXmlParseError';
        throw err;
    }

    return parser.parse(text);
}

// Two grammars, named so a call site says which one it is reading
const parseXml = text => parseWith(xmlParser, text);
const parseSoapXml = text => parseWith(soapXmlParser, text);

const { fetch: fetchCmd } = require('undici');
const { httpAgent, getMailProxyUrl } = require('./tools');
const { fetchWithVettedRedirects, readBodyCapped } = require('./egress-fetch');
const { validateWebhookTarget } = require('./webhook-egress');
const { probeMailServer } = require('./mail-probe');

const RESOLV_TIMEOUT = 5 * 1000;

// Largest autodiscovery document read. A real autoconfig file or autodiscovery response is a few
// kilobytes; the host serving it is named by the address domain, so its size is not ours to trust.
const MAX_AUTODISCOVERY_BODY = 256 * 1024;

// Shorter cap for the app-password hint MX lookup: it runs on the hosted form's validation-error
// re-render and only produces a cosmetic label, so it must not stall the page for the full RESOLV_TIMEOUT.
const APP_PASSWORD_MX_TIMEOUT = 1500;

// How many times an autodiscovery response may name another endpoint instead of answering. Each hop
// is a request on the critical path of a resolver that shares a five second budget, and a loop
// between two endpoints that redirect to each other would otherwise spend all of it.
const MAX_AUTODISCOVER_REDIRECTS = 2;

/**
 * Does a resolver result actually name a server? Asked by every branch that has to decide whether
 * a lookup answered, so they all decide it the same way.
 *
 * The presence of an `imap` or `smtp` entry is not the same question. The parsers used to build one
 * out of whatever the document carried, so a description of no server at all came back as an object
 * that was truthy and named nothing - which won the resolver race against a slower branch holding
 * the real settings, and rendered the hosted setup form with empty server fields. They now refuse
 * such an entry at the source; this is what the branches ask.
 *
 * @param {Object} res - Result of one resolver, `{ imap, smtp }`
 * @returns {Boolean} True when at least one protocol names a host
 */
function hasResolvedHost(res) {
    return !!(res && ((res.imap && res.imap.host) || (res.smtp && res.smtp.host)));
}

// Google's inbound MX hosts: the classic `*.l.google.com` set, and `smtp.google.com`, the single MX
// Google Workspace has given domains set up since 2023
const GOOGLE_MX = /(?:\bl\.google\.com|^smtp\.google\.com)$/i;

// For lookups that only read the table's triggers, never its translated warning text
const NO_GETTEXT = { gettext: text => text };

// use a function instead of const to prevent translations before locale is set
// The canonical consumer domains are listed alongside the exchange regexes so a plain domain match
// (getAppPassword with exchange=false) resolves the big providers without any MX lookup - each listed
// domain's MX points at the same entry the regex would select, so autodetect results do not change.
const getAppPasswords = gt => [
    {
        trigger: {
            domains: ['gmail.com', 'googlemail.com'],
            exchange: GOOGLE_MX
        },
        // The OAuth2 provider id (as in GET /v1/oauth2) these mailboxes sign in with, see getProviderHint()
        oauth2Provider: 'gmail',
        value: {
            required: true,
            provider: 'Gmail',
            instructions: 'https://support.google.com/accounts/answer/185833'
        }
    },

    {
        trigger: {
            domains: ['icloud.com', 'me.com', 'mac.com'],
            exchange: /\.icloud\.com$/i
        },
        value: {
            required: true,
            provider: 'iCloud',
            instructions: 'https://support.apple.com/en-us/HT204397'
        }
    },

    {
        trigger: {
            domains: ['aol.com']
        },
        value: {
            required: true,
            provider: 'AOL',
            instructions: 'https://help.aol.com/articles/Create-and-manage-app-password'
        }
    },

    {
        trigger: {
            domains: ['yahoo.com'],
            exchange: /\.yahoodns\.net$/i
        },
        value: {
            required: true,
            provider: 'Yahoo',
            instructions: 'https://help.yahoo.com/kb/SLN15241.html'
        }
    },

    {
        trigger: {
            domains: ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'],
            exchange: /\.outlook\.com$/i
        },
        oauth2Provider: 'outlook',
        value: {
            required: true,
            warning: gt.gettext(
                'Microsoft no longer accepts passwords, including app passwords, for IMAP connections to Outlook.com, Hotmail.com, or Microsoft 365. Connect your account using Microsoft sign-in.'
            ),
            provider: 'Microsoft',
            instructions: 'https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944'
        }
    },

    {
        trigger: {
            domains: ['t-online.de'],
            exchange: /\.t-online\.de$/i
        },
        value: {
            required: true,
            provider: 'T-Online',
            instructions: 'https://www.telekom.de/hilfe/apps-dienste/e-mail/programme/passwort-definition'
        }
    }
];

const addressDomain = email =>
    String(email || '')
        .split('@')
        .pop()
        .trim()
        .toLowerCase();

// The table entry the address matches: by domain first, then by MX exchange
function findAppPasswordEntry(email, exchange, gt) {
    const domain = addressDomain(email);
    return (
        getAppPasswords(gt).find(
            entry =>
                (entry.trigger.domains && entry.trigger.domains.includes(domain)) ||
                (exchange && entry.trigger.exchange && entry.trigger.exchange.test(exchange))
        ) || null
    );
}

/**
 * The OAuth2 provider an address signs in with (`oauth2Provider` of its app-password entry), so a
 * setup flow can offer that sign-in instead of a password. The same table decides both, so the
 * app-password hint and the sign-in offer never disagree about a mailbox.
 *
 * @param {string} email - Address
 * @param {string} [exchange] - The domain's primary MX exchange, when known
 * @returns {string|false} `gmail`, `outlook` or false
 */
function getProviderHint(email, exchange) {
    const entry = findAppPasswordEntry(email, exchange, NO_GETTEXT);
    return (entry && entry.oauth2Provider) || false;
}

/**
 * Whether the address is on one of the OAuth2 providers' own consumer domains (gmail.com,
 * outlook.com, ...) rather than a custom domain of a Google Workspace or Microsoft 365
 * organization. Decides which Outlook applications can sign it in: one limited to work accounts
 * cannot.
 *
 * @param {string} email - Address
 * @returns {boolean}
 */
function isConsumerMailbox(email) {
    const domain = addressDomain(email);
    return getAppPasswords(NO_GETTEXT).some(entry => entry.oauth2Provider && entry.trigger.domains && entry.trigger.domains.includes(domain));
}

function getAppPassword(email, exchange, gt) {
    const entry = findAppPasswordEntry(email, exchange, gt);
    return entry ? entry.value : false;
}

// Resolve the lowest-priority MX exchange for a domain (lowercased). Throws if the domain has no MX
// record (callers decide whether that is fatal or just "no exchange-based match").
async function resolveExchange(domain, resolverDns) {
    let srvList = await (resolverDns || dns).resolveMx(domain);
    if (!srvList || !srvList.length) {
        throw new Error('No MX record found for domain');
    }

    const firstItem = srvList.sort((a, b) => a.priority - b.priority).shift();
    return firstItem && firstItem.exchange ? firstItem.exchange.trim().toLowerCase() : undefined;
}

// Resolve only the app-password hint for an email address - a domain match plus, for exchange-based
// providers (Gmail, iCloud, Outlook, ...), a single MX lookup. Much cheaper than autodetectImapSettings
// (one DNS query, no HTTP). The hosted form's failAction re-render uses this to restore the
// app-password label/instructions server-side rather than trusting the submitted (client-controlled)
// hidden fields, which feed unescaped template sinks. Returns the trusted hint object or false; the
// returned values are static table constants, so they are safe to render. Never throws.
async function resolveAppPassword(email, gt) {
    if (!email || typeof email !== 'string' || email.indexOf('@') < 0) {
        return false;
    }

    // Fast path: a domain-only match (e.g. aol.com) needs no network.
    let hint = getAppPassword(email, false, gt);
    if (hint) {
        return hint;
    }

    let domain = email.split('@').pop().trim().toLowerCase();
    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        // ignore - use the raw domain
    }

    let exchange;
    try {
        exchange = await timedFunction(resolveExchange(domain), APP_PASSWORD_MX_TIMEOUT, 'mx');
    } catch (err) {
        // No MX record / lookup failed / timed out - no exchange-based hint to add.
        return false;
    }

    return getAppPassword(email, exchange, gt);
}

async function processAutoconfigFile(email, domain, text, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();
    let user = email.split('@').shift().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }
    let json = parseXml(text);

    // A server element with an empty <hostname> describes no server at all. Building the entry
    // anyway produced an object that was truthy and named nothing, which every caller read as an
    // answer: the resolver race was won by it and the hosted setup form rendered empty fields.
    // So the first element that names a host wins, not simply the first of its type - taking the
    // first let a hostless one discard a usable sibling further down.
    const namesHost = entry => entry && Array.isArray(entry.hostname) && entry.hostname.some(value => value);
    // <port> and <socketType> are optional as far as a hostile document is concerned: a missing one
    // used to throw on `.filter` and discard the whole file, including a sibling entry that was fine
    const firstValue = list => (Array.isArray(list) ? list.filter(entry => entry).shift() : undefined);

    let emailProviders = json && json.clientconfig && Array.isArray(json.clientconfig.emailprovider) ? json.clientconfig.emailprovider : [];
    let incomingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.incomingserver) ? entry.incomingserver : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'imap')
        .find(namesHost);
    let outgoingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.outgoingserver) ? entry.outgoingserver : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'smtp')
        .find(namesHost);

    let imap = false;
    let smtp = false;

    if (incomingServer) {
        const firstHostname = incomingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname.replace(/^%EMAILDOMAIN%$/, domain);

        const port = Number(firstValue(incomingServer.port));
        imap = Object.assign({ host: processedHostname }, port ? { port } : {}, { secure: firstValue(incomingServer.sockettype) === 'SSL' });

        if (Array.isArray(incomingServer.username) && incomingServer.username.length) {
            imap.auth = {
                user: (incomingServer.username.filter(entry => entry).shift() || '')
                    .replace(/^%EMAILADDRESS%$/, email)
                    .replace(/^%EMAILLOCALPART%$/, user)
                    .replace(/^%EMAILDOMAIN%$/, domain)
            };
        }
    }

    if (outgoingServer) {
        const firstHostname = outgoingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname.replace(/^%EMAILDOMAIN%$/, domain);

        const port = Number(firstValue(outgoingServer.port));
        smtp = Object.assign({ host: processedHostname }, port ? { port } : {}, { secure: firstValue(outgoingServer.sockettype) === 'SSL' });

        if (Array.isArray(outgoingServer.username) && outgoingServer.username.length) {
            smtp.auth = {
                user: (outgoingServer.username.filter(entry => entry).shift() || '')
                    .replace(/^%EMAILADDRESS%$/, email)
                    .replace(/^%EMAILLOCALPART%$/, user)
                    .replace(/^%EMAILDOMAIN%$/, domain)
            };
        }
    }

    return { imap, smtp, _source: source };
}

// Every HTTP lookup below reaches a destination derived from the email address a caller typed:
// autoconfig.<domain>, <domain>/.well-known, an autodiscover host a DNS SRV record names, port
// included. That is the same class of destination as a webhook target, so the requests go through
// the same egress policy (lib/webhook-egress.js): the policy-bound dispatcher resolves the name at
// connect time, the pre-check refuses a blocked address up front, and each redirect hop is vetted
// before it is taken. Without this, a DNS record under the caller's control pointed the lookup at
// the cloud metadata service or at whatever else the host can route to.
//
// Not the retrying dispatcher: a lookup that fails is skipped in favor of the next resolver, and
// the retry agent would only stretch the timeout budget of a dead one.
async function fetchAutodiscoveryResource(url, opts) {
    opts = opts || {};
    return await fetchWithVettedRedirects(
        fetchCmd,
        url,
        Object.assign({}, opts, {
            headers: Object.assign({ 'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})` }, opts.headers),
            dispatcher: httpAgent.webhook,
            validateTarget: validateWebhookTarget
        })
    );
}

/**
 * Fills in the I/O a resolver uses. Every resolver takes a context rather than reaching for DNS and
 * fetch directly, so the orchestration (the race, the time budget, the body cap) can be tested
 * against stand-ins, and so the abort signal of the resolver's time budget reaches every request.
 *
 * Applied once, where a context enters: resolver() builds one per time budget, and
 * runAutodiscovery() accepts a partial one from the tests that drive it directly. The resolvers
 * themselves take the context as given.
 *
 * @param {Object} [ctx] - `{ dns, fetchResource, probe, mailProxyUrl, signal, onAuthRequired }`, any of them optional
 * @returns {Object} Context with the production DNS, egress-policed fetch and mail server probe filled in
 */
function withIo(ctx) {
    const io = { dns, fetchResource: fetchAutodiscoveryResource, probe: probeMailServer, mailProxyUrl: getMailProxyUrl };
    for (const key of Object.keys(ctx || {})) {
        // An explicit undefined keeps the production default; only a stand-in actually given wins
        if (ctx[key] !== undefined) {
            io[key] = ctx[key];
        }
    }
    return io;
}

// Reads a response body within the size budget; see MAX_AUTODISCOVERY_BODY
const readDocument = res => readBodyCapped(res, MAX_AUTODISCOVERY_BODY);

async function fetchAutoconfigDocument(url, ctx) {
    let res = await ctx.fetchResource(url, { signal: ctx.signal });

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    return await readDocument(res);
}

async function resolveUsingMozillaDirectory(email, ctx, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let text = await fetchAutoconfigDocument(`https://autoconfig.thunderbird.net/v1.1/${domain}`, ctx);

    return await processAutoconfigFile(email, domain, text, source || 'mozilla');
}

async function resolveUsingAutoconfig(email, ctx, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let text = await fetchAutoconfigDocument(
        `https://autoconfig.${encodeURIComponent(domain)}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(email)}`,
        ctx
    );

    return await processAutoconfigFile(email, domain, text, source || 'autoconfig');
}

async function resolveUsingWellKnown(email, ctx, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let text = await fetchAutoconfigDocument(`http://${encodeURIComponent(domain)}/.well-known/autoconfig/mail/config-v1.1.xml`, ctx);

    return await processAutoconfigFile(email, domain, text, source || 'well-known');
}

// First record of an SRV lookup by priority, or null when the name has none. A missing record is
// an ordinary answer here (most domains publish none), so it must not end the whole resolver.
async function lookupSrv(ctx, name) {
    try {
        let srvList = await ctx.dns.resolveSrv(name);
        return (srvList || []).sort((a, b) => a.priority - b.priority).shift() || null;
    } catch (err) {
        return null;
    }
}

async function resolveUsingSRV(email, ctx, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    const lookupImap = async () => {
        let record = await lookupSrv(ctx, `_imaps._tcp.${domain}`);
        if (record) {
            return { host: record.name, port: record.port, secure: true };
        }
        record = await lookupSrv(ctx, `_imap._tcp.${domain}`);
        return record ? { host: record.name, port: record.port, secure: false } : false;
    };

    const lookupSmtp = async () => {
        let record = await lookupSrv(ctx, `_submissions._tcp.${domain}`);
        if (record) {
            return { host: record.name, port: record.port, secure: true };
        }
        // Used to be the one lookup left unguarded, so a domain with IMAP records and no
        // _submission one threw away the IMAP answer it had already found
        record = await lookupSrv(ctx, `_submission._tcp.${domain}`);
        // Some providers invalidly use _submission instead of _submissions
        return record ? { host: record.name, port: record.port, secure: record.port === 465 } : false;
    };

    // The two chains are independent, and this resolver runs against a time budget it shares
    // with four others, so they are not paid for one after the other
    const [imap, smtp] = await Promise.all([lookupImap(), lookupSmtp()]);

    return { smtp, imap, _source: source || 'srv' };
}

// A fixed answer for a provider whose servers are the same for every custom domain. IMAP is always
// implicit TLS on 993; SMTP is implicit TLS on 465 and STARTTLS on 587.
function staticConfig(imapHost, smtpHost, smtpPort) {
    return {
        imap: {
            host: imapHost,
            port: 993,
            secure: true
        },
        smtp: {
            host: smtpHost,
            port: smtpPort,
            secure: smtpPort === 465
        },
        _source: 'mx'
    };
}

// Microsoft 365's IMAP and SMTP hosts and submission port, for the MX table and the fallback stage
const MICROSOFT_365_SERVERS = ['outlook.office365.com', 'smtp.office365.com', 587];

// Well known MX servers, checked in order and the first match wins. `match` is a pattern, or a
// string the exchange has to equal. An entry answers with `config` (static, built fresh for every
// lookup), `resolve` (delegates to another resolver) or `build` (derived from the match).
const MX_PROVIDERS = [
    { match: GOOGLE_MX, resolve: (email, ctx) => resolveUsingSRV(email, ctx, 'gmail.com', 'mx') },
    { match: /\bmx\.yandex\.net$/i, resolve: (email, ctx) => resolveUsingAutoconfig(email, ctx, 'yandex.ru', 'mx') },
    // Zone.eu
    { match: /^mx\d*\.zone\.eu$/i, config: ['mail.zone.ee', 'smtp.zone.ee', 465] },
    // Lark Mail / ByteDance
    { match: /\blarksuite\.com$/i, config: ['imap.larksuite.com', 'smtp.larksuite.com', 465] },
    { match: /\bzonemx\.eu$/i, resolve: (email, ctx) => resolveUsingAutoconfig(email, ctx, 'zone.ee', 'mx') },
    // AWS WorkMail
    {
        match: /^inbound-smtp\.([^.]+)\.amazonaws\.com$/,
        build: awsMatch => {
            let region = awsMatch[1].toLowerCase().trim();
            return staticConfig(`imap.mail.${region}.awsapps.com`, `smtp.mail.${region}.awsapps.com`, 465);
        }
    },
    // Zoho custom domain in EU
    { match: /^mx\d*\.zoho\.eu$/i, config: ['imappro.zoho.eu', 'smtppro.zoho.eu', 465] },
    // Zoho custom domain not in EU
    { match: /^mx\d*\.zoho\.com$/i, config: ['imappro.zoho.com', 'smtppro.zoho.com', 465] },
    // MS365: as autodiscovery is currently (2021-11-17) closed use a fixed response
    { match: /\bprotection\.outlook\.com$/i, config: MICROSOFT_365_SERVERS },
    // Inbox.com
    { match: 'mx.dka.mailcore.net', config: ['imap.dka.mailcore.net', 'smtp.dka.mailcore.net', 587] },
    { match: 'ekiri.ee', config: ['turvaline.ekiri.ee', 'turvaline.ekiri.ee', 465] },
    // Alibaba Mail
    { match: /^mx\d*\.sg\.aliyun\.com$/i, config: ['imap.sg.aliyun.com', 'smtp.sg.aliyun.com', 465] },
    // ATT
    { match: /mx-vip\d*\.prodigy\.net$/i, config: ['imap.mail.att.net', 'smtp.mail.att.net', 465] },
    // Naver (kr)
    { match: /^mx\d*\.naver\.com$/i, config: ['imap.naver.com', 'smtp.naver.com', 587] },
    // QQ enterprise
    { match: /^mxbiz\d*\.qq\.com$/i, config: ['imap.exmail.qq.com', 'smtp.exmail.qq.com', 465] }
];

function matchMxProvider(provider, exchange) {
    if (typeof provider.match === 'string') {
        return exchange === provider.match ? [exchange] : null;
    }
    return provider.match.exec(exchange);
}

// Resolves the configuration of the first provider the exchange matches, or throws "Nothing found"
// carrying the exchange, which is what the app-password hint is matched on
async function resolveMxProviderConfig(email, ctx, exchange) {
    const provider = MX_PROVIDERS.find(entry => matchMxProvider(entry, exchange));
    if (!provider) {
        let error = new Error('Nothing found');
        error.exchange = exchange;
        throw error;
    }

    if (provider.resolve) {
        return await provider.resolve(email, ctx);
    }
    if (provider.build) {
        return provider.build(matchMxProvider(provider, exchange));
    }
    return staticConfig(...provider.config);
}

async function resolveUsingMX(email, ctx, gt) {
    let domain = email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    // do not catch potential error as there's nothing to do if we do not find the MX record
    let exchange = await resolveExchange(domain, ctx.dns);

    let accountConfig = await resolveMxProviderConfig(email, ctx, exchange);

    if (!hasResolvedHost(accountConfig)) {
        // The exchange matched, but the config it delegated to named no server: the Gmail branch
        // reads SRV records and the Yandex one an autoconfig file, and either can come back empty.
        // Reported as a miss rather than returned, so the racing resolvers get their turn - and
        // carrying the exchange, which is what the app-password hint is matched on.
        let error = new Error('Nothing found');
        error.exchange = exchange;
        throw error;
    }

    return withHints(accountConfig, email, exchange, gt);
}

/**
 * Adds what the address and its MX exchange say beyond the server settings: the app-password
 * requirement and the OAuth2 provider hint. A result that already carries either keeps its own.
 *
 * @returns {Object} A copy of the result with `appPassword` and `provider` where they apply
 */
function withHints(res, email, exchange, gt) {
    const appPassword = res.appPassword || getAppPassword(email, exchange, gt);
    const provider = res.provider || getProviderHint(email, exchange);
    return Object.assign({}, res, appPassword ? { appPassword } : {}, provider ? { provider } : {});
}

function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, c => {
        switch (c) {
            case '<':
                return '&lt;';
            case '>':
                return '&gt;';
            case '&':
                return '&amp;';
            case "'":
                return '&apos;';
            case '"':
                return '&quot;';
        }
    });
}

// Exchange answers `application/xml` with 415 before it looks at the body, on both autodiscovery
// endpoints. Every request below has to be announced as text/xml.
const AUTODISCOVER_CONTENT_TYPE = 'text/xml; charset=utf-8';

/**
 * Builds the legacy ("POX") autodiscovery request.
 *
 * The child order is load-bearing: the request schema declares a sequence, and Exchange answers
 * `<ErrorCode>600</ErrorCode>` ("Invalid Request") when `AcceptableResponseSchema` arrives ahead of
 * `EMailAddress`, which is the order this used to send.
 *
 * @param {string} email - Address to look up
 * @returns {string} Request document
 */
function buildAutodiscoverRequest(email) {
    return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>${escapeXml(email)}</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>`;
}

/**
 * Builds a SOAP `GetUserSettings` request for the mailbox's external IMAP and SMTP endpoints.
 *
 * This is the modern autodiscovery service (Exchange 2010 and later). It is asked in addition to
 * the POX endpoint because Exchange populates the two from different places: POX commonly answers
 * with nothing but the `WEB` (Outlook on the web) protocol, while these settings are the ones the
 * webmail "POP and IMAP settings" page shows.
 *
 * @param {string} email - Mailbox to look up
 * @returns {string} Request document
 */
function buildAutodiscoverSoapRequest(email) {
    return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2013</a:RequestedServerVersion>
    <wsa:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetUserSettings</wsa:Action>
  </soap:Header>
  <soap:Body>
    <a:GetUserSettingsRequestMessage>
      <a:Request>
        <a:Users><a:User><a:Mailbox>${escapeXml(email)}</a:Mailbox></a:User></a:Users>
        <a:RequestedSettings>
          <a:Setting>ExternalImap4Connections</a:Setting>
          <a:Setting>ExternalSmtpConnections</a:Setting>
        </a:RequestedSettings>
      </a:Request>
    </a:GetUserSettingsRequestMessage>
  </soap:Body>
</soap:Envelope>`;
}

// "SSL" is implicit TLS, "TLS" is STARTTLS on the cleartext port, "None" is neither
const isImplicitTls = entry => /^ssl$/i.test(entry.encryptionmethod);

/**
 * Picks one connection out of a `ProtocolConnectionCollectionSetting`.
 *
 * Exchange lists the same endpoint once per client access server, so the collection arrives with
 * dozens of interchangeable entries, and it offers both the implicit-TLS and the STARTTLS port. The
 * implicit-TLS one is preferred: it is what the provider's own documentation tells users to use,
 * and it needs no upgrade step that a middlebox can strip.
 *
 * @param {Array} [connections] - Parsed `protocolconnection` entries
 * @returns {Object|Boolean} `{ host, port, secure }`, or false when nothing usable was listed
 */
function pickProtocolConnection(connections) {
    let picked = null;

    for (let entry of connections || []) {
        if (!entry || !entry.hostname || !Number(entry.port)) {
            continue;
        }
        if (isImplicitTls(entry)) {
            picked = entry;
            break;
        }
        picked = picked || entry;
    }

    return picked ? { host: picked.hostname, port: Number(picked.port), secure: isImplicitTls(picked) } : false;
}

/**
 * Reads IMAP and SMTP settings out of a SOAP `GetUserSettings` response.
 *
 * @param {string} text - Response document
 * @returns {Object} `{ imap, smtp, _source }`, either entry false when it was not listed
 */
function processAutodiscoverSoapResponse(text) {
    let json = parseSoapXml(text);

    let settings = json?.envelope?.body?.getusersettingsresponsemessage?.response?.userresponses?.userresponse?.usersettings?.usersetting || [];

    let connectionsFor = name =>
        pickProtocolConnection(settings.find(entry => String(entry?.name).toLowerCase() === name)?.protocolconnections?.protocolconnection);

    return {
        imap: connectionsFor('externalimap4connections'),
        smtp: connectionsFor('externalsmtpconnections'),
        _source: 'autodiscover'
    };
}

/**
 * Resolves the host that answers autodiscovery for a domain.
 *
 * @param {string} domain - Punycode domain
 * @returns {Promise<string>} Host, with a port appended when the SRV record names a non-default one
 */
// The origin of a URL, but only when it is one a password may be sent to. A redirect is allowed to
// lead to http (the anonymous lookup carries nothing worth protecting), so the host that ends up
// issuing the challenge is not necessarily on https, and Basic over cleartext would hand the
// mailbox password to anyone on the path.
/**
 * The endpoint a POX response names instead of answering.
 *
 * Microsoft's sequence lets a server say "ask over there" rather than return settings:
 * `<Action>redirectUrl</Action>` with a `<RedirectUrl>` names another endpoint for the same mailbox.
 * processAutodiscoverResponse() reads `Account > Protocol` only, so such a response parsed as naming
 * no server and the lookup stopped there.
 *
 * `<RedirectAddr>` is deliberately NOT followed. It names a different ADDRESS, so following it would
 * restart the lookup for a mailbox the caller did not ask about. A response carrying only a
 * RedirectAddr stays a loss.
 *
 * The endpoint this does name is asked anonymously - see the call site in runAutodiscovery().
 *
 * @param {String} text - The POX response body
 * @returns {String|false} The URL the response names, or false
 */
function poxRedirectUrl(text) {
    let json;
    try {
        // Only reached after processAutodiscoverResponse() has already parsed the same body, so a
        // document that does not parse cannot get here in production - guarded so the helper is still
        // safe called on its own
        json = parseXml(text);
    } catch (err) {
        return false;
    }
    const responses = json && json.autodiscover && Array.isArray(json.autodiscover.response) ? json.autodiscover.response : [];

    for (const responseRow of responses) {
        if (!responseRow || !Array.isArray(responseRow.account)) {
            continue;
        }
        for (const accountRow of responseRow.account) {
            const action = accountRow && Array.isArray(accountRow.action) ? accountRow.action[0] : null;
            const redirectUrl = accountRow && Array.isArray(accountRow.redirecturl) ? accountRow.redirecturl[0] : null;

            // The action is what makes it a redirect; a document that carries a stray RedirectUrl
            // without saying so is not one
            if (typeof action === 'string' && /^redirecturl$/i.test(action.trim()) && typeof redirectUrl === 'string' && redirectUrl.trim()) {
                return redirectUrl.trim();
            }
        }
    }

    return false;
}

function secureOriginOf(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:' ? parsed.origin : false;
    } catch (err) {
        return false;
    }
}

async function resolveAutodiscoveryHost(domain, ctx) {
    let record = await lookupSrv(ctx, `_autodiscover._tcp.${domain}`);
    if (record) {
        return `${record.name}${record.port !== 443 ? `:${record.port}` : ''}`;
    }

    return `autodiscover.${encodeURIComponent(domain)}`;
}

/**
 * The https endpoint that the subdomain's plain-http redirect names.
 *
 * Microsoft's sequence has a step before the POSTs: an unauthenticated GET to
 * `http://autodiscover.<domain>/autodiscover/autodiscover.xml`, whose 302 names the endpoint that
 * actually answers. It used to be skipped entirely, and for a provider that publishes nothing else
 * the lookup then had nowhere to go: IONOS/1&1 hosted mail points `autodiscover.<domain>` at a
 * redirector that listens on port 80 only, so the https POST could not connect and the whole
 * Exchange branch failed for every domain on that provider.
 *
 * Anonymous, and it stays anonymous: no credential is attached to an http request, and only an https
 * origin is returned, so a redirect that lands on http names nothing. The target is chosen by a
 * server the address domain's DNS points at, so the hop goes through the same vetted-redirect fetch
 * as every other request here and `fetchWithVettedRedirects` drops credentials on a cross-origin hop.
 *
 * @param {String} domain - The address domain, already punycoded
 * @param {Object} ctx - `{ fetchResource, signal }`
 * @returns {Promise<String|false>} An https origin, or false when the lookup names nothing new
 */
async function autodiscoverRedirectOrigin(domain, ctx) {
    const { fetchResource, signal } = withIo(ctx);
    const subdomain = `autodiscover.${encodeURIComponent(domain)}`;

    try {
        const res = await fetchResource(`http://${subdomain}/autodiscover/autodiscover.xml`, { method: 'get', signal });
        // Nothing reads the body - only where the request ended up - but it is drained so the
        // keep-alive socket goes back to the pool
        await readDocument(res).catch(() => false);

        const origin = secureOriginOf(res.url || '');
        // A plain http-to-https upgrade on the same host names nothing new: that origin is already
        // one of the candidates raced below
        return origin && origin !== `https://${subdomain}` ? origin : false;
    } catch (err) {
        return false;
    }
}

/**
 * Runs autodiscovery against one host.
 *
 * Both endpoints answer a mailbox lookup with 401 on a hosted Exchange, so the password is what
 * makes them usable at all. It is offered only once the server has answered with a challenge that
 * names Basic: never on the first request, never to a host that answered some other way, and only
 * ever over https - a challenge that reached us over http is refused rather than answered.
 *
 * The two endpoints are asked at the same time rather than one after the other: they are answered
 * from different Exchange configuration, either can be the one that carries IMAP settings, and the
 * whole resolver runs against a five second budget shared with four other lookups.
 *
 * @param {string} baseUrl - Origin of the autodiscovery host, no trailing slash
 * @param {string} email - Mailbox to look up
 * @param {Object} [credentials] - `{ user, pass }`; the lookup stays anonymous without it
 * @param {Object} [ctx] - `{ fetchResource, signal }`: the fetch to use, `(url, opts) =>
 *   Promise<Response>`, and the signal that aborts every request of the lookup (the resolver's
 *   time budget). Either may be left out, this is an entry point of its own for the tests
 * @param {Number} [redirectsLeft] - How many more times a response may name another endpoint
 *   instead of answering; see MAX_AUTODISCOVER_REDIRECTS
 * @returns {Promise<Object>} `{ imap, smtp, _source }`
 * @throws {Error} When no endpoint returned anything usable
 */
async function runAutodiscovery(baseUrl, email, credentials, ctx, redirectsLeft = MAX_AUTODISCOVER_REDIRECTS) {
    const { fetchResource, signal, onAuthRequired } = withIo(ctx);

    const poxBody = buildAutodiscoverRequest(email);
    const post = (origin, path, body, authorization) =>
        fetchResource(`${origin}${path}`, {
            method: 'post',
            headers: Object.assign({ 'Content-type': AUTODISCOVER_CONTENT_TYPE }, authorization ? { Authorization: authorization } : {}),
            body,
            signal
        });

    // A server that answers without credentials is never asked for them
    let res = await post(baseUrl, '/autodiscover/autodiscover.xml', poxBody);
    if (res.ok) {
        const body = await readDocument(res);
        let result = processAutodiscoverResponse(body);
        if (hasResolvedHost(result)) {
            return result;
        }

        // The response can name another endpoint for the same mailbox instead of answering, which read
        // as "no server" before. Asked ANONYMOUSLY, whatever credentials this lookup holds: the origin
        // is named by the body of a server that answered 200 without asking for anything, and an
        // anonymous 200 carrying no settings is exactly the case that must end the lookup rather than
        // escalate it. Passing the password on here would let any host the address domain points at
        // choose where that password goes, which is the one thing the rules around it prevent. https
        // only, for the same reason the 401 retry is.
        const redirectOrigin = redirectsLeft > 0 && secureOriginOf(poxRedirectUrl(body) || '');
        if (redirectOrigin) {
            return await runAutodiscovery(redirectOrigin, email, undefined, ctx, redirectsLeft - 1);
        }

        // It answered anonymously, just with nothing usable. It never asked for a password, so it
        // is not given one.
        throw new Error('Invalid response');
    }

    // Nothing here reads the body, and the retries below reuse this connection
    await readDocument(res).catch(() => false);

    // Only a challenge that names Basic earns the password. A 404 from a wildcard-DNS parking host,
    // a 500, a CDN answering an unknown path, a server offering only NTLM - all answered without
    // asking for one, and Basic would be no use to the last of them anyway.
    if (res.status !== 401 || !/\bbasic\b/i.test(res.headers?.get('www-authenticate') || '')) {
        throw new Error('Invalid response');
    }

    // Recorded as it happens rather than read off the rejection: a sibling lookup that outlives the
    // time budget turns the whole race into a timeout, which would hide that this host asked. The
    // fallback stage must not guess a server for a mailbox that is behind a password-protected
    // autodiscovery endpoint, see resolveUsingFallbacks()
    if (onAuthRequired) {
        onAuthRequired();
    }

    if (!credentials || !credentials.pass) {
        throw new Error('Invalid response');
    }

    // Ask the host that actually answered. Following the redirect again for each retry would repeat
    // every hop, and a cross-origin one strips the very header the retry exists to carry. A
    // challenge that arrived over http is refused rather than answered on the original host: the
    // host that asked for the password is the one that would have to receive it.
    const origin = secureOriginOf(res.url || baseUrl);
    if (!origin) {
        throw new Error('Invalid response');
    }
    const authorization = `Basic ${Buffer.from(`${credentials.user || email}:${credentials.pass}`).toString('base64')}`;

    const attempt = (path, body, processResponse) =>
        post(origin, path, body, authorization)
            .then(async res => (res.ok ? processResponse(await readDocument(res)) : false))
            .catch(() => false);

    // Both are in flight before either is awaited, and whichever answers first with a usable
    // configuration wins. Collecting them into an array first - `[await pox, await soap]` - looked
    // like it did that but awaited both, so a stalled endpoint held up an answer the other one had
    // already given, and the five second budget this resolver shares could run out with the
    // settings sitting in a resolved promise. The two are populated from different Exchange
    // configuration, so either can be the one that has them.
    //
    // An answer that names no server is a loss rather than a win, which is what makes this the same
    // policy resolver() applies to the five lookups above it. POX still wins a tie, because both
    // are already settled by then and reactions run in the order they were subscribed, and it is
    // the only one of the two that names the login to use.
    const pox = attempt('/autodiscover/autodiscover.xml', poxBody, processAutodiscoverResponse);
    const soap = attempt('/autodiscover/autodiscover.svc', buildAutodiscoverSoapRequest(email), processAutodiscoverSoapResponse);

    const usable = result => (hasResolvedHost(result) ? result : Promise.reject(new Error('Invalid response')));

    try {
        return await Promise.any([pox.then(usable), soap.then(usable)]);
    } catch (err) {
        // Both came back with nothing usable, which Promise.any reports as an AggregateError over
        // the two rejections above
        throw new Error('Invalid response', { cause: err });
    }
}

async function resolveUsingAutodiscovery(email, ctx, credentials) {
    let domain = email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    // Microsoft's sequence names three places a provider may publish autodiscovery, and a provider
    // can publish only one of them: the root domain, the autodiscover subdomain (or whatever the
    // _autodiscover._tcp SRV record names instead), and the endpoint that the subdomain's plain-http
    // redirect names. Only the second was ever tried.
    //
    // Raced rather than walked in order, for the same reason the two endpoints of one host already
    // are: this resolver shares a five second budget with four others, and a domain that publishes
    // none of them fails slowly - a DNS name that does not exist, a port that refuses the connection
    // and a host that answers 404 are three waits, not three answers.
    const subdomainOrigin = `https://${await resolveAutodiscoveryHost(domain, ctx)}`;
    const rootOrigin = `https://${encodeURIComponent(domain)}`;

    const attempts = [...new Set([subdomainOrigin, rootOrigin])].map(origin => runAutodiscovery(origin, email, credentials, ctx));

    // One request behind the others, so it is started here rather than awaited first
    attempts.push(
        autodiscoverRedirectOrigin(domain, ctx).then(origin => {
            if (!origin) {
                throw new Error('Invalid response');
            }
            return runAutodiscovery(origin, email, credentials, ctx);
        })
    );

    try {
        // Every attempt rejects unless it has a usable configuration (runAutodiscovery throws on
        // anything else), so the first to resolve is the first real answer
        return await Promise.any(attempts);
    } catch (err) {
        throw new Error('Invalid response', { cause: err });
    }
}

// Ports where TLS starts with the connection rather than through STARTTLS
const IMPLICIT_TLS_PORTS = new Set([993, 465]);

/**
 * Reads the TLS mode off a POX `<Protocol>` entry.
 *
 * `<Encryption>` (None, SSL, TLS, Auto) overrides `<SSL>` when both are present, per the POX
 * schema. "TLS" is STARTTLS on the cleartext port, and "Auto" leaves the choice to the client,
 * so it is decided by the port.
 *
 * @param {Object} entry - Parsed `<Protocol>` fields
 * @param {Number} [port] - The listed port
 * @returns {Boolean|undefined} true for implicit TLS, false for none or STARTTLS, undefined when neither element says
 */
function poxSecure(entry, port) {
    if (entry.encryption && typeof entry.encryption === 'string') {
        switch (entry.encryption.trim().toLowerCase()) {
            case 'ssl':
                return true;
            case 'tls':
            case 'none':
                return false;
            case 'auto':
                return IMPLICIT_TLS_PORTS.has(port);
        }
    }
    if (entry.ssl && typeof entry.ssl === 'string') {
        return entry.ssl === 'on';
    }
    return undefined;
}

function processAutodiscoverResponse(text, source) {
    let json = parseXml(text);

    let imap = false;
    let smtp = false;

    let resp = json && json.autodiscover && Array.isArray(json.autodiscover.response) ? json.autodiscover.response : [];
    resp.forEach(responseRow => {
        if (!responseRow || !Array.isArray(responseRow.account)) {
            return;
        }
        responseRow.account.forEach(accountRow => {
            if (
                !accountRow ||
                !accountRow.accounttype ||
                !Array.isArray(accountRow.accounttype) ||
                !Array.isArray(accountRow.protocol) ||
                !accountRow.accounttype.includes('email')
            ) {
                return;
            }

            accountRow.protocol.forEach(protocolRow => {
                let entry = {};
                for (let key of ['type', 'server', 'loginname', 'port', 'ssl', 'encryption']) {
                    if (protocolRow && Array.isArray(protocolRow[key]) && protocolRow[key].length) {
                        entry[key] = protocolRow[key][0];
                    }
                }

                let getStructureFromObject = entry => {
                    if (!entry.server || typeof entry.server !== 'string') {
                        // A <Protocol> with a <Type> and no <Server> names nothing, and an entry
                        // that names nothing is not a result - see hasResolvedHost()
                        return false;
                    }

                    let res = { host: entry.server };
                    if (entry.port && (typeof entry.port === 'string' || (typeof entry.port === 'number' && !isNaN(entry.port)))) {
                        res.port = Number(entry.port);
                    }
                    let secure = poxSecure(entry, res.port);
                    if (typeof secure === 'boolean') {
                        res.secure = secure;
                    }
                    if (entry.loginname && typeof entry.loginname === 'string') {
                        res.auth = { user: entry.loginname };
                    }
                    return res;
                };

                // First usable entry wins. Exchange emits several <Protocol> blocks of the same
                // type (internal and external variants, and Type-only blocks naming no server at
                // all), and overwriting on every match let a hostless sibling further down discard
                // the one that actually named a host
                if (/^IMAP$/i.test(entry.type) && !imap) {
                    // imap entry
                    imap = getStructureFromObject(entry);
                }

                if (/^SMTP$/i.test(entry.type) && !smtp) {
                    // smtp entry
                    smtp = getStructureFromObject(entry);
                }
            });
        });
    });

    return { imap, smtp, _source: source || 'autodiscover' };
}

// ---------------------------------------------------------------------------------------------
// Fallback stage: domains that publish nothing about their mail
//
// Most domains on small hosting providers have no SRV records, no autoconfig document and no
// autodiscovery, so every resolver above comes back empty. resolveUsingFallbacks() runs only then,
// and works from what the domain's DNS does say: where its MX points, what its mail names are
// aliases of, and what its SPF record authorizes.
// ---------------------------------------------------------------------------------------------

// Hosts probed per protocol, most likely first. Each protocol is probed in one round with all of its
// candidates at once, so this is also the most connections a lookup opens at a time.
const MAX_PROBE_CANDIDATES = 6;

// The names whose CNAME targets are probed, see probeCandidates()
const ALIAS_NAMES = ['imap', 'mail', 'smtp', 'webmail'];

const MICROSOFT_AUTODISCOVER = /^autodiscover\.outlook\.com\.?$/i;
const MICROSOFT_SPF = /(?:^|\s)include:spf\.protection\.outlook\.com(?:\s|$)/i;

// Lowercased, without a trailing dot, in its ASCII form
function asciiDomain(domain) {
    domain = String(domain || '')
        .trim()
        .toLowerCase()
        .replace(/\.$/, '');
    try {
        return punycode.toASCII(domain);
    } catch (err) {
        return domain;
    }
}

// A name that does not resolve is one of the ordinary answers here, never an error
async function lookupOrEmpty(lookup) {
    try {
        return (await lookup()) || [];
    } catch (err) {
        return [];
    }
}

/**
 * The domains an MX host sits under, most specific first, down to its registrable domain:
 * `mx1.mail.ovh.net` gives `mail.ovh.net` and `ovh.net`.
 *
 * @param {string} [exchange] - MX host
 * @returns {string[]} Parent domains
 */
function exchangeParents(exchange) {
    const base = exchange && getDomain(exchange);
    if (!base || base === exchange) {
        return [];
    }

    const labels = exchange.split('.');
    const parents = [];
    for (let i = 1; i < labels.length; i++) {
        const parent = labels.slice(i).join('.');
        parents.push(parent);
        if (parent === base) {
            break;
        }
    }
    return parents;
}

function microsoft365Config(gt) {
    const appPassword = getAppPasswords(gt).find(entry => entry.value.provider === 'Microsoft');
    return Object.assign(staticConfig(...MICROSOFT_365_SERVERS), { _source: 'microsoft365', appPassword: appPassword.value, provider: 'outlook' });
}

/**
 * The Thunderbird directory, asked for the domains the MX host sits under rather than for the
 * address domain. This is a step of Thunderbird's own lookup sequence that the racing
 * resolveUsingMozillaDirectory() does not take: OVH lists `ovh.net`, and every OVH MX Plan domain
 * has its MX under it. The address domain still fills `%EMAILDOMAIN%`, as in Thunderbird.
 *
 * @returns {Promise<Object|null>} The most specific parent's entry that names a server
 */
async function lookupDirectoryByMx(email, domain, parents, ctx) {
    const answers = await Promise.all(
        parents.map(parent =>
            fetchAutoconfigDocument(`https://autoconfig.thunderbird.net/v1.1/${encodeURIComponent(parent)}`, ctx)
                .then(text => processAutoconfigFile(email, domain, text, 'mozilla-mx'))
                .catch(() => null)
        )
    );
    return answers.find(hasResolvedHost) || null;
}

/**
 * Collects what the fallback stage decides on. Only DNS reads and the directory request, nothing
 * that touches the domain's own servers, so it runs alongside the resolver race and costs that
 * race nothing; resolver() throws it away when the race wins.
 *
 * @param {string} email - Address to look up
 * @param {string} [exchange] - Primary MX host, when the domain has one
 * @param {Object} ctx - `{ dns, fetchResource, signal }`
 * @returns {Promise<Object>} The facts resolveUsingFallbacks() works from
 */
async function gatherFallbackFacts(email, exchange, ctx) {
    const domain = asciiDomain(email.split('@').pop());
    exchange = exchange ? asciiDomain(exchange) : null;
    const parents = exchangeParents(exchange).filter(parent => parent !== domain);

    const cname = name => lookupOrEmpty(() => ctx.dns.resolveCname(name)).then(list => list.map(asciiDomain).filter(Boolean));

    const [autodiscoverTargets, txtRecords, aliasEntries, directory] = await Promise.all([
        cname(`autodiscover.${domain}`),
        lookupOrEmpty(() => ctx.dns.resolveTxt(domain)),
        Promise.all(ALIAS_NAMES.map(async name => [name, await cname(`${name}.${domain}`)])),
        lookupDirectoryByMx(email, domain, parents, ctx)
    ]);

    return {
        domain,
        exchange,
        parents,
        microsoftAutodiscover: autodiscoverTargets.some(target => MICROSOFT_AUTODISCOVER.test(target)),
        microsoftSpf: txtRecords.map(chunks => [].concat(chunks).join('')).some(record => MICROSOFT_SPF.test(record)),
        aliases: Object.fromEntries(aliasEntries),
        directory
    };
}

/**
 * The hosts worth probing, most likely first: for IMAP the MX host itself, `imap.`/`mail.` of the
 * domain, whatever its mail names are aliases of (probed under the target's own name, since the
 * alias carries the provider's certificate), and `imap.` under the MX host's domains. SMTP starts
 * from the submission names and then tries the IMAP list, as the same host often serves both.
 *
 * @param {Object} facts - From gatherFallbackFacts()
 * @returns {{imap: string[], smtp: string[]}} Candidates, at most MAX_PROBE_CANDIDATES each
 */
function probeCandidates(facts) {
    const { domain, exchange, parents, aliases } = facts;
    const firstUnique = list => [...new Set(list.filter(Boolean))].slice(0, MAX_PROBE_CANDIDATES);

    const imap = firstUnique([
        exchange,
        `imap.${domain}`,
        `mail.${domain}`,
        ...aliases.imap,
        ...aliases.mail,
        ...aliases.smtp,
        ...aliases.webmail,
        ...parents.map(parent => `imap.${parent}`)
    ]);
    const smtp = firstUnique([`smtp.${domain}`, ...aliases.smtp, ...parents.map(parent => `smtp.${parent}`), ...imap]);

    return { imap, smtp };
}

/**
 * Probes the candidates and builds a configuration from the first IMAP server that answered,
 * paired with an SMTP server: the IMAP host itself when it also answered on 465, otherwise the
 * first SMTP candidate that did. SMTP is probed only once an IMAP server answered, since without
 * one the result is thrown away; each round probes its candidates all at once.
 *
 * @returns {Promise<Object|null>} `{ imap, smtp, _source: 'probe' }`, or null when no IMAP server answered
 */
async function probeLikelyHosts(facts, ctx) {
    const candidates = probeCandidates(facts);
    const proxyUrl = await ctx.mailProxyUrl();
    const greeted = async (hosts, port) => {
        const answered = await Promise.all(hosts.map(host => ctx.probe(host, port, { signal: ctx.signal, proxyUrl }).catch(() => false)));
        return hosts.filter((host, i) => answered[i]);
    };

    const imapHosts = await greeted(candidates.imap, 993);
    if (!imapHosts.length) {
        return null;
    }
    const imapHost = imapHosts[0];

    const smtpHosts = await greeted(candidates.smtp, 465);
    const smtpHost = smtpHosts.includes(imapHost) ? imapHost : smtpHosts[0];

    return {
        imap: { host: imapHost, port: 993, secure: true },
        smtp: smtpHost ? { host: smtpHost, port: 465, secure: true } : false,
        _source: 'probe'
    };
}

/**
 * The last autodiscovery stage, run only once every resolver above has come back empty. In order:
 *
 * 1. `autodiscover.<domain>` is an alias of Microsoft's: Microsoft 365 behind a mail filter, whose
 *    MX names the filter (Mailinblack, Hornetsecurity, Proofpoint) so the MX table never sees it.
 * 2. An autodiscovery host asked for the mailbox password: hosted Exchange. Nothing is guessed,
 *    since OVH and others run Exchange and plain IMAP mailboxes behind the same MX and a guess
 *    would name the wrong server. The caller has to supply the password instead.
 * 3. The Thunderbird directory lists one of the MX host's domains.
 * 4. A probe of the likely hosts finds a mail server (see probeCandidates()).
 * 5. The SPF record authorizes Microsoft 365, and nothing above found a server of the domain's
 *    own. Sending through Microsoft says little about where the mailboxes are, so this is last.
 *
 * @param {string} email - Address to look up
 * @param {Object} facts - From gatherFallbackFacts()
 * @param {Object} ctx - `{ probe, signal }` plus what the probe needs
 * @param {Object} gt - gettext instance
 * @param {boolean} authRequired - An autodiscovery host answered with a Basic challenge
 * @returns {Promise<Object>} `{ imap, smtp, _source }`
 * @throws {Error} When none of them found a server
 */
async function resolveUsingFallbacks(email, facts, ctx, gt, authRequired) {
    if (facts.microsoftAutodiscover) {
        return microsoft365Config(gt);
    }

    if (authRequired) {
        throw new Error('Nothing found');
    }

    const found = facts.directory || (await probeLikelyHosts(facts, ctx));
    if (found) {
        return withHints(found, email, facts.exchange, gt);
    }

    if (facts.microsoftSpf) {
        return microsoft365Config(gt);
    }

    throw new Error('Nothing found');
}

/**
 * Races a lookup against a time budget.
 *
 * Given a function, it is called with an AbortSignal that fires when the budget runs out, so the
 * requests still in flight are cancelled rather than left to stream into memory after the race
 * has been decided. A promise can only be raced, not cancelled.
 *
 * @param {Promise|Function} prom - The lookup, or `signal => Promise` to make it abortable
 * @param {number} timeout - Budget in milliseconds
 * @param {string} [source] - Resolver name, copied onto the timeout error
 * @returns {Promise<*>} Whatever the lookup resolves with
 */
async function timedFunction(prom, timeout, source) {
    let controller;
    if (typeof prom === 'function') {
        controller = new AbortController();
        try {
            prom = Promise.resolve(prom(controller.signal));
        } catch (err) {
            prom = Promise.reject(err);
        }
    }

    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            let err = new Error('Resolving requested resource timed out');
            if (source) {
                err._source = source;
            }
            if (controller) {
                controller.abort(err);
            }
            reject(err);
        }, timeout).unref();

        prom.then(resolve)
            .catch(reject)
            .finally(() => clearTimeout(timer));
    });
}

/**
 * The race of the five resolvers that run when the MX table has no answer. The first to come back
 * with something wins. A resolver that answers but names no host counts as a loss, not a win:
 * several of them parse a response that turned out to describe nothing, and resolving on that
 * would beat a slower resolver that had the real answer.
 *
 * @returns {Promise<Object>} The first result that names a server
 * @throws {Error} Marked `_is_last` once every resolver has lost
 */
function raceResolvers(email, ctx, credentials, timeout) {
    const resolvers = {
        srv: resolveUsingSRV,
        'well-known': resolveUsingWellKnown,
        autoconfig: resolveUsingAutoconfig,
        mozilla: resolveUsingMozillaDirectory,
        autodiscover: (email, ctx) => resolveUsingAutodiscovery(email, ctx, credentials)
    };
    const promises = Object.entries(resolvers).map(([source, resolve]) => timedFunction(signal => resolve(email, ctx(signal)), timeout, source));

    return new Promise((resolve, reject) => {
        let runCount = 0;
        const settle = err => {
            if (++runCount === promises.length) {
                err = err || new Error('Nothing found');
                err._is_last = true;
                reject(err);
            }
        };

        for (let prom of promises) {
            prom.then(res => {
                if (!hasResolvedHost(res)) {
                    return settle();
                }
                runCount++;
                resolve(res);
            }).catch(settle);
        }
    });
}

/**
 * Runs the resolvers: the MX one first, then the other five racing under their own time budget,
 * and when none of them names a server, the fallback stage (resolveUsingFallbacks()) under a
 * budget of its own. What that stage decides on is gathered while the race runs, so a domain
 * that publishes nothing does not wait for its DNS twice.
 *
 * @param {string} email - Address to look up
 * @param {Object} gt - gettext instance
 * @param {Object} [credentials] - `{ user, pass }`, see autodetectImapSettings()
 * @param {Object} [io] - `{ dns, fetchResource, probe, mailProxyUrl, timeout }` stand-ins for tests; production passes none
 * @returns {Promise<Object>} The first result that names a server
 */
async function resolver(email, gt, credentials, io) {
    io = io || {};
    const timeout = io.timeout || RESOLV_TIMEOUT;

    let authRequired = false;
    const onAuthRequired = () => {
        authRequired = true;
    };

    // Each resolver gets its own signal, aborted by its own timer
    const ctx = signal => withIo({ dns: io.dns, fetchResource: io.fetchResource, probe: io.probe, mailProxyUrl: io.mailProxyUrl, onAuthRequired, signal });

    let exchange;
    try {
        // prefer MX based resolver
        let res = await timedFunction(signal => resolveUsingMX(email, ctx(signal), gt), timeout, 'mx');
        return res;
    } catch (err) {
        if (err.exchange) {
            exchange = err.exchange;
        }
        // nothing useful found
    }

    // Only DNS reads and the directory requests, cancelled when the race wins
    const factsAbort = new AbortController();
    const facts = timedFunction(signal => gatherFallbackFacts(email, exchange, ctx(AbortSignal.any([signal, factsAbort.signal]))), timeout, 'fallback').catch(
        () => null
    );

    let res;
    try {
        res = await raceResolvers(email, ctx, credentials, timeout);
    } catch (err) {
        const known = await facts;
        if (!known) {
            throw err;
        }
        // The race's own failure is the one callers already know how to read
        return await timedFunction(signal => resolveUsingFallbacks(email, known, ctx(signal), gt, authRequired), timeout, 'fallback').catch(() => {
            throw err;
        });
    }
    factsAbort.abort();

    return withHints(res, email, exchange, gt);
}

/**
 * Discovers the IMAP and SMTP settings for an email address.
 *
 * @param {string} email - Address to look up
 * @param {Object} gt - gettext instance, for the app-password hints
 * @param {Object} [credentials] - `{ user, pass }` for the mailbox. Only used to answer an
 *   autodiscovery endpoint that refuses to respond anonymously, which is how hosted Exchange
 *   behaves; every other resolver is unauthenticated. The callers that hold a password pass it:
 *   the hosted setup form, and `POST /v1/autoconfig` for an integrator running its own form.
 *   `GET /v1/autoconfig` takes the address in a query string, where a password must never go, so
 *   it stays anonymous and an Exchange domain stays unresolvable there - use the POST instead.
 * @returns {Promise<Object>} `{ imap, smtp, _source }`, plus `appPassword` and the OAuth2 `provider`
 *   hint (see getProviderHint()) where they apply
 */
async function autodetectImapSettings(email, gt, credentials) {
    return await resolver(email, gt, credentials);
}

module.exports.autodetectImapSettings = autodetectImapSettings;

// Exposed for unit testing of the pure parsing/matching helpers. These have no
// network side effects, so they can be exercised directly without mocking DNS or HTTP.
module.exports.processAutoconfigFile = processAutoconfigFile;
module.exports.processAutodiscoverResponse = processAutodiscoverResponse;
module.exports.processAutodiscoverSoapResponse = processAutodiscoverSoapResponse;
module.exports.buildAutodiscoverRequest = buildAutodiscoverRequest;
module.exports.buildAutodiscoverSoapRequest = buildAutodiscoverSoapRequest;
module.exports.hasResolvedHost = hasResolvedHost;
module.exports.getAppPassword = getAppPassword;
module.exports.getProviderHint = getProviderHint;
module.exports.isConsumerMailbox = isConsumerMailbox;
module.exports.resolveAppPassword = resolveAppPassword;
module.exports.escapeXml = escapeXml;

// Exposed so the request sequence (anonymous first, credentials only once the server has asked for
// them, both endpoints in parallel) can be tested against an injected fetch rather than a live
// Exchange server. Production callers pass no fetch and get the egress-policed one.
module.exports.runAutodiscovery = runAutodiscovery;

// Exposed so the orchestration (the resolver race, the time budget and its abort, the body cap, the
// SRV fallbacks) can be tested against stand-in DNS and fetch
module.exports.resolver = resolver;
module.exports.exchangeParents = exchangeParents;
module.exports.probeCandidates = probeCandidates;
module.exports.MAX_PROBE_CANDIDATES = MAX_PROBE_CANDIDATES;
module.exports.resolveUsingSRV = resolveUsingSRV;
module.exports.timedFunction = timedFunction;
module.exports.MAX_AUTODISCOVERY_BODY = MAX_AUTODISCOVERY_BODY;

// Exposed so the two steps of Microsoft's sequence that used to be missing can be tested on their
// own: the plain-http GET whose redirect names the real endpoint, and the in-response redirect
module.exports.autodiscoverRedirectOrigin = autodiscoverRedirectOrigin;
module.exports.poxRedirectUrl = poxRedirectUrl;
module.exports.resolveUsingAutodiscovery = resolveUsingAutodiscovery;
module.exports.MAX_AUTODISCOVER_REDIRECTS = MAX_AUTODISCOVER_REDIRECTS;
