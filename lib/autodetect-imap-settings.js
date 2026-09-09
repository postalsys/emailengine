'use strict';

const punycode = require('punycode.js');
const dns = require('dns').promises;
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
const { httpAgent } = require('./tools');
const { fetchWithVettedRedirects } = require('./egress-fetch');
const { validateWebhookTarget } = require('./webhook-egress');

const RESOLV_TIMEOUT = 5 * 1000;

// Shorter cap for the app-password hint MX lookup: it runs on the hosted form's validation-error
// re-render and only produces a cosmetic label, so it must not stall the page for the full RESOLV_TIMEOUT.
const APP_PASSWORD_MX_TIMEOUT = 1500;

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

// use a function instead of const to prevent translations before locale is set
// The canonical consumer domains are listed alongside the exchange regexes so a plain domain match
// (getAppPassword with exchange=false) resolves the big providers without any MX lookup - each listed
// domain's MX points at the same entry the regex would select, so autodetect results do not change.
const getAppPasswords = gt => [
    {
        trigger: {
            domains: ['gmail.com', 'googlemail.com'],
            exchange: /\bl\.google\.com$/i
        },
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
            domains: ['outlook.com', 'hotmail.com', 'live.com'],
            exchange: /\.outlook\.com$/i
        },
        value: {
            required: true,
            warning: gt.gettext(
                'Microsoft has disabled password-based sign-ins (including app passwords) for Outlook.com, Hotmail.com, and Microsoft 365 email accounts. To continue, please use the "Sign in with Microsoft" button to securely connect your account.'
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

function getAppPassword(email, exchange, gt) {
    let domain = email.split('@').pop().trim().toLowerCase();

    for (let appPassword of getAppPasswords(gt)) {
        if (appPassword.trigger.domains && appPassword.trigger.domains.includes(domain)) {
            return appPassword.value;
        }
        if (exchange && appPassword.trigger.exchange && appPassword.trigger.exchange.test(exchange)) {
            return appPassword.value;
        }
    }
    return false;
}

// Resolve the lowest-priority MX exchange for a domain (lowercased). Throws if the domain has no MX
// record (callers decide whether that is fatal or just "no exchange-based match").
async function resolveExchange(domain) {
    let srvList = await dns.resolveMx(domain);
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

    let emailProviders = json && json.clientconfig && Array.isArray(json.clientconfig.emailprovider) ? json.clientconfig.emailprovider : [];
    let incomingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.incomingserver) ? entry.incomingserver : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'imap')
        .shift();
    let outgoingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.outgoingserver) ? entry.outgoingserver : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'smtp')
        .shift();

    let imap = false;
    let smtp = false;

    // A server element with an empty <hostname> describes no server at all. Building the entry
    // anyway produced an object that was truthy and named nothing, which every caller read as an
    // answer: the resolver race was won by it and the hosted setup form rendered empty fields.
    if (incomingServer && incomingServer.hostname.some(entry => entry)) {
        const firstHostname = incomingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname.replace(/^%EMAILDOMAIN%$/, domain);

        imap = {
            host: processedHostname,
            port: Number(incomingServer.port.filter(entry => entry).shift()),
            secure: incomingServer.sockettype.filter(entry => entry).shift() === 'SSL'
        };

        if (Array.isArray(incomingServer.username) && incomingServer.username.length) {
            imap.auth = {
                user: (incomingServer.username.filter(entry => entry).shift() || '')
                    .replace(/^%EMAILADDRESS%$/, email)
                    .replace(/^%EMAILLOCALPART%$/, user)
                    .replace(/^%EMAILDOMAIN%$/, domain)
            };
        }
    }

    if (outgoingServer && outgoingServer.hostname.some(entry => entry)) {
        const firstHostname = outgoingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname.replace(/^%EMAILDOMAIN%$/, domain);

        smtp = {
            host: processedHostname,
            port: Number(outgoingServer.port.filter(entry => entry).shift()),
            secure: outgoingServer.sockettype.filter(entry => entry).shift() === 'SSL'
        };

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

async function resolveUsingMozillaDirectory(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let res = await fetchAutodiscoveryResource(`https://autoconfig.thunderbird.net/v1.1/${domain}`);

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    let text = await res.text();

    return await processAutoconfigFile(email, domain, text, source || 'mozilla');
}

async function resolveUsingAutoconfig(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let res = await fetchAutodiscoveryResource(
        `https://autoconfig.${encodeURIComponent(domain)}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(email)}`
    );

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    let text = await res.text();

    return await processAutoconfigFile(email, domain, text, source || 'autoconfig');
}

async function resolveUsingWellKnown(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let res = await fetchAutodiscoveryResource(`http://${encodeURIComponent(domain)}/.well-known/autoconfig/mail/config-v1.1.xml`);

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    let text = await res.text();

    return await processAutoconfigFile(email, domain, text, source || 'well-known');
}

async function resolveUsingSRV(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let imap = false;
    let smtp = false;

    try {
        let srvList = await dns.resolveSrv(`_imaps._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            imap = {
                host: record.name,
                port: record.port,
                secure: true
            };
        }
    } catch (err) {
        //ignore
    }

    if (!imap) {
        try {
            let srvList = await dns.resolveSrv(`_imap._tcp.${domain}`);
            let record = srvList.sort((a, b) => a.priority - b.priority).shift();
            if (record) {
                imap = {
                    host: record.name,
                    port: record.port,
                    secure: false
                };
            }
        } catch (err) {
            //ignore
        }
    }

    try {
        let srvList = await dns.resolveSrv(`_submissions._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            smtp = {
                host: record.name,
                port: record.port,
                secure: true
            };
        }
    } catch (err) {
        //ignore
    }

    if (!smtp) {
        let srvList = await dns.resolveSrv(`_submission._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            smtp = {
                host: record.name,
                port: record.port,
                // Some providers invalidly use _submission instead of _submissions
                secure: record.port === 465
            };
        }
    }

    return { smtp, imap, _source: source || 'srv' };
}

async function resolveUsingMX(email, domain, gt) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    // do not catch potential error as there's nothing to do if we do not find the MX record
    let exchange = await resolveExchange(domain);

    let resolveConfig = async () => {
        // look for some well known MX servers
        if (/\bl\.google\.com$/i.test(exchange)) {
            return await resolveUsingSRV(email, 'gmail.com', 'mx');
        }

        if (/\bmx\.yandex\.net$/i.test(exchange)) {
            return await resolveUsingAutoconfig(email, 'yandex.ru', 'mx');
        }

        if (/^mx\d*\.zone\.eu$/i.test(exchange)) {
            // Zoho custom domain not in EU
            return {
                imap: {
                    host: 'mail.zone.ee',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.zone.ee',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        if (/\blarksuite\.com$/i.test(exchange)) {
            // Lark Mail / ByteDance
            return {
                imap: {
                    host: 'imap.larksuite.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.larksuite.com',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        if (/\bzonemx\.eu$/i.test(exchange)) {
            return await resolveUsingAutoconfig(email, 'zone.ee', 'mx');
        }

        // AWS WorkMail
        let awsMatch = exchange.match(/inbound-smtp\.([^.]+)\.amazonaws.com/);
        if (awsMatch) {
            let region = awsMatch[1].toLowerCase().trim();
            return {
                imap: {
                    host: `imap.mail.${region}.awsapps.com`,
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: `smtp.mail.${region}.awsapps.com`,
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // Zoho EU
        if (/^mx\d*\.zoho\.eu$/i.test(exchange)) {
            // Zoho custom domain in EU
            return {
                imap: {
                    host: 'imappro.zoho.eu',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtppro.zoho.eu',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // Zoho international
        if (/^mx\d*\.zoho\.com$/i.test(exchange)) {
            // Zoho custom domain not in EU
            return {
                imap: {
                    host: 'imappro.zoho.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtppro.zoho.com',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // MS365
        if (/\bprotection\.outlook\.com$/i.test(exchange)) {
            // outlook
            // as autodiscovery is currently (2021-11-17) closed use a fixed response
            return {
                imap: {
                    host: 'outlook.office365.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.office365.com',
                    port: 587,
                    secure: false
                },
                _source: 'mx'
            };
        }

        // Inbox.com
        if (exchange === 'mx.dka.mailcore.net') {
            return {
                imap: {
                    host: 'imap.dka.mailcore.net',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.dka.mailcore.net',
                    port: 587,
                    secure: false
                },
                _source: 'mx'
            };
        }

        if (exchange === 'ekiri.ee') {
            return {
                imap: {
                    host: `turvaline.ekiri.ee`,
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: `turvaline.ekiri.ee`,
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // Alibaba Mail
        if (/^mx\d*\.sg\.aliyun\.com$/i.test(exchange)) {
            // Naver.com
            return {
                imap: {
                    host: 'imap.sg.aliyun.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.sg.aliyun.com',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // ATT
        if (/mx-vip\d*\.prodigy\.net$/i.test(exchange)) {
            // ATT
            return {
                imap: {
                    host: 'imap.mail.att.net',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.mail.att.net',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        // Naver (kr)
        if (/^mx\d*\.naver\.com$/i.test(exchange)) {
            // Naver.com
            return {
                imap: {
                    host: 'imap.naver.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.naver.com',
                    port: 587,
                    secure: false
                },
                _source: 'mx'
            };
        }

        // QQ enterprise
        if (/^mxbiz\d*\.qq\.com$/i.test(exchange)) {
            // Naver.com
            return {
                imap: {
                    host: 'imap.exmail.qq.com',
                    port: 993,
                    secure: true
                },
                smtp: {
                    host: 'smtp.exmail.qq.com',
                    port: 465,
                    secure: true
                },
                _source: 'mx'
            };
        }

        let error = new Error('Nothing found');
        error.exchange = exchange;

        throw error;
    };

    let accountConfig = await resolveConfig();

    if (!hasResolvedHost(accountConfig)) {
        // The exchange matched, but the config it delegated to named no server: the Gmail branch
        // reads SRV records and the Yandex one an autoconfig file, and either can come back empty.
        // Reported as a miss rather than returned, so the racing resolvers get their turn - and
        // carrying the exchange, which is what the app-password hint is matched on.
        let error = new Error('Nothing found');
        error.exchange = exchange;
        throw error;
    }

    let appPassword = getAppPassword(email, exchange, gt);

    return Object.assign({}, accountConfig, appPassword ? { appPassword } : {});
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
function secureOriginOf(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:' ? parsed.origin : false;
    } catch (err) {
        return false;
    }
}

async function resolveAutodiscoveryHost(domain) {
    try {
        let srvList = await dns.resolveSrv(`_autodiscover._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            return `${record.name}${record.port !== 443 ? `:${record.port}` : ''}`;
        }
    } catch (err) {
        //ignore
    }

    return `autodiscover.${encodeURIComponent(domain)}`;
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
 * @param {Function} [fetchResource] - Fetch to use, `(url, opts) => Promise<Response>`
 * @returns {Promise<Object>} `{ imap, smtp, _source }`
 * @throws {Error} When no endpoint returned anything usable
 */
async function runAutodiscovery(baseUrl, email, credentials, fetchResource) {
    fetchResource = fetchResource || fetchAutodiscoveryResource;

    const poxBody = buildAutodiscoverRequest(email);
    const post = (origin, path, body, authorization) =>
        fetchResource(`${origin}${path}`, {
            method: 'post',
            headers: Object.assign({ 'Content-type': AUTODISCOVER_CONTENT_TYPE }, authorization ? { Authorization: authorization } : {}),
            body
        });

    // A server that answers without credentials is never asked for them
    let res = await post(baseUrl, '/autodiscover/autodiscover.xml', poxBody);
    if (res.ok) {
        let result = processAutodiscoverResponse(await res.text());
        if (hasResolvedHost(result)) {
            return result;
        }
        // It answered anonymously, just with nothing usable. It never asked for a password, so it
        // is not given one.
        throw new Error('Invalid response');
    }

    // Nothing here reads the body, and the retries below reuse this connection
    await res.text().catch(() => false);

    // Only a challenge that names Basic earns the password. A 404 from a wildcard-DNS parking host,
    // a 500, a CDN answering an unknown path, a server offering only NTLM - all answered without
    // asking for one, and Basic would be no use to the last of them anyway.
    if (res.status !== 401 || !/\bbasic\b/i.test(res.headers?.get('www-authenticate') || '')) {
        throw new Error('Invalid response');
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
            .then(async res => (res.ok ? processResponse(await res.text()) : false))
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

async function resolveUsingAutodiscovery(email, credentials) {
    let domain = email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let discoveryDomain = await resolveAutodiscoveryHost(domain);

    return await runAutodiscovery(`https://${discoveryDomain}`, email, credentials);
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
                for (let key of ['type', 'server', 'loginname', 'port', 'ssl']) {
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
                    if (entry.ssl && typeof entry.ssl === 'string') {
                        res.secure = entry.ssl === 'on';
                    }
                    if (entry.loginname && typeof entry.loginname === 'string') {
                        res.auth = { user: entry.loginname };
                    }
                    return res;
                };

                if (/^IMAP$/i.test(entry.type)) {
                    // imap entry
                    imap = getStructureFromObject(entry);
                }

                if (/^SMTP$/i.test(entry.type)) {
                    // imap entry
                    smtp = getStructureFromObject(entry);
                }
            });
        });
    });

    return { imap, smtp, _source: source || 'autodiscover' };
}

async function timedFunction(prom, timeout, source) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            let err = new Error('Resolving requested resource timed out');
            if (source) {
                err._source = source;
            }
            reject(err);
        }, timeout).unref();

        prom.then(resolve)
            .catch(reject)
            .finally(() => clearTimeout(timer));
    });
}

async function resolver(email, gt, credentials) {
    let exchange;
    try {
        // prefer MX based resolver
        let res = await timedFunction(resolveUsingMX(email, null, gt), RESOLV_TIMEOUT, 'mx');
        return res;
    } catch (err) {
        if (err.exchange) {
            exchange = err.exchange;
        }
        // nothing useful found
    }

    return new Promise((resolve, reject) => {
        let promises = [
            timedFunction(resolveUsingSRV(email), RESOLV_TIMEOUT, 'srv', exchange),
            timedFunction(resolveUsingWellKnown(email), RESOLV_TIMEOUT, 'well-known'),
            timedFunction(resolveUsingAutoconfig(email), RESOLV_TIMEOUT, 'autoconfig'),
            timedFunction(resolveUsingMozillaDirectory(email), RESOLV_TIMEOUT, 'mozilla'),
            timedFunction(resolveUsingAutodiscovery(email, credentials), RESOLV_TIMEOUT, 'autodiscover')
        ];

        // The first resolver to come back with something wins. A resolver that answers but names
        // neither a host counts as a loss, not a win: several of them parse a response that turned
        // out to describe nothing, and resolving on that would beat a slower resolver that had the
        // real answer.
        let runCount = 0;
        let settle = err => {
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

                let appPassword = getAppPassword(email, exchange, gt);
                if (appPassword) {
                    res = Object.assign({}, res, { appPassword });
                }

                resolve(res);
            }).catch(settle);
        }
    });
}

/**
 * Discovers the IMAP and SMTP settings for an email address.
 *
 * @param {string} email - Address to look up
 * @param {Object} gt - gettext instance, for the app-password hints
 * @param {Object} [credentials] - `{ user, pass }` for the mailbox. Only used to answer an
 *   autodiscovery endpoint that refuses to respond anonymously, which is how hosted Exchange
 *   behaves; every other resolver is unauthenticated. The hosted setup form is the one caller that
 *   holds a password, so it is the one that passes this. `GET /v1/autoconfig` takes the address in
 *   a query string and can never carry one, which is why an Exchange domain stays unresolvable
 *   there - deliberately, rather than for want of a credential-carrying endpoint.
 * @returns {Promise<Object>} `{ imap, smtp, _source }`, plus `appPassword` where one applies
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
module.exports.resolveAppPassword = resolveAppPassword;
module.exports.escapeXml = escapeXml;

// Exposed so the request sequence (anonymous first, credentials only once the server has asked for
// them, both endpoints in parallel) can be tested against an injected fetch rather than a live
// Exchange server. Production callers pass no fetch and get the egress-policed one.
module.exports.runAutodiscovery = runAutodiscovery;
