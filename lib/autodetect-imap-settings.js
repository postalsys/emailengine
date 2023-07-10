'use strict';

const punycode = require('punycode/');
const dns = require('dns').promises;
const { parseString: parseXmlCb } = require('xml2js');
const util = require('util');
const packageData = require('../package.json');
const parseXml = util.promisify(parseXmlCb);

const { FETCH_TIMEOUT } = require('./consts');
const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const RESOLV_TIMEOUT = 5 * 1000;

const APP_PASSWORDS = [
    {
        trigger: {
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
            exchange: /\.outlook\.com$/i
        },
        value: {
            required: true,
            provider: 'Microsoft',
            instructions:
                'https://support.microsoft.com/en-us/account-billing/using-app-passwords-with-apps-that-don-t-support-two-step-verification-5896ed9b-4263-e681-128a-a6f2979a7944'
        }
    }
];

function getAppPassword(email, exchange) {
    let domain = email.split('@').pop().trim().toLowerCase();

    for (let appPassword of APP_PASSWORDS) {
        if (appPassword.trigger.domains && appPassword.trigger.domains.includes(domain)) {
            return appPassword.value;
        }
        if (exchange && appPassword.trigger.exchange && appPassword.trigger.exchange.test(exchange)) {
            return appPassword.value;
        }
    }
    return false;
}

async function processAutoconfigFile(email, domain, text, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();
    let user = email.split('@').shift().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }
    let json = await parseXml(text);

    let emailProviders = json && json.clientConfig && Array.isArray(json.clientConfig.emailProvider) ? json.clientConfig.emailProvider : [];
    let incomingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.incomingServer) ? entry.incomingServer : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'imap')
        .shift();
    let outgoingServer = emailProviders
        .flatMap(entry => (entry && Array.isArray(entry.outgoingServer) ? entry.outgoingServer : []))
        .filter(entry => entry && entry.$ && entry.$.type === 'smtp')
        .shift();

    let imap = false;
    let smtp = false;

    if (incomingServer) {
        imap = {
            host: incomingServer.hostname.filter(entry => entry).shift(),
            port: Number(incomingServer.port.filter(entry => entry).shift()),
            secure: incomingServer.socketType.filter(entry => entry).shift() === 'SSL'
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

    if (outgoingServer) {
        smtp = {
            host: outgoingServer.hostname.filter(entry => entry).shift(),
            port: Number(outgoingServer.port.filter(entry => entry).shift()),
            secure: outgoingServer.socketType.filter(entry => entry).shift() === 'SSL'
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

async function resolveUsingMozillaDirectory(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let res = await fetchCmd(`https://autoconfig.thunderbird.net/v1.1/${domain}`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        },
        dispatcher: fetchAgent
    });

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

    let res = await fetchCmd(`http://autoconfig.${encodeURIComponent(domain)}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(email)}`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        },
        dispatcher: fetchAgent
    });

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

    let res = await fetchCmd(`http://${encodeURIComponent(domain)}/.well-known/autoconfig/mail/config-v1.1.xml`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        },
        dispatcher: fetchAgent
    });

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
        let srvList = await dns.resolveSrv(`_imap._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            imap = {
                host: record.name,
                port: record.port,
                secure: false
            };
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
                secure: false
            };
        }
    }

    return { smtp, imap, _source: source || 'srv' };
}

async function resolveUsingMX(email, domain) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    // do not catch potential error as there's nothing to do if we do not find the MX record
    let srvList = await dns.resolveMx(domain);
    if (!srvList || !srvList.length) {
        throw new Error('No MX record found for domain');
    }

    let exchange = srvList
        .sort((a, b) => a.priority - b.priority)
        .shift()
        .exchange.trim()
        .toLowerCase();

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

        if (/\bzonemx\.eu$/i.test(exchange)) {
            return await resolveUsingAutoconfig(email, 'zone.ee', 'mx');
        }

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

        let error = new Error('Nothing found');
        error.exchange = exchange;

        throw error;
    };

    let accountConfig = await resolveConfig();
    let appPassword = getAppPassword(email, exchange);

    return Object.assign({}, accountConfig, appPassword ? { appPassword } : {});
}

async function resolveUsingAutodiscovery(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let discoveryDomain = 'autodiscover.${encodeURIComponent(domain)}';
    try {
        let srvList = await dns.resolveSrv(`_autodiscover._tcp.${domain}`);
        let record = srvList.sort((a, b) => a.priority - b.priority).shift();
        if (record) {
            discoveryDomain = `${record.name}${record.port !== 443 ? `:${record.port}` : ''}`;
        }
    } catch (err) {
        //ignore
    }

    const body = `<?xml version="1.0" encoding="utf-8" ?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    <EMailAddress>${email}</EMailAddress>
  </Request>
</Autodiscover>'`;

    let discoveryUrl = `https://${discoveryDomain}/autodiscover/autodiscover.xml`;

    let res = await fetchCmd(discoveryUrl, {
        method: 'post',
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
            'Content-type': 'application/xml'
        },
        body,
        dispatcher: fetchAgent
    });

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    let text = await res.text();

    let json = await parseXml(text);

    let imap = false;
    let smtp = false;

    let resp = json && json.Autodiscover && Array.isArray(json.Autodiscover.Response) ? json.Autodiscover.Response : [];
    resp.forEach(responseRow => {
        if (!responseRow || !Array.isArray(responseRow.Account)) {
            return;
        }
        responseRow.Account.forEach(accountRow => {
            if (
                !accountRow ||
                !accountRow.AccountType ||
                !Array.isArray(accountRow.AccountType) ||
                !Array.isArray(accountRow.Protocol) ||
                !accountRow.AccountType.includes('email')
            ) {
                return;
            }

            accountRow.Protocol.forEach(protocolRow => {
                let entry = {};
                for (let key of ['Type', 'Server', 'LoginName', 'Port', 'SSL']) {
                    if (protocolRow && Array.isArray(protocolRow[key]) && protocolRow[key].length) {
                        entry[key] = protocolRow[key][0];
                    }
                }

                let getStructureFromObject = entry => {
                    // imap entry
                    let res = {};
                    if (entry.Server && typeof entry.Server === 'string') {
                        res.host = entry.Server;
                    }
                    if (entry.Port && (typeof entry.Port === 'string' || (typeof entry.Port === 'number' && !isNaN(entry.Port)))) {
                        res.port = Number(entry.Port);
                    }
                    if (entry.SSL && typeof entry.SSL === 'string') {
                        res.secure = entry.SSL === 'on';
                    }
                    if (entry.LoginName && typeof entry.LoginName === 'string') {
                        res.auth = { user: entry.LoginName };
                    }
                    return res;
                };

                if (/^IMAP$/i.test(entry.Type)) {
                    // imap entry
                    imap = getStructureFromObject(entry);
                }

                if (/^SMTP$/i.test(entry.Type)) {
                    // imap entry
                    smtp = getStructureFromObject(entry);
                }
            });
        });
    });

    resp = resp.filter(entry => entry.Account);

    return { imap, smtp, _source: source || 'autodiscover' };
}

async function timedFunction(prom, timeout, source) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            let err = new Error('Resolving requested resource timed out');
            if (source) {
                err._source = source;
            }
            reject(err);
        }, timeout).unref();
        prom.then(resolve).catch(reject);
    });
}

async function resolve(email) {
    let exchange;
    try {
        // prefer MX based resolver
        let res = await timedFunction(resolveUsingMX(email), RESOLV_TIMEOUT, 'mx');
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
            timedFunction(resolveUsingAutodiscovery(email), RESOLV_TIMEOUT, 'autodiscover')
        ];

        let runCount = 0;
        for (let prom of promises) {
            prom.then(res => {
                runCount++;

                let appPassword = getAppPassword(email, exchange);
                if (appPassword) {
                    res = Object.assign({}, res, { appPassword });
                }

                resolve(res);
            }).catch(err => {
                runCount++;
                if (runCount === promises.length) {
                    err._is_last = true;
                    reject(err);
                }
            });
        }
    });
}

async function autodetectImapSettings(email) {
    return await resolve(email);
}

module.exports.autodetectImapSettings = autodetectImapSettings;
