'use strict';

const punycode = require('punycode/');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const { parseString: parseXmlCb } = require('xml2js');
const util = require('util');
const packageData = require('../package.json');
const parseXml = util.promisify(parseXmlCb);

let RESOLV_TIMEOUT = 5 * 1000;

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

    let res = await fetch(`https://autoconfig.thunderbird.net/v1.1/${domain}`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        }
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

    let res = await fetch(`http://autoconfig.${encodeURIComponent(domain)}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(email)}`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        }
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

    let res = await fetch(`http://${encodeURIComponent(domain)}/.well-known/autoconfig/mail/config-v1.1.xml`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        }
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

    // look for some well known MX servers
    if (/\baspmx\.l\.google\.com$/i.test(exchange)) {
        return await resolveUsingSRV(email, 'gmail.com', 'mx');
    }

    if (/\bmx\.yandex\.net$/i.test(exchange)) {
        return await resolveUsingAutoconfig(email, 'yandex.ru', 'mx');
    }

    if (/\bzonemx\.eu$/i.test(exchange)) {
        return await resolveUsingAutoconfig(email, 'zone.ee', 'mx');
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

    throw new Error('Nothing found');
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
    console.log('DISCOVERY URL', discoveryUrl);

    let res = await fetch(discoveryUrl, {
        method: 'post',
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
            'Content-type': 'application/xml'
        },
        body
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

                let getStructureFromObject = obj => {
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
        let err = new Error('Resolving requested resource timed out');
        if (source) {
            err._source = source;
        }
        setTimeout(() => reject(err), timeout).unref();
        prom.then(resolve).catch(reject);
    });
}

function resolve(email) {
    return new Promise((resolve, reject) => {
        let promises = [
            timedFunction(resolveUsingSRV(email), RESOLV_TIMEOUT, 'srv'),
            timedFunction(resolveUsingWellKnown(email), RESOLV_TIMEOUT, 'well-known'),
            timedFunction(resolveUsingAutoconfig(email), RESOLV_TIMEOUT, 'autoconfig'),
            timedFunction(resolveUsingMozillaDirectory(email), RESOLV_TIMEOUT, 'mozilla'),
            timedFunction(resolveUsingMX(email), RESOLV_TIMEOUT, 'mx'),
            timedFunction(resolveUsingAutodiscovery(email), RESOLV_TIMEOUT, 'autodiscover')
        ];

        let runCount = 0;
        for (let prom of promises) {
            prom.then(res => {
                runCount++;
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
