'use strict';

const punycode = require('punycode.js');
const dns = require('dns').promises;
const { parseString: parseXmlCb } = require('xml2js');
const util = require('util');
const packageData = require('../package.json');
const parseXml = util.promisify((xml, cb) => {
    parseXmlCb(
        xml,
        {
            explicitArray: true,
            normalize: true,
            normalizeTags: true,
            xmlMode: true,
            strict: true
        },
        cb
    );
});

const { fetch: fetchCmd } = require('undici');
const { httpAgent } = require('./tools');

const RESOLV_TIMEOUT = 5 * 1000;

// use a function instead of const to prevent translations before locale is set
const getAppPasswords = gt => [
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
            warning: gt.gettext(
                'Microsoft has disabled password-based sign-ins (including app passwords) for Outlook.com, Hotmail.com, and Microsoft 365 email accounts. To continue, please use the "Sign in with Microsoft" button to securely connect your account.'
            ),
            provider: 'Microsoft',
            instructions: 'https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944'
        }
    },

    {
        trigger: {
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

async function processAutoconfigFile(email, domain, text, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();
    let user = email.split('@').shift().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }
    let json = await parseXml(text);

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

    if (incomingServer) {
        const firstHostname = incomingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname ? firstHostname.replace(/^%EMAILDOMAIN%$/, domain) : undefined;

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

    if (outgoingServer) {
        const firstHostname = outgoingServer.hostname.filter(entry => entry).shift();
        const processedHostname = firstHostname ? firstHostname.replace(/^%EMAILDOMAIN%$/, domain) : undefined;

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
        dispatcher: httpAgent.retry
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

    let res = await fetchCmd(`https://autoconfig.${encodeURIComponent(domain)}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(email)}`, {
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        },
        dispatcher: httpAgent.retry
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
        dispatcher: httpAgent.retry
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
    let srvList = await dns.resolveMx(domain);
    if (!srvList || !srvList.length) {
        throw new Error('No MX record found for domain');
    }

    let exchange;
    const firstItem = srvList.sort((a, b) => a.priority - b.priority).shift();

    if (firstItem && firstItem.exchange) {
        exchange = firstItem.exchange.trim().toLowerCase();
    }

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

async function resolveUsingAutodiscovery(email, domain, source) {
    domain = domain || email.split('@').pop().trim().toLowerCase();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        //ignore
    }

    let discoveryDomain = `autodiscover.${encodeURIComponent(domain)}`;
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
    <EMailAddress>${escapeXml(email)}</EMailAddress>
  </Request>
</Autodiscover>`;

    let discoveryUrl = `https://${discoveryDomain}/autodiscover/autodiscover.xml`;

    let res = await fetchCmd(discoveryUrl, {
        method: 'post',
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
            'Content-type': 'application/xml'
        },
        body,
        dispatcher: httpAgent.retry
    });

    if (!res.ok) {
        throw new Error('Invalid response');
    }

    let text = await res.text();

    let json = await parseXml(text);

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
                    // imap entry
                    let res = {};
                    if (entry.server && typeof entry.server === 'string') {
                        res.host = entry.server;
                    }
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

    resp = resp.filter(entry => entry.account);

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

async function resolver(email, gt) {
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
            timedFunction(resolveUsingAutodiscovery(email), RESOLV_TIMEOUT, 'autodiscover')
        ];

        let runCount = 0;
        for (let prom of promises) {
            prom.then(res => {
                runCount++;

                let appPassword = getAppPassword(email, exchange, gt);
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

async function autodetectImapSettings(email, gt) {
    return await resolver(email, gt);
}

module.exports.autodetectImapSettings = autodetectImapSettings;
