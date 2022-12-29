'use strict';

const libmime = require('libmime');
const addressparser = require('nodemailer/lib/addressparser');

const ARF_SINGLE = [
    'feedback-type',
    'user-agent',
    'version',
    'original-envelope-id',
    'original-mail-from',
    'abuse-type',
    'arrival-date',
    'received-date',
    'reporting-mta',
    'source-ip',
    'source',
    'subscription-link',
    'incidents'
];

const arfDetect = async messageInfo => {
    const report = {
        arf: {},
        headers: {}
    };

    let returnPath;

    for (let attachment of messageInfo.attachments) {
        switch (attachment.contentType.toLowerCase()) {
            case 'message/feedback-report': {
                // found a feedback report

                const contents = libmime.decodeHeaders((attachment.content || '').toString());

                // eslint-disable-next-line no-loop-func
                Object.keys(contents).forEach(key => {
                    let value = contents[key];

                    if (!key || !value) {
                        return;
                    }

                    if (ARF_SINGLE.includes(key)) {
                        value = Array.isArray(contents[key]) ? contents[key].join(',') : (contents[key] || '').toString();
                    } else if (!Array.isArray(value)) {
                        value = []
                            .concat(value || [])
                            .map(element => (element || '').toString().trim())
                            .filter(element => element);
                    }

                    if (!value || !value.length) {
                        return;
                    }

                    switch (key) {
                        case 'original-mail-from':
                            value = value.replace(/^[\s<]*|[>\s]*$/g, '');
                            break;

                        case 'arrival-date':
                        case 'received-date':
                            key = 'arrival-date';
                            value = new Date(value);
                            if (value.toString() === 'Invalid Date') {
                                return;
                            }
                            value = value.toISOString();
                            break;
                    }

                    report.arf[key] = value;
                });

                break;
            }

            case 'message/rfc822':
            case 'message/rfc822-headers': {
                let contents = (attachment.content || '').toString();
                const headerPos = contents.match(/\r?\n\r?\n/);

                if (headerPos) {
                    contents = contents.substr(0, headerPos.index);
                }

                const headers = libmime.decodeHeaders(contents);

                // Hotmail original recipient X-HmXmrOriginalRecipient
                const addresses = addressparser([].concat(headers['x-hmxmroriginalrecipient'] || []).join(', '))
                    .map(addr => addr.address)
                    .filter(addr => addr && !(report.arf['original-rcpt-to'] && report.arf['original-rcpt-to'].includes(addr)));

                report.arf['original-rcpt-to'] = [].concat(report.arf['original-rcpt-to'] || []).concat(addresses);

                if (headers['return-path']) {
                    returnPath = addressparser([].concat(headers['return-path'] || []).join(', '))
                        .map(addr => addr.address)
                        .filter(addr => addr)
                        .pop();
                }

                let messageId = [].concat(headers['message-id'] || []).pop();
                if (messageId && !report.headers['message-id']) {
                    report.headers['message-id'] = messageId;
                }

                let sourceIp = [].concat(headers['x-sender-ip'] || []).pop();
                if (sourceIp && !report['source-ip']) {
                    report.arf['source-ip'] = sourceIp;
                }

                let originalArrivalTime = [].concat(headers['x-ms-exchange-crosstenant-originalarrivaltime'] || []).pop();
                if (originalArrivalTime && !report.arf['arrival-date']) {
                    let originalArrivalTimeDate = new Date(originalArrivalTime);
                    if (originalArrivalTimeDate && originalArrivalTimeDate.toString() !== 'Invalid Date') {
                        report.arf['arrival-date'] = originalArrivalTimeDate.toISOString();
                    }
                }

                for (let headerKey of ['from', 'to', 'cc', 'bcc', 'subject', 'date']) {
                    let headerLines = []
                        .concat(headers[headerKey] || [])
                        .map(val => val && typeof val === 'string' && val.trim())
                        .filter(val => val);
                    if (!headerLines.length) {
                        continue;
                    }

                    switch (headerKey) {
                        case 'date':
                            {
                                let value = new Date(headerLines.pop());
                                if (value.toString() !== 'Invalid Date') {
                                    report.headers[headerKey] = report.headers[headerKey] || value.toISOString();
                                }
                            }
                            break;

                        case 'subject':
                            {
                                let value = libmime.decodeWords(headerLines.pop()).trim();
                                if (value) {
                                    report.headers[headerKey] = report.headers[headerKey] || value;
                                }
                            }
                            break;

                        case 'from':
                        case 'to':
                        case 'cc':
                        case 'bcc':
                            {
                                let value = headerLines
                                    .flatMap(addressparser)
                                    .map(entry => entry.address)
                                    .filter(addr => addr);

                                if (value && value.length) {
                                    if (headerKey === 'from') {
                                        value = value.pop();
                                    }
                                    report.headers[headerKey] = report.headers[headerKey] || value;
                                }
                            }
                            break;
                    }
                }

                break;
            }

            default:
                break;
        }
    }

    let reportDefauls = {
        arf: {},
        headers: {}
    };

    if (!report.source && messageInfo.from && messageInfo.from.address === 'staff@hotmail.com') {
        reportDefauls.arf.source = 'Hotmail';
        reportDefauls.arf['feedback-type'] = reportDefauls.arf['feedback-type'] || 'abuse';
        reportDefauls.arf['abuse-type'] = reportDefauls.arf['abuse-type'] || 'complaint';
        if (returnPath) {
            reportDefauls.arf['original-mail-from'] = returnPath;
        }
    }

    for (let key of Object.keys(reportDefauls)) {
        report[key] = Object.assign(reportDefauls[key], report[key]);
    }

    return report;
};

module.exports = { arfDetect };
