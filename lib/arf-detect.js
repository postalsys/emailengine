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
    const report = {};

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

                    report[key] = value;
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
                    .filter(addr => addr && !(report['original-rcpt-to'] && report['original-rcpt-to'].includes(addr)));

                report['original-rcpt-to'] = [].concat(report['original-rcpt-to'] || []).concat(addresses);

                let messageId = [].concat(headers['message-id'] || []).pop();
                if (messageId && !report['message-id']) {
                    report['message-id'] = messageId;
                }

                let sourceIp = [].concat(headers['x-sender-ip'] || []).pop();
                if (sourceIp && !report['source-ip']) {
                    report['source-ip'] = sourceIp;
                }

                let originalArrivalTime = [].concat(headers['x-ms-exchange-crosstenant-originalarrivaltime'] || []).pop();
                if (originalArrivalTime && !report['arrival-date']) {
                    let originalArrivalTimeDate = new Date(originalArrivalTime);
                    if (originalArrivalTimeDate && originalArrivalTimeDate.toString() !== 'Invalid Date') {
                        report['arrival-date'] = originalArrivalTimeDate.toISOString();
                    }
                }

                break;
            }

            default:
                break;
        }
    }

    let reportDefauls = {};

    if (!report.source && messageInfo.from && messageInfo.from.address === 'staff@hotmail.com') {
        reportDefauls.source = 'Hotmail';
        reportDefauls.feedbackType = reportDefauls.feedbackType || 'abuse';
        reportDefauls.abuseType = reportDefauls.abuseType || 'complaint';
    }

    return Object.assign(reportDefauls, report);
};

module.exports = { arfDetect };
