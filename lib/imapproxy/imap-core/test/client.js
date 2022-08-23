/* eslint no-console:0 */

'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const config = require('wild-config');
const { ImapFlow } = require('imapflow');

const client = new ImapFlow({
    host: '127.0.0.1',
    port: config.imap.port,
    secure: config.imap.secure,
    auth: {
        user: 'testuser',
        pass: 'secretpass'
    },
    tls: {
        rejectUnauthorized: false
    },
    clientInfo: {
        name: 'My Client',
        version: '0.1'
    }
});

client.on('error', err => {
    console.log(err);
    process.exit(1);
});

const raw = Buffer.from('from: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nzzzz\r\n');

client
    .connect()
    .then(() => client.append('INBOX', raw))
    .then(() => client.mailboxOpen('INBOX'))
    .then(mailbox => client.fetchOne(mailbox.exists, { bodyStructure: true, source: true }))
    .then(data => {
        console.log('<<<%s>>>', data.source.toString());
        return process.exit(0);
    })
    .catch(err => {
        console.log(err);
        process.exit(1);
    });
