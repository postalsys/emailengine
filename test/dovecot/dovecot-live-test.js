'use strict';

// Live IMAP tests against a real IMAP4rev2 server - Dovecot 2.4+ in Docker -
// instead of protocol mocks, mirroring the ImapFlow rev2 live suite. Exercises
// the full EmailEngine stack (REST API -> account -> IMAP worker -> ImapFlow)
// against a server with IMAP4rev2, UTF8=ACCEPT, ESEARCH, MOVE and BINARY
// active. See README.md in this directory for coverage notes; not part of
// `npm test` - run with `npm run test:dovecot` (requires Docker; the runner
// script boots the container and the test server).

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');
const testConfig = require('../integration/test-config');
const { ACCESS_TOKEN, waitForCondition } = require('../integration/helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

const DOVECOT_PORT = Number(process.env.EENGINE_DOVECOT_PORT) || 31143;

// every byte value a few times over - a base64 or line-ending corruption
// anywhere in the fetch pipeline cannot go unnoticed
const BLOB = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 256));

const TEXT_CONTENT = 'Tere tulemast! Õäöü õnnelik unicode \u{1F643}';
const HTML_CONTENT = '<b>Tere tulemast! Õäöü õnnelik unicode \u{1F643}</b>';

async function createDovecotAccount(account, imapExtras) {
    await server
        .post(`/v1/account`)
        .send({
            account,
            name: `Dovecot live test (${account})`,
            email: `${account}@example.com`,
            // store the IMAP protocol log so the tests can assert what actually
            // went over the wire
            logs: true,
            imap: Object.assign(
                {
                    host: '127.0.0.1',
                    port: DOVECOT_PORT,
                    secure: false,
                    // the Dovecot test container uses a static passdb: any user
                    // authenticates with the shared password and gets its own
                    // empty mail home, so accounts need no server-side setup
                    auth: { user: account, pass: 'pass' },
                    resyncDelay: 3600
                },
                imapExtras
            )
        })
        .expect(200);

    return waitForCondition(
        async () => {
            const response = await server.get(`/v1/account/${account}`).expect(200);
            return response.body.state === 'connected' ? response.body : false;
        },
        { timeout: testConfig.CONNECTION_TIMEOUT, message: `Account ${account} did not connect` }
    );
}

// Parse the NDJSON account protocol log (ImapFlow emitLogs entries; raw client
// lines have src 'c', server lines src 's')
async function fetchWireLog(account) {
    const response = await server.get(`/v1/logs/${account}`).expect(200);
    return response.text
        .split(/\n/)
        .filter(line => line.trim())
        .map(line => {
            try {
                return JSON.parse(line);
            } catch (err) {
                return {};
            }
        });
}

const clientCommandLines = (log, command) =>
    log.filter(entry => entry.src === 'c' && typeof entry.msg === 'string' && new RegExp(`^\\S+ ${command}\\b`, 'i').test(entry.msg));

const serverLines = (log, re) => log.filter(entry => entry.src === 's' && typeof entry.msg === 'string' && re.test(entry.msg));

async function uploadAndVerifyMessage(account) {
    const token = crypto.randomBytes(8).toString('hex');
    const subject = `Dovecot live test ${token}`;

    const uploadResponse = await server
        .post(`/v1/account/${account}/message`)
        .send({
            path: 'INBOX',
            from: { name: 'Test Sender', address: 'sender@example.com' },
            to: [{ name: 'Test Recipient', address: `${account}@example.com` }],
            subject,
            text: TEXT_CONTENT,
            html: HTML_CONTENT,
            messageId: `<${token}@example.com>`,
            attachments: [
                {
                    filename: 'blob.bin',
                    content: BLOB.toString('base64'),
                    contentType: 'application/octet-stream',
                    encoding: 'base64'
                }
            ]
        })
        .expect(200);

    assert.ok(uploadResponse.body.id, 'upload must return a message id');

    const messageResponse = await server.get(`/v1/account/${account}/message/${uploadResponse.body.id}?textType=*`).expect(200);
    assert.equal(messageResponse.body.subject, subject);
    assert.equal(messageResponse.body.text.plain.trim(), TEXT_CONTENT, 'plain text content must survive the round-trip byte for byte');
    assert.equal(messageResponse.body.text.html.trim(), HTML_CONTENT, 'html content must survive the round-trip byte for byte');
    assert.equal(messageResponse.body.attachments.length, 1);
    assert.equal(messageResponse.body.attachments[0].filename, 'blob.bin');

    // the attachment download decodes the transfer encoding server- or client-side
    // depending on the fetch mechanism - either way the bytes must match exactly
    const attachmentResponse = await server.get(`/v1/account/${account}/attachment/${messageResponse.body.attachments[0].id}`).expect(200);
    assert.ok(Buffer.isBuffer(attachmentResponse._body), 'attachment response must be binary');
    assert.ok(attachmentResponse._body.equals(BLOB), 'attachment content must survive the round-trip byte for byte');

    return { id: uploadResponse.body.id, subject, token };
}

test('IMAP4rev2 account against live Dovecot', async t => {
    const account = `ee-rev2-${crypto.randomBytes(4).toString('hex')}`;

    t.after(async () => {
        await server.delete(`/v1/account/${account}`);
    });

    await createDovecotAccount(account, {});

    await t.test('connects with IMAP4rev2 enabled on the wire', async () => {
        const log = await fetchWireLog(account);

        const enableLines = clientCommandLines(log, 'ENABLE');
        assert.ok(enableLines.length, 'client must send an ENABLE command');
        assert.ok(
            enableLines.some(entry => /\bIMAP4REV2\b/i.test(entry.msg)),
            `ENABLE must request IMAP4rev2 (sent: ${JSON.stringify(enableLines.map(entry => entry.msg))})`
        );
        assert.ok(serverLines(log, /^\* ENABLED\b.*\bIMAP4REV2\b/i).length, 'server must confirm IMAP4rev2 with an untagged ENABLED');

        // IMAP4rev2 removed LSUB; the subscription state must come from LIST
        assert.equal(clientCommandLines(log, 'LSUB').length, 0, 'client must not use LSUB against an IMAP4rev2 server');

        // the suite must run against a BINARY-capable server, so the fetch path
        // is covered by the content assertions should EmailEngine ever opt into
        // ImapFlow's FETCH BINARY (download() currently never passes binary:true)
        assert.ok(serverLines(log, /\bBINARY\b/).length, 'server must advertise the BINARY extension');
    });

    await t.test('lists special-use mailboxes', async () => {
        const response = await server.get(`/v1/account/${account}/mailboxes`).expect(200);
        const specialUse = response.body.mailboxes.map(mailbox => mailbox.specialUse).filter(Boolean);
        for (const flag of ['\\Inbox', '\\Sent', '\\Drafts', '\\Junk', '\\Trash']) {
            assert.ok(specialUse.includes(flag), `mailbox listing must include a ${flag} mailbox (got ${JSON.stringify(specialUse)})`);
        }
    });

    let message;

    await t.test('uploads a message and reads back byte-exact content', async () => {
        message = await uploadAndVerifyMessage(account);
    });

    await t.test('finds the message via search (ESEARCH response shape)', async () => {
        const response = await server
            .post(`/v1/account/${account}/search?path=INBOX`)
            .send({ search: { subject: message.token } })
            .expect(200);
        assert.equal(response.body.total, 1);
        assert.equal(response.body.messages[0].subject, message.subject);
    });

    await t.test('updates flags, moves to Trash (COPYUID), deletes', async () => {
        const flagResponse = await server
            .put(`/v1/account/${account}/message/${message.id}`)
            .send({ flags: { add: ['\\Seen'] } })
            .expect(200);
        assert.ok(flagResponse.body.flags.add);

        // MOVE against rev2 Dovecot reports the target UID via the COPYUID
        // response code, which EmailEngine surfaces as the new message location
        const moveResponse = await server.put(`/v1/account/${account}/message/${message.id}/move`).send({ path: 'Trash' }).expect(200);
        assert.equal(moveResponse.body.path, 'Trash');
        assert.ok(moveResponse.body.id, 'move must return the message id in the target mailbox');

        await server.delete(`/v1/account/${account}/message/${moveResponse.body.id}`).expect(200);
    });
});

test('disableIMAP4rev2 account against live Dovecot', async t => {
    const account = `ee-rev1-${crypto.randomBytes(4).toString('hex')}`;

    t.after(async () => {
        await server.delete(`/v1/account/${account}`);
    });

    await createDovecotAccount(account, { disableIMAP4rev2: true });

    await t.test('keeps the connection on IMAP4rev1', async () => {
        const log = await fetchWireLog(account);

        const enableLines = clientCommandLines(log, 'ENABLE');
        assert.ok(enableLines.length, 'client must still send an ENABLE command for the other extensions');
        for (const entry of enableLines) {
            assert.ok(!/\bIMAP4REV2\b/i.test(entry.msg), `ENABLE must not request IMAP4rev2 (sent: ${JSON.stringify(entry.msg)})`);
        }
        assert.equal(serverLines(log, /^\* ENABLED\b.*\bIMAP4REV2\b/i).length, 0, 'server must not report IMAP4rev2 as enabled');
    });

    await t.test('uploads a message and reads back byte-exact content over rev1', async () => {
        await uploadAndVerifyMessage(account);
    });
});
