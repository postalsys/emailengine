'use strict';

// Any instance answers for any account. A request that reaches an instance which does not serve
// the account is run on the one that does, and the answer is the same as if it had been sent there
// directly: status, body, headers that matter, downloaded bytes.

const test = require('node:test');
const assert = require('node:assert').strict;
const { startScenario, waitUntil, sleep } = require('./helpers');
const { startCaptureSmtp } = require('../helpers/capture-smtp');

const ATTACHMENT = Buffer.from(Array.from({ length: 300 * 1024 }, (_, i) => i % 251));

function messageWithAttachment(subject) {
    const boundary = 'b-fleet-attachment';
    return [
        'From: Sender <sender@example.com>',
        'To: Recipient <recipient@example.com>',
        `Subject: ${subject}`,
        `Message-ID: <${Date.now()}.attachment@farm.test>`,
        `Date: ${new Date().toUTCString()}`,
        'MIME-Version: 1.0',
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=utf-8',
        '',
        'The body text',
        `--${boundary}`,
        'Content-Type: application/octet-stream; name="blob.bin"',
        'Content-Disposition: attachment; filename="blob.bin"',
        'Content-Transfer-Encoding: base64',
        '',
        ATTACHMENT.toString('base64').replace(/.{76}/g, '$&\r\n'),
        `--${boundary}--`,
        ''
    ].join('\r\n');
}

test('requests through the instance that does not serve the account', async t => {
    const capture = await startCaptureSmtp();
    const scenario = await startScenario({ instances: 2, accounts: 6, smtpPort: capture.port });
    t.after(async () => {
        await scenario.stop();
        await capture.close();
    });
    const [ee0, ee1] = scenario.fleet.instances;

    await scenario.waitConnected();
    const owners = await scenario.owners();
    const account = scenario.accounts.find(candidate => owners.get(candidate) === ee1.id);
    assert.ok(account, 'ee-1 owns something');
    const owner = ee1;
    const other = ee0;

    // Both ask the same question; the answers must match
    const both = async (method, path, body, opts) => {
        const direct = await owner.request(method, path, body, opts);
        const forwarded = await other.request(method, path, body, opts);
        return { direct, forwarded };
    };
    const same = async (method, path, body, opts) => {
        const { direct, forwarded } = await both(method, path, body, opts);
        assert.equal(forwarded.status, direct.status, `${method} ${path}: ${JSON.stringify(forwarded.body).slice(0, 300)}`);
        assert.deepEqual(forwarded.body, direct.body, `${method} ${path}`);
        return direct;
    };

    scenario.farm.inject(account, { raw: messageWithAttachment('Forwarding attachment') });
    await waitUntil(
        async () => {
            const res = await other.request('GET', `/v1/account/${account}/messages?path=INBOX`);
            return res.status === 200 && res.body.messages && res.body.messages.length === 1;
        },
        { timeout: 60000, label: 'the message to be listed' }
    );

    let message;

    await t.test('reads', async () => {
        await same('GET', `/v1/account/${account}`);
        await same('GET', `/v1/account/${account}/mailboxes`);
        const listing = await same('GET', `/v1/account/${account}/messages?path=INBOX`);
        message = listing.body.messages[0];
        await same('GET', `/v1/account/${account}/message/${message.id}`);
        await same('GET', `/v1/account/${account}/message/${message.id}?textType=*`);
        await same('GET', `/v1/account/${account}/text/${message.text.id}?textType=*`);
        await same('POST', `/v1/account/${account}/search?path=INBOX`, { search: { subject: 'Forwarding' } });
    });

    await t.test('downloads stream through byte for byte', async () => {
        const attachmentId = message.attachments[0].id;
        const { direct, forwarded } = await both('GET', `/v1/account/${account}/attachment/${attachmentId}`, null, { raw: true });
        assert.equal(forwarded.status, 200);
        assert.deepEqual(forwarded.body, ATTACHMENT);
        assert.deepEqual(forwarded.body, direct.body);
        for (const header of ['content-type', 'content-disposition']) {
            assert.equal(forwarded.headers[header], direct.headers[header], header);
        }

        const source = await both('GET', `/v1/account/${account}/message/${message.id}/source`, null, { raw: true });
        assert.equal(source.forwarded.status, 200);
        assert.deepEqual(source.forwarded.body, source.direct.body);
    });

    await t.test('an unknown message is the same 404', async () => {
        const res = await same('GET', `/v1/account/${account}/message/AAAAAQAAAZk`);
        assert.equal(res.status, 404);
    });

    await t.test('changes made through the other instance take effect', async () => {
        let res = await other.request('PUT', `/v1/account/${account}/message/${message.id}`, { flags: { add: ['\\Flagged'] } });
        assert.equal(res.status, 200, JSON.stringify(res.body));
        res = await owner.request('GET', `/v1/account/${account}/message/${message.id}`);
        assert.ok(res.body.flags.includes('\\Flagged'));

        res = await other.request('POST', `/v1/account/${account}/mailbox`, { path: ['Forwarded'] });
        assert.equal(res.status, 200, JSON.stringify(res.body));

        res = await other.request('PUT', `/v1/account/${account}/message/${message.id}/move`, { path: 'Forwarded' });
        assert.equal(res.status, 200, JSON.stringify(res.body));
        const moved = res.body.id;

        res = await other.request('POST', `/v1/account/${account}/message`, {
            path: 'Forwarded',
            from: { address: 'uploader@example.com' },
            to: [{ address: 'recipient@example.com' }],
            subject: 'Uploaded through the other instance',
            text: 'Uploaded'
        });
        assert.equal(res.status, 200, JSON.stringify(res.body));

        await waitUntil(
            async () => {
                const listing = await owner.request('GET', `/v1/account/${account}/messages?path=Forwarded`);
                return listing.status === 200 && listing.body.messages.length === 2;
            },
            { timeout: 30000, label: 'the moved and the uploaded message' }
        );

        res = await other.request('DELETE', `/v1/account/${account}/message/${moved}?force=true`);
        assert.equal(res.status, 200, JSON.stringify(res.body));
    });

    await t.test('a message submitted through the other instance is delivered through the account', async () => {
        const res = await other.request('POST', `/v1/account/${account}/submit`, {
            from: { address: `${account}@example.com` },
            to: [{ address: 'recipient@example.com' }],
            subject: 'Submitted through the other instance',
            text: 'Hello'
        });
        assert.equal(res.status, 200, JSON.stringify(res.body));
        await waitUntil(() => capture.received.find(entry => entry.raw.includes('Submitted through the other instance')), {
            timeout: 60000,
            label: 'the submitted message at the capture server'
        });
    });

    await t.test('fire-and-forget commands reach the owner', async () => {
        const before = owner.logEntries('Account sync requested').length;
        const res = await other.request('PUT', `/v1/account/${account}/sync`, { sync: true });
        assert.equal(res.status, 200, JSON.stringify(res.body));
        await waitUntil(() => owner.logEntries('Account sync requested').filter(entry => entry.account === account).length > before, {
            timeout: 15000,
            label: 'the sync request on the owner'
        });
    });

    await t.test('an account deleted through the other instance is closed on its owner', async () => {
        assert.ok(scenario.farm.sessionsFor(account).length > 0);
        const res = await other.request('DELETE', `/v1/account/${account}`);
        assert.equal(res.status, 200, JSON.stringify(res.body));
        await waitUntil(() => scenario.farm.sessionsFor(account).length === 0, { timeout: 15000, label: 'the IMAP session to close' });
        assert.equal(await scenario.redis.exists(`cluster:own:${account}`), 0, 'the owner record goes with the account');
        await sleep(2000);
        assert.equal(scenario.farm.sessionsFor(account).length, 0, 'nobody connects it again');
    });
});
