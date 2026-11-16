'use strict';

// The update the admin account edit form builds (lib/ui-routes/account-edit-form.js). The route
// itself is driven end to end in test/ui-routes-handlers-test.js; this covers the builders alone,
// including that the stored account they start from is left as it was.

const test = require('node:test');
const assert = require('node:assert').strict;

const { buildAccountEditUpdates, buildBaseUpdates, buildImapUpdates, buildSmtpUpdates } = require('../lib/ui-routes/account-edit-form');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// The schema chain the builders share with the route pulls in lib/db
registerRedisTeardown(redis);

const storedImap = () => ({
    host: 'imap.example.com',
    port: 993,
    secure: true,
    disabled: false,
    auth: { user: 'iu', pass: 'ip' },
    tls: { rejectUnauthorized: false },
    sentMailPath: 'Sent'
});

const storedSmtp = () => ({ host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'su', pass: 'sp' } });

// The validated payload of an untouched form for the stored objects above
const untouchedImap = {
    imap: true,
    imap_host: 'imap.example.com',
    imap_port: 993,
    imap_disabled: false,
    imap_auth_user: 'iu',
    imap_secure: true,
    imap_tls_ignoreCertErrors: true,
    imap_requireTLS: true,
    imap_disableIMAP4rev2: false,
    imap_sentMailPath: 'Sent'
};

const untouchedSmtp = {
    smtp: true,
    smtp_host: 'smtp.example.com',
    smtp_port: 465,
    smtp_secure: true,
    smtp_auth_user: 'su',
    smtp_tls_ignoreCertErrors: false,
    smtp_requireTLS: true
};

test('an untouched form builds the stored connection objects back', () => {
    assert.deepEqual(buildImapUpdates(untouchedImap, storedImap()), storedImap());
    assert.deepEqual(buildSmtpUpdates(untouchedSmtp, storedSmtp()), storedSmtp());
});

test('the stored account is never written into', () => {
    const oldData = { imap: storedImap(), smtp: storedSmtp() };
    const payload = Object.assign({ email: 'a@example.com' }, untouchedImap, untouchedSmtp, {
        imap_auth_pass: 'new-ip',
        smtp_auth_pass: 'new-sp',
        imap_tls_ignoreCertErrors: false,
        smtp_tls_ignoreCertErrors: true,
        imap_host: 'other.example.com',
        smtp_host: 'other.example.com'
    });

    const updates = buildAccountEditUpdates('acc', payload, oldData);

    assert.deepEqual(oldData, { imap: storedImap(), smtp: storedSmtp() }, 'the loaded account is unchanged');
    assert.notEqual(updates.imap, oldData.imap);
    assert.notEqual(updates.imap.auth, oldData.imap.auth);
    assert.notEqual(updates.imap.tls, oldData.imap.tls);
    assert.notEqual(updates.smtp.auth, oldData.smtp.auth);
    assert.deepEqual(updates.imap.auth, { user: 'iu', pass: 'new-ip' });
    assert.deepEqual(updates.imap.tls, { rejectUnauthorized: true });
    assert.deepEqual(updates.smtp.auth, { user: 'su', pass: 'new-sp' });
    assert.deepEqual(updates.smtp.tls, { rejectUnauthorized: false });
});

test('the IMAP section writes only what the form showed and changed', async t => {
    await t.test('an emptied override is unset, an absent one is left alone', () => {
        const imap = buildImapUpdates(Object.assign({}, untouchedImap, { imap_sentMailPath: '', imap_junkMailPath: 'Spam' }), storedImap());
        assert.equal(imap.sentMailPath, null);
        assert.equal(imap.junkMailPath, 'Spam');
        assert.ok(!('draftsMailPath' in imap));
    });

    await t.test('without the connection settings section, auth, secure and the checkboxes stay', () => {
        const payload = { imap: true, imap_disabled: true, imap_disableIMAP4rev2: true, imap_tls_ignoreCertErrors: false, imap_requireTLS: false };
        const imap = buildImapUpdates(payload, storedImap());
        assert.equal(imap.disabled, true);
        assert.deepEqual(imap.auth, { user: 'iu', pass: 'ip' });
        assert.deepEqual(imap.tls, { rejectUnauthorized: false });
        assert.ok(!('requireTLS' in imap));
        assert.ok(!('disableIMAP4rev2' in imap));
    });

    await t.test('a missing disabled key and false are the same state', () => {
        const stored = storedImap();
        delete stored.disabled;
        assert.deepEqual(buildImapUpdates(untouchedImap, stored), stored, 'an untouched save adds no disabled key');

        assert.equal(buildImapUpdates(Object.assign({}, untouchedImap, { imap_disabled: true }), stored).disabled, true);
        assert.equal(
            buildImapUpdates(untouchedImap, Object.assign(storedImap(), { disabled: true })).disabled,
            false,
            'unchecking a disabled account writes false'
        );
    });

    await t.test('an account with no IMAP yet gets no empty tls object', () => {
        const imap = buildImapUpdates(
            {
                imap: true,
                imap_host: 'h',
                imap_port: 993,
                imap_auth_user: 'u',
                imap_auth_pass: 'p',
                imap_secure: true,
                imap_requireTLS: true,
                imap_tls_ignoreCertErrors: false,
                imap_disableIMAP4rev2: false
            },
            undefined
        );
        assert.deepEqual(imap, { host: 'h', port: 993, auth: { user: 'u', pass: 'p' }, secure: true });
    });

    await t.test('the resync delay and the IDLE interval are written when given', () => {
        const imap = buildImapUpdates(Object.assign({}, untouchedImap, { imap_resyncDelay: 600, imap_maxIdleTime: 120 }), storedImap());
        assert.equal(imap.resyncDelay, 600);
        assert.equal(imap.maxIdleTime, 120 * 1000);
    });
});

test('the SMTP section of an account that had none', () => {
    assert.deepEqual(
        buildSmtpUpdates(
            { smtp: true, smtp_host: 'h', smtp_port: 587, smtp_secure: false, smtp_auth_user: 'u', smtp_requireTLS: true, smtp_tls_ignoreCertErrors: false },
            undefined
        ),
        {
            host: 'h',
            port: 587,
            secure: false,
            auth: { user: 'u' }
        }
    );
});

test('the account-level fields', () => {
    assert.deepEqual(buildBaseUpdates('acc', { email: 'a@example.com', webhooks: '', customHeaders: 'X-One: 1' }), {
        account: 'acc',
        name: '',
        email: 'a@example.com',
        expectedEmail: null,
        proxy: undefined,
        smtpEhloName: undefined,
        webhooks: '',
        webhooksCustomHeaders: [{ key: 'X-One', value: '1' }]
    });
    assert.ok(!('webhooksCustomHeaders' in buildBaseUpdates('acc', { email: 'a@example.com' })), 'stored headers kept when the field was not rendered');

    const updates = buildAccountEditUpdates('acc', { email: 'a@example.com', imap: false, smtp: false }, { imap: storedImap(), smtp: storedSmtp() });
    assert.ok(!('imap' in updates) && !('smtp' in updates), 'a section that was not submitted is not written');
});
