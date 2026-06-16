'use strict';

// Shared helpers for the EmailEngine happy-path e2e suite (test/e2e).

const nodemailer = require('nodemailer');

// Provision an Ethereal test account whose SMTP AUTH actually works. Ethereal occasionally hands
// out an account that authenticates over IMAP but is rejected over SMTP with "535 Authentication
// failed"; such an account breaks message submission with an opaque timeout. Verify SMTP up front
// and pick another account if the first one is not usable. Mirrors the proven pattern in
// test/integration/api-test.js.
async function createUsableTestAccount(attempts = 5) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
        const acct = await nodemailer.createTestAccount();
        const transport = nodemailer.createTransport({
            host: acct.smtp.host,
            port: acct.smtp.port,
            secure: acct.smtp.secure,
            auth: { user: acct.user, pass: acct.pass }
        });
        try {
            await transport.verify();
            return acct;
        } catch (err) {
            lastErr = err;
        } finally {
            transport.close();
        }
    }
    throw new Error(`Could not provision a usable Ethereal test account: ${lastErr && lastErr.message}`);
}

// Poll `checkFn` until it returns a truthy value (then return it) or the timeout elapses.
async function waitFor(checkFn, { interval = 1000, timeout = 90000, message = 'Condition not met within timeout' } = {}) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
        const result = await checkFn();
        if (result) {
            return result;
        }
        await new Promise(r => setTimeout(r, interval));
    }
    throw new Error(`Timeout: ${message}`);
}

module.exports = { createUsableTestAccount, waitFor };
