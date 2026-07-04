'use strict';

// Cross-tier test helpers shared by the integration (test/integration) and e2e (test/e2e) suites.
// Lives under test/helpers/ so neither test runner picks it up as a test file (the unit and
// integration globs only match *-test.js, and Playwright only matches *.spec.js under test/e2e).

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

// Poll `checkFn` until it returns a truthy value (then return it) or the timeout elapses. The
// tier-specific wrappers (test/integration/helpers.js and test/e2e/helpers/ethereal.js) override
// the conservative defaults with their own.
async function waitForCondition(checkFn, { interval = 1000, timeout = 90000, message = 'Condition not met within timeout' } = {}) {
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

// The POST /v1/account body fragment for an Ethereal account (as returned by
// createUsableTestAccount): email plus imap/smtp blocks. Callers spread it and add
// account/name/etc so the registration payload is built in one place.
function etherealAccountPayload(acct) {
    return {
        email: acct.user,
        imap: {
            host: acct.imap.host,
            port: acct.imap.port,
            secure: acct.imap.secure,
            auth: { user: acct.user, pass: acct.pass }
        },
        smtp: {
            host: acct.smtp.host,
            port: acct.smtp.port,
            secure: acct.smtp.secure,
            auth: { user: acct.user, pass: acct.pass }
        }
    };
}

module.exports = { createUsableTestAccount, waitForCondition, etherealAccountPayload };
