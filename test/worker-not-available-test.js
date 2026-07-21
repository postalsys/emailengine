'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Exercise the real submit-worker discard predicate (lib/delivery-error.js), the exact code path
// workers/submit.js uses to decide whether a failed delivery job should be discarded (permanent
// failure) or left for BullMQ to retry.
//
// The cases below deliberately build their errors the way the production code builds them, rather
// than hand-setting whichever field the predicate happens to read. An earlier version of this suite
// asserted on codes that nothing in the codebase ever emits, so it passed while the bug it was
// written for was still live.
const { shouldDiscardJob, isPermanentDeliveryError, NON_RETRYABLE_CODES } = require('../lib/delivery-error');

// How base-client.js stamps a real nodemailer SMTP failure: `responseCode` is nodemailer's, and
// `statusCode` is a copy of it made for the API response and webhook payload.
function smtpError(message, responseCode) {
    let err = new Error(message);
    err.responseCode = responseCode;
    err.statusCode = Number(responseCode) || null;
    return err;
}

test('submit worker delivery-error classification', async t => {
    await t.test('a genuine SMTP 5xx is permanent', () => {
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let responseCode of [500, 501, 502, 550, 554]) {
            let err = smtpError(`Error ${responseCode}`, responseCode);
            assert.strictEqual(isPermanentDeliveryError(err), true, `SMTP ${responseCode} should be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), true, `SMTP ${responseCode} should be discarded`);
        }
    });

    await t.test('an SMTP 503 is transient', () => {
        let job = { attemptsMade: 1, opts: { attempts: 10 } };
        let err = smtpError('Try again later', 503);

        assert.strictEqual(isPermanentDeliveryError(err), false, '503 is a transient "try again later"');
        assert.strictEqual(shouldDiscardJob(err, job), false);
    });

    await t.test('an SMTP 4xx is transient', () => {
        let job = { attemptsMade: 0, opts: { attempts: 5 } };

        for (let responseCode of [421, 450, 451, 452]) {
            let err = smtpError(`Error ${responseCode}`, responseCode);
            assert.strictEqual(shouldDiscardJob(err, job), false, `SMTP ${responseCode} should be retried`);
        }
    });

    await t.test('a 5xx that is NOT an SMTP reply does not discard the queued message', () => {
        // The regression this guards. Only the SMTP path sets `responseCode`; everywhere else a 5xx
        // `statusCode` describes infrastructure, not the message - 503 "no active handler", 504 RPC
        // timeouts, 500 Redis lock failures, and every API transport's passthrough of the provider's
        // HTTP status. Reading it as an SMTP verdict silently discarded perfectly good mail.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let statusCode of [500, 502, 504]) {
            let err = new Error(`Infrastructure failure ${statusCode}`);
            err.statusCode = statusCode;

            assert.strictEqual(isPermanentDeliveryError(err), false, `a non-SMTP ${statusCode} must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `a non-SMTP ${statusCode} must not discard the job`);
        }
    });

    await t.test('a Gmail/Graph API 5xx during send does not discard the queued message', () => {
        // Built exactly as lib/oauth/gmail.js and lib/oauth/outlook.js build it: only `statusCode`,
        // never a `code`. An allowlist keyed on `code` could not cover this, which is why the
        // classification is keyed on provenance instead.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let statusCode of [500, 502, 503]) {
            let err = new Error('OAuth2 request failed');
            err.statusCode = statusCode;
            err.oauthRequest = { status: statusCode, provider: 'gmail' };

            assert.strictEqual(isPermanentDeliveryError(err), false, `a provider ${statusCode} must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `a provider ${statusCode} must not discard the job`);
        }
    });

    await t.test('an OAuth2 token-endpoint 5xx does not discard the queued message', () => {
        // {code:'ETokenRefresh', statusCode:<token endpoint's HTTP status>} - the status belongs to
        // the token endpoint, not to the mail server, so it says nothing about the message.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let statusCode of [500, 502, 504]) {
            let err = new Error('Token request failed');
            err.code = 'ETokenRefresh';
            err.statusCode = statusCode;

            assert.strictEqual(isPermanentDeliveryError(err), false, `a token endpoint ${statusCode} must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `a token endpoint ${statusCode} must not discard the job`);
        }
    });

    await t.test('an RPC timeout to the IMAP worker does not discard the queued message', () => {
        // workers/submit.js call() rejects with {code:'Timeout', statusCode:504} when the IMAP
        // worker does not answer in time. Retrying is safe because the submit worker checks the
        // job's own 'smtp-completed'/'submitted' progress before treating a failure as a failure.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        let err = new Error('Timeout waiting for command response [T5]');
        err.code = 'Timeout';
        err.statusCode = 504;

        assert.strictEqual(isPermanentDeliveryError(err), false, 'an RPC timeout must not be permanent');
        assert.strictEqual(shouldDiscardJob(err, job), false, 'an RPC timeout must not discard the job');
    });

    await t.test('a Workload Identity Federation token failure does not discard the queued message', () => {
        // ESTSExchange / ESignJwt / ESubjectTokenRead carry the responding Google endpoint's HTTP
        // status. Under the old allowlist every one of these discarded queued mail during a
        // Google-side blip; keying on provenance covers them without naming them.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let code of ['ESTSExchange', 'ESignJwt', 'ESubjectTokenRead']) {
            let err = new Error(`${code} request failed`);
            err.code = code;
            err.statusCode = 500;

            assert.strictEqual(isPermanentDeliveryError(err), false, `${code} must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `${code} must not discard the job`);
        }
    });

    await t.test('an explicit permanentDeliveryError marker is honoured', () => {
        // Contract test for the predicate only - nothing sets this marker today. It is the escape
        // hatch for a rejection that is genuinely permanent without being an SMTP reply, but it
        // cannot be used yet: submitMessage() runs in the IMAP worker and the RPC hop to the submit
        // worker copies only {error, code, statusCode, info}, so a marker set at the throw site is
        // stripped before shouldDiscardJob() ever sees it. Widen the RPC envelope before relying on
        // it, and add a test that crosses the worker boundary rather than building the error here.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        let err = new Error('Invalid message format');
        err.code = 'ErrorInvalidRecipients';
        err.statusCode = 500;
        err.permanentDeliveryError = true;

        assert.strictEqual(isPermanentDeliveryError(err), true);
        assert.strictEqual(shouldDiscardJob(err, job), true);
    });

    await t.test('discards non-retryable error codes regardless of status', () => {
        let job = { attemptsMade: 0, opts: { attempts: 10 } };

        for (let code of NON_RETRYABLE_CODES) {
            let err = new Error(`Permanent failure: ${code}`);
            err.code = code;
            // No status at all - must still be permanent because of the code.
            assert.strictEqual(isPermanentDeliveryError(err), true, `${code} should be a permanent error`);
            assert.strictEqual(shouldDiscardJob(err, job), true, `${code} jobs should be discarded`);
        }
    });

    await t.test('a non-retryable code wins over a transient SMTP reply', () => {
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        let err = smtpError('Auth failed mid-handshake', 503);
        err.code = 'EAUTH';

        assert.strictEqual(isPermanentDeliveryError(err), true);
        assert.strictEqual(shouldDiscardJob(err, job), true);
    });

    await t.test('does not discard unknown/transient errors with no status or code', () => {
        let job = { attemptsMade: 0, opts: { attempts: 10 } };

        let err = new Error('ETIMEDOUT'); // network timeout, retryable
        err.code = 'ETIMEDOUT';

        assert.strictEqual(isPermanentDeliveryError(err), false);
        assert.strictEqual(shouldDiscardJob(err, job), false);
    });

    await t.test('does not discard when all attempts are exhausted', () => {
        // BullMQ fails the job naturally at that point, so there is nothing to discard.
        let job = { attemptsMade: 10, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscardJob(smtpError('Internal server error', 550), job), false);
    });

    await t.test('isPermanentDeliveryError tolerates a missing error object', () => {
        assert.strictEqual(isPermanentDeliveryError(null), false);
        assert.strictEqual(isPermanentDeliveryError(undefined), false);
    });
});
