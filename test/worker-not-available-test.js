'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Exercise the real submit-worker discard predicate (lib/delivery-error.js), the exact code path
// workers/submit.js uses to decide whether a failed delivery job should be discarded (permanent
// failure) or left for BullMQ to retry.
//
// The cases below build their errors the way the production code builds them: real nodemailer SMTP
// failures always carry a `code` (EENVELOPE/EMESSAGE/EAUTH/...) alongside the numeric `responseCode`,
// and those errors reach shouldDiscardJob only after crossing two worker-thread RPC hops. Both are
// modelled here - the `code` (an earlier version of this suite omitted it and so asserted retry
// behavior production never had), and the RPC round-trip (via the real lib/worker-rpc-error helpers,
// so a dropped field fails a test instead of silently changing production).
const { shouldDiscardJob, isPermanentDeliveryError, NON_RETRYABLE_CODES } = require('../lib/delivery-error');
const { packRpcError, unpackRpcError } = require('../lib/worker-rpc-error');

// How base-client.js stamps a real nodemailer SMTP failure: nodemailer sets `responseCode` and a
// `code` (EENVELOPE for envelope rejections, EMESSAGE for DATA rejections, EAUTH for auth), and
// base-client copies responseCode into `statusCode` for the API response and webhook payload.
function smtpError(message, responseCode, code) {
    let err = new Error(message);
    err.responseCode = responseCode;
    err.statusCode = Number(responseCode) || null;
    if (code) {
        err.code = code;
    }
    return err;
}

// Serializes the error the way the worker-thread RPC hops do (lib/worker-rpc-error.js), so a case is
// classified against the exact shape the submit worker receives, not the one built above. The
// transform is stateless, so one crossing catches a dropped field as well as replaying all the hops:
// if a future change drops a field from the RPC envelope, the greylist/5xx cases below fail here.
function acrossWorkerBoundary(err) {
    return unpackRpcError(packRpcError(err));
}

test('submit worker delivery-error classification', async t => {
    await t.test('a genuine SMTP 5xx is permanent', () => {
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        for (let responseCode of [500, 501, 502, 550, 554]) {
            let err = acrossWorkerBoundary(smtpError(`Error ${responseCode}`, responseCode, 'EENVELOPE'));
            assert.strictEqual(isPermanentDeliveryError(err), true, `SMTP ${responseCode} should be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), true, `SMTP ${responseCode} should be discarded`);
        }
    });

    await t.test('an SMTP 503 is transient', () => {
        let job = { attemptsMade: 1, opts: { attempts: 10 } };
        let err = acrossWorkerBoundary(smtpError('Try again later', 503, 'EENVELOPE'));

        assert.strictEqual(isPermanentDeliveryError(err), false, '503 is left retryable on purpose');
        assert.strictEqual(shouldDiscardJob(err, job), false);
    });

    await t.test('a transient 4xx SMTP reply is retried even though nodemailer tags it EENVELOPE', () => {
        // The regression this guards: greylisting (and other soft 4xx rejections) come back as a 4xx
        // reply with code EENVELOPE/EMESSAGE/EAUTH. EENVELOPE is in NON_RETRYABLE_CODES, so before
        // the fix the message was discarded on the first attempt despite the server asking for a
        // retry. Per RFC 5321 a 4yz reply is transient, so the reply code has to win over the code.
        let job = { attemptsMade: 0, opts: { attempts: 5 } };

        for (let [responseCode, code] of [
            [421, 'EPROTOCOL'],
            [450, 'EENVELOPE'], // "450 greylisted, try again later" on RCPT TO
            [451, 'EMESSAGE'],
            [452, 'EENVELOPE'],
            [454, 'EAUTH'] // temporary authentication failure
        ]) {
            let err = acrossWorkerBoundary(smtpError(`Error ${responseCode}`, responseCode, code));
            assert.strictEqual(isPermanentDeliveryError(err), false, `SMTP ${responseCode}/${code} must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `SMTP ${responseCode}/${code} must be retried`);
        }
    });

    await t.test('a 5xx that is NOT an SMTP reply does not discard the queued message', () => {
        // Only the SMTP path sets `responseCode`; everywhere else a 5xx `statusCode` describes
        // infrastructure, not the message - 503 "no active handler", 504 RPC timeouts, 500 Redis lock
        // failures, an OAuth2 token-endpoint blip, a Gmail/Graph API 5xx, a WIF token exchange. None
        // set a NON_RETRYABLE `code`, so keying on provenance retries them all without naming them.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        const nonSmtpErrors = [
            { msg: 'No active handler', statusCode: 503, code: 'WorkerNotAvailable' },
            { msg: 'Timeout waiting for command response [T5]', statusCode: 504, code: 'Timeout' },
            { msg: 'Redis lock failed', statusCode: 500 },
            { msg: 'OAuth2 request failed', statusCode: 502 },
            { msg: 'Token request failed', statusCode: 500, code: 'ETokenRefresh' },
            { msg: 'ESTSExchange request failed', statusCode: 500, code: 'ESTSExchange' }
        ];

        for (let spec of nonSmtpErrors) {
            let source = new Error(spec.msg);
            source.statusCode = spec.statusCode;
            if (spec.code) {
                source.code = spec.code;
            }
            let err = acrossWorkerBoundary(source);

            assert.strictEqual(isPermanentDeliveryError(err), false, `a non-SMTP ${spec.statusCode} (${spec.code || 'no code'}) must not be permanent`);
            assert.strictEqual(shouldDiscardJob(err, job), false, `a non-SMTP ${spec.statusCode} (${spec.code || 'no code'}) must not discard the job`);
        }
    });

    await t.test('discards non-retryable error codes with no SMTP reply', () => {
        // Hard failures with no server reply at all (missing credentials, TLS/protocol mismatch, a
        // client-side "no recipients defined" EENVELOPE): they recur on every retry, so discard.
        let job = { attemptsMade: 0, opts: { attempts: 10 } };

        for (let code of NON_RETRYABLE_CODES) {
            let err = new Error(`Permanent failure: ${code}`);
            err.code = code;
            err = acrossWorkerBoundary(err);
            assert.strictEqual(isPermanentDeliveryError(err), true, `${code} should be a permanent error`);
            assert.strictEqual(shouldDiscardJob(err, job), true, `${code} jobs should be discarded`);
        }
    });

    await t.test('does not discard when all attempts are exhausted', () => {
        // BullMQ fails the job naturally at that point, so there is nothing to discard.
        let job = { attemptsMade: 10, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscardJob(acrossWorkerBoundary(smtpError('Rejected', 550, 'EENVELOPE')), job), false);
    });

    await t.test('isPermanentDeliveryError tolerates a missing error object', () => {
        assert.strictEqual(isPermanentDeliveryError(null), false);
        assert.strictEqual(isPermanentDeliveryError(undefined), false);
    });
});
