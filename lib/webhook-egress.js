'use strict';

// Owns the webhook egress policy: where it is read from, what "off" means, and the two forms the
// rest of the system consumes it in. Previously each consumer resolved the environment variable
// itself and re-derived the off-switch, which meant the pre-check and the connect-time binding
// could disagree about what was configured - the same split-brain the binding exists to prevent.

const { readEnvValue } = require('./read-env-value');
const { assertAllowedUrl, createEgressLookup, normalizePolicy, POLICY_OFF } = require('./egress-filter');

// Which destinations webhook deliveries may reach. An account-scoped API token can set both the
// webhook URL and its custom headers, so without this the least-privileged credential in the
// system can aim EmailEngine at anything its host can route to. Defaults to blocking the
// link-local range (cloud instance metadata); `private` also blocks RFC1918 and friends, `off`
// disables the check and restores redirect following. See lib/egress-filter.js
const WEBHOOK_EGRESS_POLICY = normalizePolicy(readEnvValue('EENGINE_WEBHOOK_EGRESS_POLICY'));

const policyEnabled = WEBHOOK_EGRESS_POLICY !== POLICY_OFF;

// Built once rather than per delivery. Null when the policy is off, which is also what tells
// sendWebhookRequest() to keep following redirects.
const validateWebhookTarget = policyEnabled ? target => assertAllowedUrl(target, { policy: WEBHOOK_EGRESS_POLICY }) : null;

/**
 * Builds the connect-time half of the guard, for use as an undici Agent's `connect.lookup`.
 *
 * @returns {Function|null} A lookup enforcing the policy, or null when the policy is off
 */
function createWebhookLookup() {
    return policyEnabled ? createEgressLookup(WEBHOOK_EGRESS_POLICY) : null;
}

module.exports = {
    WEBHOOK_EGRESS_POLICY,
    validateWebhookTarget,
    createWebhookLookup
};
