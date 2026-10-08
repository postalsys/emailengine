'use strict';

// OAuth2 app "Verify setup" diagnostic. Runs the real authentication chain for a
// configured OAuth2 app step by step against the provider and returns a structured
// result so the admin can see exactly which step fails and how to fix it. Reuses the
// existing OAuth clients and the coded errors they already throw - no provider logic
// is reimplemented here.

const { createImapClient } = require('../create-imap-client');
const { oauth2Apps, oauth2ProviderData, SERVICE_ACCOUNT_PROVIDERS, pubSubResourceNames } = require('../oauth2-apps');
const { normalizeAuthMethod } = require('./gmail');
const gcpMetadata = require('./gcp-metadata');
const packageData = require('../../package.json');

// A single diagnostic step. status: 'ok' | 'fail' | 'skip'.
const mkStep = (id, label, status, message, extra) => Object.assign({ id, label, status, message: message || null }, extra || {});

const finalize = (appData, authMethod, steps, account) => ({
    app: appData.id,
    provider: appData.provider,
    authMethod: authMethod || null,
    account: account || null,
    ok: steps.every(s => s.status !== 'fail'),
    steps
});

// Bound the live IMAP probe so a hung connection cannot stall the request.
const withTimeout = (promise, ms, label) =>
    Promise.race([
        promise,
        new Promise((resolve, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`)), ms).unref())
    ]);

// Upper bound on remote error text echoed into the verify report. These strings come from the
// remote endpoint, so they are reflected content: bound them rather than passing an
// arbitrarily long body through into the API response.
const MAX_REMOTE_DETAIL_LENGTH = 512;

function truncateDetail(value) {
    if (typeof value !== 'string') {
        return null;
    }
    return value.length > MAX_REMOTE_DETAIL_LENGTH ? `${value.slice(0, MAX_REMOTE_DETAIL_LENGTH)}...` : value;
}

function describeResponse(err) {
    let resp = err && (err.response || (err.tokenRequest && err.tokenRequest.response) || (err.oauthRequest && err.oauthRequest.response));
    if (resp && typeof resp === 'object') {
        // Google API errors nest the detail under error.message; OAuth/STS errors
        // use top-level string error/error_description fields.
        if (resp.error && typeof resp.error === 'object' && resp.error.message) {
            return truncateDetail(resp.error.message);
        }
        let parts = [resp.error, resp.error_description].filter(part => typeof part === 'string' && part);
        if (parts.length) {
            return truncateDetail(parts.join(': '));
        }
    }
    return null;
}

// Maps the signer's coded errors (ESubjectTokenRead / ESTSExchange / ESignJwt) onto
// discrete steps, marking everything up to the failure as ok.
function mapSigningError(err, authMethod, steps) {
    let detail = describeResponse(err);
    let msg = m => [m, detail].filter(Boolean).join(' - ');

    if (authMethod === 'externalAccount') {
        switch (err.code) {
            case 'ESubjectTokenRead':
                steps.push(
                    mkStep('subjectToken', 'Read OIDC subject token', 'fail', err.message, {
                        hint: 'EmailEngine could not read the OIDC subject token from the configured credential source on this host. Ensure the file path or URL in the external account configuration exists and is readable by the EmailEngine process.'
                    })
                );
                return;
            case 'ESTSExchange':
                steps.push(mkStep('subjectToken', 'Read OIDC subject token', 'ok', 'Subject token read from the credential source'));
                steps.push(
                    mkStep('sts', 'STS token exchange', 'fail', msg('Google STS rejected the token exchange'), {
                        hint: "Verify the Workload Identity Pool provider's issuer URI, allowed audience and attribute mapping, and that the subject token's audience matches the provider."
                    })
                );
                return;
            case 'ESignJwt':
                steps.push(mkStep('subjectToken', 'Read OIDC subject token', 'ok', 'Subject token read from the credential source'));
                steps.push(mkStep('sts', 'STS token exchange', 'ok', 'Federated access token obtained from Google STS'));
                steps.push(
                    mkStep('signJwt', 'Sign assertion (signJwt)', 'fail', msg('Google IAM rejected signJwt'), {
                        hint: 'The federated identity is not allowed to sign JWTs as this service account. Grant it roles/iam.serviceAccountTokenCreator on the target service account. Note: roles/iam.workloadIdentityUser is NOT sufficient - it allows generateAccessToken but not signJwt.'
                    })
                );
                return;
            default:
                steps.push(mkStep('signJwt', 'Sign assertion (Workload Identity Federation)', 'fail', msg(err.message)));
                return;
        }
    }

    // serviceKey mode: a single local signing step
    steps.push(
        mkStep('sign', 'Sign assertion with service key', 'fail', err.message, {
            hint: 'The service account private key could not sign the assertion. Re-upload the JSON key file for this service account.'
        })
    );
}

// Maps a metadata server failure (lib/oauth/gcp-metadata.js) onto the hint that fixes it
function metadataServerHint(err) {
    switch (err.code) {
        case 'EMetadataConfig':
            return 'The metadata server override in the environment is not a host name or host:port. Correct or remove EENGINE_GCP_METADATA_HOST (or GCE_METADATA_HOST).';
        case 'EMetadataUnreachable':
            if (err.transient) {
                return 'The metadata server did not answer in time or dropped the connection. Retry in a moment; if it persists, check the network path to metadata.google.internal from this host.';
            }
            return 'EmailEngine is not running on Google Cloud, or the metadata server cannot be reached from it. The attached service account is only available on Compute Engine, GKE with Workload Identity enabled on the node pool, and Cloud Run. The request never goes through the configured proxy.';
        case 'EMetadataServer':
            if (err.wrongFlavor) {
                return 'Something other than the Google Cloud metadata server answered at this address. Check EENGINE_GCP_METADATA_HOST (or GCE_METADATA_HOST), and that no proxy or other service intercepts metadata.google.internal.';
            }
            if (err.statusCode === 404) {
                return 'No service account is attached to this instance. Attach one to the VM, the GKE Kubernetes service account (Workload Identity) or the Cloud Run service.';
            }
            if (err.statusCode === 403) {
                return 'The metadata server refused the request. On GKE, the Kubernetes service account must be bound to a Google service account through Workload Identity.';
            }
            return 'The metadata server did not issue a token. Retry in a moment; if it persists, check the service account attached to this instance.';
        default:
            return 'The metadata server answered without a usable access token.';
    }
}

// Read-only proof that the token can do what a Pub/Sub app needs: reading the app's own topic. A
// token is not the same as access: the role may be missing, and on Compute Engine the VM's access
// scopes cap the token whatever roles the service account holds. The topic itself rather than a
// project listing, because the least-privilege role the documentation offers grants topics.get
// and not topics.list, and because a topic that was never created is worth reporting too
async function pubSubAccessProbe(appData, client, accessToken, steps) {
    if (!appData.googleProjectId) {
        steps.push(
            mkStep('pubsub', 'Pub/Sub access', 'skip', 'No Google Cloud project ID is configured', {
                hint: 'Set the Google Cloud Project ID in the app settings. EmailEngine creates the Pub/Sub topic and subscription in that project.'
            })
        );
        return;
    }

    // The stored topic is the one the Gmail watches publish to, and it does not always follow the
    // current project and topic name (an adopted topic is kept as recorded), so it is the one to
    // probe. Before the first setup there is none, and the name that setup creates is probed instead
    // (both parts pattern-validated, so neither can leave the path)
    let topicName = appData.pubSubTopic || `projects/${appData.googleProjectId}/topics/${pubSubResourceNames(appData).topic}`;

    try {
        await client.request(accessToken, `https://pubsub.googleapis.com/v1/${topicName}`, 'get');
        steps.push(mkStep('pubsub', 'Pub/Sub access', 'ok', `Pub/Sub topic ${topicName} is reachable`));
    } catch (err) {
        let status = err.statusCode;
        let detail = describeResponse(err) || err.message;
        let hint;
        if (status === 403 && /scope/i.test(detail)) {
            hint =
                'The access token does not carry a scope that covers Pub/Sub. On Compute Engine, give the VM the "cloud-platform" access scope (or allow full access to all Cloud APIs); the roles of the service account cannot widen what the access scopes allow.';
        } else if (status === 403) {
            hint = `The service account is not allowed to manage Pub/Sub in project ${appData.googleProjectId}. Grant it the "Pub/Sub Admin" role.`;
        } else if (status === 404) {
            hint = `The topic does not exist. EmailEngine creates it when the application is saved, so the application page should show why that failed; also check that project ${appData.googleProjectId} exists and has the Cloud Pub/Sub API enabled.`;
        } else {
            hint = 'The Pub/Sub API request failed. Check the project ID and that the Cloud Pub/Sub API is enabled.';
        }
        steps.push(mkStep('pubsub', 'Pub/Sub access', 'fail', detail, { hint }));
    }
}

// Maps GmailOauth.refreshToken (jwt-bearer) failures, using checkForFlags codes.
function mapTokenError(err, account, appData, steps) {
    let flag = err.tokenRequest && err.tokenRequest.flag;
    let detail = describeResponse(err) || err.message;
    let scopeList = (appData.baseScopes === 'api' && 'https://www.googleapis.com/auth/gmail.modify') || 'https://mail.google.com/';

    let hint;
    switch (flag && flag.code) {
        case 'UNAUTHORIZED_CLIENT':
            hint = `Authorize domain-wide delegation in Google Workspace Admin (Security > API controls > Domain-wide delegation): add client ID ${appData.serviceClient} with the OAuth scope ${scopeList}.`;
            break;
        case 'INVALID_CLIENT_EMAIL':
        case 'INVALID_SERVICE_CLIENT_EMAIL':
            hint = 'The service account principal is invalid or unrecognized. Verify the service account email and client ID in the app settings.';
            break;
        case 'INSUFFICIENT_AUTH_SCOPES':
            hint = `The scopes authorized for domain-wide delegation do not cover the requested scope (${scopeList}). Update the DWD authorization in Workspace Admin.`;
            break;
        case 'GMAIL_API_NOT_ENABLED':
            hint = `Enable the Gmail API for this Google Cloud project${flag.url ? `: ${flag.url}` : '.'}`;
            break;
        default:
            hint = `Could not obtain a token for ${account}. Ensure the address exists in the Workspace domain and that domain-wide delegation is authorized for client ID ${appData.serviceClient} with scope ${scopeList}.`;
    }

    steps.push(mkStep('token', 'Domain-wide delegation token', 'fail', detail, { hint }));
}

// Live, read-only IMAP XOAUTH2 login. No mailbox changes, no mail sent.
async function imapProbe(appData, account, accessToken, steps) {
    let imapCfg = oauth2ProviderData(appData.provider, appData.cloud).imap;
    let client = createImapClient({
        host: imapCfg.host,
        port: imapCfg.port,
        secure: imapCfg.secure,
        auth: { user: account, accessToken },
        logger: false,
        emitLogs: false,
        clientInfo: { name: packageData.name, version: packageData.version }
    });
    client.on('error', () => {});
    try {
        await withTimeout(client.connect(), 25 * 1000, 'IMAP connection');
        let mailboxes = await withTimeout(client.list(), 15 * 1000, 'IMAP folder listing');
        steps.push(mkStep('mailbox', 'Mailbox access (IMAP)', 'ok', `Connected to ${imapCfg.host} as ${account}; ${mailboxes.length} folders visible`));
    } catch (err) {
        let authFailed =
            err.authenticationFailed || /AUTHENTICATIONFAILED|Invalid credentials|authenticationfailed/i.test(err.responseText || err.message || '');
        steps.push(
            mkStep('mailbox', 'Mailbox access (IMAP)', 'fail', err.responseText || err.message, {
                hint: authFailed
                    ? 'A token was obtained but the IMAP login was rejected. Ensure IMAP access is enabled for the domain/user in Google Workspace (Apps > Gmail > end-user access) and that the OAuth scope includes https://mail.google.com/.'
                    : `Could not reach ${imapCfg.host}. Check network egress and TLS to the mail server.`
            })
        );
    } finally {
        // Best-effort cleanup; must never throw out of finally and mask the result.
        try {
            await client.logout();
        } catch (err) {
            try {
                client.close();
            } catch (err2) {
                // ignore
            }
        }
    }
}

async function verifyGmailService(appData, opts, steps) {
    let { account, testConnection } = opts;
    let authMethod = normalizeAuthMethod(appData.authMethod);

    // Step 1 - configuration. getClient builds the signer, which validates the external
    // account JSON and the service-account-email match (or fails if creds are missing).
    let client;
    try {
        client = await oauth2Apps.getClient(appData.id, { setFlag: async () => {} });
        let configMessage =
            authMethod === 'metadataServer'
                ? `Attached service account, read from the metadata server at ${gcpMetadata.resolveMetadataOrigin()}`
                : authMethod === 'externalAccount'
                  ? 'External account configuration is valid'
                  : 'Service account key is present';
        steps.push(mkStep('config', 'Configuration', 'ok', configMessage));
    } catch (err) {
        steps.push(
            mkStep('config', 'Configuration', 'fail', err.message, {
                hint:
                    err.code === 'EMetadataConfig'
                        ? metadataServerHint(err)
                        : 'Complete the service account credentials in the app settings (service client, email and key/external account configuration).'
            })
        );
        return finalize(appData, authMethod, steps, account);
    }

    let isMetadataServer = authMethod === 'metadataServer';

    // Step 2 - signing chain (no mailbox/email needed; signJwt signs an arbitrary payload). The
    // attached service account has none: the metadata server issues the token itself
    if (!isMetadataServer) {
        try {
            await client.generateServiceRequest(account || 'verify-probe@example.com', false);
            if (authMethod === 'externalAccount') {
                steps.push(mkStep('subjectToken', 'Read OIDC subject token', 'ok', 'Subject token read from the credential source'));
                steps.push(mkStep('sts', 'STS token exchange', 'ok', 'Federated access token obtained from Google STS'));
                steps.push(mkStep('signJwt', 'Sign assertion (signJwt)', 'ok', 'Assertion signed via IAM signJwt'));
            } else {
                steps.push(mkStep('sign', 'Sign assertion with service key', 'ok', 'Assertion signed locally with the service account key'));
            }
        } catch (err) {
            mapSigningError(err, authMethod, steps);
            return finalize(appData, authMethod, steps, account);
        }
    }

    // Pub/Sub apps authenticate as the service account itself (principal mode), not by
    // impersonating a user, so they need no mailbox address and no domain-wide delegation.
    if (appData.baseScopes === 'pubsub') {
        let label = isMetadataServer ? 'Service account token (metadata server)' : 'Service account token';
        let accessToken;
        try {
            // The attached service account is named by the metadata server, not the app record, so
            // its email is read beside the token to say who EmailEngine acts as; its failure is ignored
            let [resp, serviceAccountEmail] = await Promise.all([
                client.refreshToken({ isPrincipal: true }),
                isMetadataServer ? gcpMetadata.fetchServiceAccountEmail().catch(() => null) : null
            ]);
            if (!resp || !resp.access_token) {
                throw Object.assign(new Error('No access token returned by the token endpoint'), { code: 'ETokenRefresh' });
            }
            accessToken = resp.access_token;
            let message = isMetadataServer
                ? `Access token issued for ${serviceAccountEmail || 'the attached service account'}`
                : 'App-only access token obtained for the service account';
            steps.push(mkStep('token', label, 'ok', message));
        } catch (err) {
            let flag = err.tokenRequest && err.tokenRequest.flag;
            let hint;
            if (isMetadataServer) {
                hint = metadataServerHint(err);
            } else if (flag && flag.code === 'INVALID_SERVICE_CLIENT_EMAIL') {
                hint = 'The service account is invalid or unrecognized. Verify the service account email and client ID in the app settings.';
            } else {
                hint = 'The service account could not obtain its own access token. Verify the service account email and client ID in the app settings.';
            }
            steps.push(mkStep('token', label, 'fail', describeResponse(err) || err.message, { hint }));
            return finalize(appData, authMethod, steps, account);
        }
        await pubSubAccessProbe(appData, client, accessToken, steps);
        return finalize(appData, authMethod, steps, account);
    }

    // Step 3 - domain-wide delegation token (needs a Workspace email to impersonate).
    if (!account) {
        steps.push(
            mkStep('token', 'Domain-wide delegation token', 'skip', 'Provide a Workspace email address to verify domain-wide delegation and mailbox access')
        );
        return finalize(appData, authMethod, steps, account);
    }

    let accessToken;
    try {
        let resp = await client.refreshToken({ user: account });
        accessToken = resp && resp.access_token;
        steps.push(mkStep('token', 'Domain-wide delegation token', 'ok', `Access token obtained for ${account}`));
    } catch (err) {
        mapTokenError(err, account, appData, steps);
        return finalize(appData, authMethod, steps, account);
    }

    if (!accessToken) {
        steps.push(mkStep('mailbox', 'Mailbox access', 'fail', 'No access token returned by the token endpoint'));
        return finalize(appData, authMethod, steps, account);
    }

    // Step 4 - live mailbox access.
    if (!testConnection) {
        steps.push(mkStep('mailbox', 'Mailbox access', 'skip', 'Connection test disabled'));
    } else if (appData.baseScopes === 'api') {
        try {
            let profile = await client.request(accessToken, 'https://gmail.googleapis.com/gmail/v1/users/me/profile', 'get');
            steps.push(
                mkStep(
                    'mailbox',
                    'Gmail API access',
                    'ok',
                    `Gmail API reachable for ${(profile && profile.emailAddress) || account} (${(profile && profile.messagesTotal) || 0} messages)`
                )
            );
        } catch (err) {
            steps.push(
                mkStep('mailbox', 'Gmail API access', 'fail', describeResponse(err) || err.message, {
                    hint: 'Ensure the Gmail API is enabled for the project and the configured scope grants Gmail API access (e.g. gmail.modify or gmail.readonly).'
                })
            );
        }
    } else {
        await imapProbe(appData, account, accessToken, steps);
    }

    return finalize(appData, authMethod, steps, account);
}

async function verifyOutlookService(appData, opts, steps) {
    let { account, testConnection } = opts;

    let client;
    try {
        client = await oauth2Apps.getClient(appData.id, { setFlag: async () => {} });
        steps.push(mkStep('config', 'Configuration', 'ok', 'Client credentials configuration is present'));
    } catch (err) {
        steps.push(
            mkStep('config', 'Configuration', 'fail', err.message, {
                hint: 'Complete the client ID, client secret and tenant (authority) in the app settings.'
            })
        );
        return finalize(appData, 'clientCredentials', steps, account);
    }

    let accessToken;
    try {
        let resp = await client.refreshToken({});
        accessToken = resp && resp.access_token;
        steps.push(mkStep('token', 'Client credentials token', 'ok', 'App-only access token obtained from Microsoft Entra'));
    } catch (err) {
        steps.push(
            mkStep('token', 'Client credentials token', 'fail', describeResponse(err) || err.message, {
                hint: 'Microsoft Entra rejected the client credentials grant. Verify the tenant ID, client ID and secret, and that admin consent has been granted for the application.'
            })
        );
        return finalize(appData, 'clientCredentials', steps, account);
    }

    if (!account) {
        steps.push(mkStep('mailbox', 'Mailbox access', 'skip', 'Provide a mailbox address to verify application access to a mailbox'));
        return finalize(appData, 'clientCredentials', steps, account);
    }
    if (!testConnection || !accessToken) {
        steps.push(mkStep('mailbox', 'Mailbox access', 'skip', testConnection ? 'No access token returned' : 'Connection test disabled'));
        return finalize(appData, 'clientCredentials', steps, account);
    }

    // outlookService is API-based: probe Microsoft Graph (app-only), matching how the
    // real client accesses the mailbox - not IMAP.
    try {
        let url = `${client.apiBase}/v1.0/users/${encodeURIComponent(account)}?$select=id,mail,userPrincipalName`;
        let user = await client.request(accessToken, url, 'get');
        steps.push(
            mkStep('mailbox', 'Mailbox access (Microsoft Graph)', 'ok', `Graph reachable for ${(user && (user.mail || user.userPrincipalName)) || account}`)
        );
    } catch (err) {
        let status = err.statusCode;
        let hint =
            status === 403
                ? 'The application lacks the required Graph permission or admin consent. Grant application permissions (e.g. Mail.ReadWrite) and admin consent in Microsoft Entra.'
                : status === 404
                  ? `Mailbox ${account} was not found in the tenant.`
                  : 'Microsoft Graph request failed. Verify the application permissions and that the mailbox exists.';
        steps.push(mkStep('mailbox', 'Mailbox access (Microsoft Graph)', 'fail', describeResponse(err) || err.message, { hint }));
    }
    return finalize(appData, 'clientCredentials', steps, account);
}

// 3-legged interactive OAuth apps cannot be verified without a user authorization.
function verifyInteractive(appData, steps) {
    let configured = !!(appData.clientId && appData.clientSecret && appData.redirectUrl);

    steps.push(
        mkStep(
            'config',
            'Client configuration',
            configured ? 'ok' : 'fail',
            configured ? 'Client ID, client secret and redirect URL are set' : 'Missing one of: client ID, client secret, redirect URL',
            {
                hint: configured ? undefined : 'Fill in the client ID, client secret and redirect URL in the app settings.'
            }
        )
    );
    steps.push(
        mkStep('interactive', 'End-user authorization', 'skip', 'This is an interactive (3-legged) OAuth2 application', {
            hint: 'Connect a test email account using this application to fully verify the configuration - the authorization, scopes and token exchange are validated when a user grants access.'
        })
    );
    return finalize(appData, null, steps, null);
}

/**
 * Verify the setup of a configured OAuth2 application.
 * @param {String} appId - OAuth2 application id
 * @param {Object} [opts]
 * @param {String} [opts.account] - email/mailbox address used to verify delegation and mailbox access
 * @param {Boolean} [opts.testConnection=true] - perform the live IMAP/API connection step
 * @returns {Object} { app, provider, authMethod, account, ok, steps[] }
 */
async function verifyOAuth2App(appId, opts) {
    opts = opts || {};
    let account = opts.account || null;
    let testConnection = opts.testConnection !== false;

    let appData = await oauth2Apps.get(appId);
    if (!appData) {
        let err = new Error('OAuth2 application was not found');
        err.code = 'AppNotFound';
        err.statusCode = 404;
        throw err;
    }

    let steps = [];
    let runOpts = { account, testConnection };

    if (appData.provider === 'gmailService') {
        return await verifyGmailService(appData, runOpts, steps);
    }
    if (appData.provider === 'outlookService') {
        return await verifyOutlookService(appData, runOpts, steps);
    }
    if (SERVICE_ACCOUNT_PROVIDERS.has(appData.provider)) {
        // Future service-account providers: fall back to a config-only check.
        let authMethod = appData.authMethod || null;
        steps.push(mkStep('config', 'Configuration', 'skip', `Automated verification is not implemented for provider "${appData.provider}"`));
        return finalize(appData, authMethod, steps, account);
    }
    return verifyInteractive(appData, steps);
}

module.exports = { verifyOAuth2App };

// Exported for tests only; describeResponse reflects remote content into the verify report.
module.exports.__test__ = { describeResponse, metadataServerHint, MAX_REMOTE_DETAIL_LENGTH };
