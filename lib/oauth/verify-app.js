'use strict';

// OAuth2 app "Verify setup" diagnostic. Runs the real authentication chain for a
// configured OAuth2 app step by step against the provider and returns a structured
// result so the admin can see exactly which step fails and how to fix it. Reuses the
// existing OAuth clients and the coded errors they already throw - no provider logic
// is reimplemented here.

const { ImapFlow } = require('imapflow');
const { oauth2Apps, oauth2ProviderData, SERVICE_ACCOUNT_PROVIDERS } = require('../oauth2-apps');
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

function describeResponse(err) {
    let resp = err && (err.response || (err.tokenRequest && err.tokenRequest.response));
    if (resp && typeof resp === 'object') {
        // Google API errors nest the detail under error.message; OAuth/STS errors
        // use top-level string error/error_description fields.
        if (resp.error && typeof resp.error === 'object' && resp.error.message) {
            return resp.error.message;
        }
        let parts = [resp.error, resp.error_description].filter(Boolean);
        if (parts.length) {
            return parts.join(': ');
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
    let client = new ImapFlow({
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
    let authMethod = appData.authMethod === 'externalAccount' ? 'externalAccount' : 'serviceKey';

    // Step 1 - configuration. getClient builds the signer, which validates the external
    // account JSON and the service-account-email match (or fails if creds are missing).
    let client;
    try {
        client = await oauth2Apps.getClient(appData.id, { setFlag: async () => {} });
        steps.push(
            mkStep(
                'config',
                'Configuration',
                'ok',
                authMethod === 'externalAccount' ? 'External account configuration is valid' : 'Service account key is present'
            )
        );
    } catch (err) {
        steps.push(
            mkStep('config', 'Configuration', 'fail', err.message, {
                hint: 'Complete the service account credentials in the app settings (service client, email and key/external account configuration).'
            })
        );
        return finalize(appData, authMethod, steps, account);
    }

    // Step 2 - signing chain (no mailbox/email needed; signJwt signs an arbitrary payload).
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

    // Pub/Sub apps authenticate as the service account itself (principal mode), not by
    // impersonating a user, so they need no mailbox address and no domain-wide delegation.
    if (appData.baseScopes === 'pubsub') {
        try {
            let resp = await client.refreshToken({ isPrincipal: true });
            if (!resp || !resp.access_token) {
                throw Object.assign(new Error('No access token returned by the token endpoint'), { code: 'ETokenRefresh' });
            }
            steps.push(mkStep('token', 'Service account token', 'ok', 'App-only access token obtained for the service account'));
        } catch (err) {
            let flag = err.tokenRequest && err.tokenRequest.flag;
            let hint =
                flag && flag.code === 'INVALID_SERVICE_CLIENT_EMAIL'
                    ? 'The service account is invalid or unrecognized. Verify the service account email and client ID in the app settings.'
                    : 'The service account could not obtain its own access token. Verify the service account email and client ID in the app settings.';
            steps.push(mkStep('token', 'Service account token', 'fail', describeResponse(err) || err.message, { hint }));
        }
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
