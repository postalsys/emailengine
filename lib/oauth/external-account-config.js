'use strict';

// Pure configuration helpers for Google external_account (Workload Identity
// Federation) credentials. This module intentionally has NO heavy dependencies
// (no Redis, no undici, no settings) so it can be imported from request
// validation (lib/schemas.js) as well as the runtime signer without dragging in
// the database layer.

const ACCEPTED_SUBJECT_TOKEN_TYPES = new Set(['urn:ietf:params:oauth:token-type:jwt', 'urn:ietf:params:oauth:token-type:id_token']);
const IMPERSONATION_URL_RE = /\/v1\/projects\/-\/serviceAccounts\/([^/]+):generateAccessToken$/;

// Google STS is the only endpoint allowed to receive the subject token.
//
// The subject token is read from this host - a projected OIDC token file, or a metadata endpoint -
// and POSTed verbatim as the `subject_token` form field. A caller-chosen token_url therefore turns
// the credential source into an exfiltration channel: point it at your own server and whatever the
// configured file contains is delivered to you, and the response comes back in-band because
// /v1/oauth2/{app}/verify reports the endpoint's error_description. Pinning the host closes that
// channel, so the credential source can only ever be delivered to Google.
const STS_HOST = 'sts.googleapis.com';

// Regional STS endpoints, e.g. sts.europe-west1.rep.googleapis.com
const REGIONAL_STS_HOST_RE = /^sts\.[a-z0-9-]+\.rep\.googleapis\.com$/;

// Validates token_url against the Google STS endpoints. `allowedTokenHosts` is an injection point
// for tests that stand up a local STS double; production callers never pass it, which is the same
// arrangement as the signer's iamCredentialsBaseUrl option.
function assertTokenUrl(rawUrl, allowedTokenHosts) {
    let url;
    try {
        url = new URL(rawUrl);
    } catch (err) {
        throw makeError('External account token_url is not a valid URL', 'EExternalAccountConfig');
    }

    if (allowedTokenHosts && allowedTokenHosts.includes(url.hostname)) {
        return;
    }

    if (url.protocol !== 'https:' || !(url.hostname === STS_HOST || REGIONAL_STS_HOST_RE.test(url.hostname))) {
        throw makeError(
            `External account token_url must be a Google STS endpoint (https://${STS_HOST}/v1/token), got ${JSON.stringify(url.protocol + '//' + url.hostname)}`,
            'EExternalAccountConfig'
        );
    }
}

function makeError(message, code, statusCode, extra) {
    let err = new Error(message);
    err.code = code;
    if (statusCode) {
        err.statusCode = statusCode;
    }
    if (extra && typeof extra === 'object') {
        Object.assign(err, extra);
    }
    return err;
}

// Validates the structural shape of an external_account credential config and
// returns the derived target service account email. Throws an error tagged with
// code 'EExternalAccountConfig' on any problem so callers can surface a clean
// validation message instead of a late runtime failure.
function validateConfig(config, opts) {
    const { allowedTokenHosts } = opts || {};

    if (!config || typeof config !== 'object') {
        throw makeError('External account configuration must be a JSON object', 'EExternalAccountConfig');
    }

    if (config.type !== 'external_account') {
        throw makeError(`External account configuration must have type "external_account" (got ${JSON.stringify(config.type)})`, 'EExternalAccountConfig');
    }

    for (let key of ['audience', 'subject_token_type', 'token_url', 'service_account_impersonation_url']) {
        let value = config[key];
        if (typeof value !== 'string' || !value) {
            throw makeError(`External account configuration is missing required string field "${key}"`, 'EExternalAccountConfig');
        }
    }

    assertTokenUrl(config.token_url, allowedTokenHosts);

    if (!ACCEPTED_SUBJECT_TOKEN_TYPES.has(config.subject_token_type)) {
        throw makeError(
            `External account subject_token_type ${JSON.stringify(config.subject_token_type)} is not supported. ` +
                `Supported types: ${Array.from(ACCEPTED_SUBJECT_TOKEN_TYPES).join(', ')}.`,
            'EExternalAccountConfig'
        );
    }

    let impersonationMatch = IMPERSONATION_URL_RE.exec(config.service_account_impersonation_url);
    if (!impersonationMatch) {
        throw makeError(
            'External account service_account_impersonation_url must point at iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{EMAIL}:generateAccessToken',
            'EExternalAccountConfig'
        );
    }
    let targetServiceAccountEmail = decodeURIComponent(impersonationMatch[1]);

    let source = config.credential_source;
    if (!source || typeof source !== 'object') {
        throw makeError('External account configuration is missing credential_source', 'EExternalAccountConfig');
    }

    let hasFile = typeof source.file === 'string' && source.file;
    let hasUrl = typeof source.url === 'string' && source.url;
    let hasExecutable = source.executable && typeof source.executable === 'object';
    let hasEnvironmentId = typeof source.environment_id === 'string' && source.environment_id;

    if (hasExecutable) {
        throw makeError('credential_source.executable is not supported by EmailEngine', 'EExternalAccountConfig');
    }
    if (hasEnvironmentId) {
        throw makeError(
            `credential_source.environment_id (${source.environment_id}) is not supported by EmailEngine. Use a file or url credential source.`,
            'EExternalAccountConfig'
        );
    }
    if (hasFile && hasUrl) {
        throw makeError('credential_source must specify either "file" or "url", not both', 'EExternalAccountConfig');
    }
    if (!hasFile && !hasUrl) {
        throw makeError('credential_source must specify a "file" or "url" field', 'EExternalAccountConfig');
    }

    if (source.format && typeof source.format === 'object') {
        let formatType = source.format.type;
        if (formatType && formatType !== 'text' && formatType !== 'json') {
            throw makeError(`credential_source.format.type must be "text" or "json" (got ${JSON.stringify(formatType)})`, 'EExternalAccountConfig');
        }
        if (formatType === 'json' && (typeof source.format.subject_token_field_name !== 'string' || !source.format.subject_token_field_name)) {
            throw makeError('credential_source.format.subject_token_field_name is required when format.type is "json"', 'EExternalAccountConfig');
        }
    }

    return { targetServiceAccountEmail };
}

// Extracts the subject token string from a raw credential-source payload,
// honouring the optional text/json format descriptor.
function extractFromFormat(rawText, format) {
    let formatType = (format && format.type) || 'text';
    if (formatType === 'text') {
        let trimmed = rawText.trim();
        if (!trimmed) {
            throw makeError('Subject token source returned an empty value', 'ESubjectTokenRead');
        }
        return trimmed;
    }

    let parsed;
    try {
        parsed = JSON.parse(rawText);
    } catch (err) {
        throw makeError(`Subject token source did not return valid JSON: ${err.message}`, 'ESubjectTokenRead');
    }
    let field = format.subject_token_field_name;
    let value = parsed && typeof parsed === 'object' ? parsed[field] : undefined;
    if (typeof value !== 'string' || !value.trim()) {
        throw makeError(`Subject token JSON did not contain a non-empty string at field "${field}"`, 'ESubjectTokenRead');
    }
    return value.trim();
}

module.exports = {
    ACCEPTED_SUBJECT_TOKEN_TYPES,
    IMPERSONATION_URL_RE,
    makeError,
    validateConfig,
    extractFromFormat
};
