'use strict';

const fs = require('fs');
const { fetch: undiciFetch } = require('undici');
const packageData = require('../../package.json');
const { httpAgent } = require('../tools');

const STS_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const REQUESTED_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ACCEPTED_SUBJECT_TOKEN_TYPES = new Set(['urn:ietf:params:oauth:token-type:jwt', 'urn:ietf:params:oauth:token-type:id_token']);
const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const DEFAULT_IAM_CREDENTIALS_BASE_URL = 'https://iamcredentials.googleapis.com';
const SIGN_JWT_URL_TEMPLATE = '/v1/projects/-/serviceAccounts/{email}:signJwt';
const IMPERSONATION_URL_RE = /\/v1\/projects\/-\/serviceAccounts\/([^/]+):generateAccessToken$/;
const TOKEN_EXPIRY_SKEW_MS = 60 * 1000;
const USER_AGENT = `${packageData.name}/${packageData.version} (+${packageData.homepage})`;

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

function validateConfig(config) {
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

class ExternalAccountSigner {
    constructor(opts) {
        opts = opts || {};

        let { targetServiceAccountEmail } = validateConfig(opts.config);

        this.config = opts.config;
        this.targetServiceAccountEmail = targetServiceAccountEmail;
        this.logger = opts.logger || null;
        this.logRaw = !!opts.logRaw;

        // Injection points for tests; production code uses undici/fs/Date as defaults.
        this._fetch = opts.fetchImpl || undiciFetch;
        this._readFile = opts.readFileImpl || fs.promises.readFile;
        this._now = opts.nowImpl || (() => Date.now());

        // Allow overriding the IAM Credentials base URL so integration tests
        // (and unusual forward-proxy deployments) can redirect signJwt traffic.
        this._iamCredentialsBaseUrl = (opts.iamCredentialsBaseUrl || DEFAULT_IAM_CREDENTIALS_BASE_URL).replace(/\/+$/, '');

        this._cachedToken = null;
        this._cachedTokenExpiresAt = 0;
        this._pendingRefresh = null;
    }

    describeCredentialSource() {
        let source = this.config.credential_source;
        if (source.file) {
            return { type: 'file', location: source.file };
        }
        return { type: 'url', location: source.url };
    }

    async _readSubjectToken() {
        let source = this.config.credential_source;
        let format = source.format || { type: 'text' };

        if (source.file) {
            let rawText;
            try {
                rawText = await this._readFile(source.file, 'utf8');
            } catch (err) {
                throw makeError(`Failed to read subject token file ${source.file}: ${err.message}`, 'ESubjectTokenRead', null, { cause: err });
            }
            return extractFromFormat(rawText, format);
        }

        let headers = { 'User-Agent': USER_AGENT };
        if (source.headers && typeof source.headers === 'object') {
            for (let key of Object.keys(source.headers)) {
                headers[key] = source.headers[key];
            }
        }

        let res;
        try {
            res = await this._fetch(source.url, {
                method: 'GET',
                headers,
                dispatcher: httpAgent.retry
            });
        } catch (err) {
            throw makeError(`Failed to fetch subject token from ${source.url}: ${err.message}`, 'ESubjectTokenRead', null, { cause: err });
        }

        let body = await res.text();

        this._log('readSubjectToken', 'GET', source.url, res.ok, res.status);

        if (!res.ok) {
            throw makeError(`Subject token endpoint ${source.url} returned HTTP ${res.status}`, 'ESubjectTokenRead', res.status, {
                responseText: body.slice(0, 1024)
            });
        }

        return extractFromFormat(body, format);
    }

    async _exchangeAtSts(subjectToken) {
        let body = new URLSearchParams({
            grant_type: STS_GRANT_TYPE,
            audience: this.config.audience,
            scope: CLOUD_PLATFORM_SCOPE,
            requested_token_type: REQUESTED_TOKEN_TYPE,
            subject_token_type: this.config.subject_token_type,
            subject_token: subjectToken
        });

        let res;
        let responseJson;
        try {
            res = await this._fetch(this.config.token_url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Accept: 'application/json',
                    'User-Agent': USER_AGENT
                },
                body: body.toString(),
                dispatcher: httpAgent.retry
            });
            responseJson = await res.json().catch(() => null);
        } catch (err) {
            throw makeError(`STS token exchange request failed: ${err.message}`, 'ESTSExchange', null, { cause: err });
        }

        this._log('exchangeAtSts', 'POST', this.config.token_url, res.ok, res.status);

        if (!res.ok) {
            throw makeError(`STS token exchange at ${this.config.token_url} returned HTTP ${res.status}`, 'ESTSExchange', res.status, {
                response: responseJson || null
            });
        }

        let token = responseJson && responseJson.access_token;
        if (typeof token !== 'string' || !token) {
            throw makeError('STS response did not include an access_token', 'ESTSExchange', res.status, { response: responseJson || null });
        }
        return token;
    }

    async _impersonateServiceAccount(federatedToken) {
        let res;
        let responseJson;
        try {
            res = await this._fetch(this.config.service_account_impersonation_url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                    Authorization: `Bearer ${federatedToken}`,
                    'User-Agent': USER_AGENT
                },
                body: JSON.stringify({ scope: [CLOUD_PLATFORM_SCOPE] }),
                dispatcher: httpAgent.retry
            });
            responseJson = await res.json().catch(() => null);
        } catch (err) {
            throw makeError(`Service account impersonation request failed: ${err.message}`, 'EImpersonate', null, { cause: err });
        }

        this._log('impersonateServiceAccount', 'POST', this.config.service_account_impersonation_url, res.ok, res.status);

        if (!res.ok) {
            throw makeError(`Service account impersonation returned HTTP ${res.status}`, 'EImpersonate', res.status, {
                response: responseJson || null
            });
        }

        let accessToken = responseJson && responseJson.accessToken;
        let expireTime = responseJson && responseJson.expireTime;
        if (typeof accessToken !== 'string' || !accessToken) {
            throw makeError('Impersonation response did not include accessToken', 'EImpersonate', res.status, { response: responseJson || null });
        }

        let expiresAtMs;
        if (typeof expireTime === 'string') {
            let parsed = Date.parse(expireTime);
            expiresAtMs = Number.isFinite(parsed) ? parsed : this._now() + 3600 * 1000;
        } else {
            expiresAtMs = this._now() + 3600 * 1000;
        }

        return { accessToken, expiresAtMs };
    }

    async _ensureImpersonatedToken() {
        if (this._cachedToken && this._now() + TOKEN_EXPIRY_SKEW_MS < this._cachedTokenExpiresAt) {
            return this._cachedToken;
        }

        // Deduplicate concurrent refreshes: when many accounts hit a cold cache
        // at once, share the single in-flight chain rather than stampeding STS
        // and signJwt with redundant exchanges.
        if (!this._pendingRefresh) {
            this._pendingRefresh = (async () => {
                try {
                    let subjectToken = await this._readSubjectToken();
                    let federatedToken = await this._exchangeAtSts(subjectToken);
                    let { accessToken, expiresAtMs } = await this._impersonateServiceAccount(federatedToken);
                    this._cachedToken = accessToken;
                    this._cachedTokenExpiresAt = expiresAtMs;
                    return accessToken;
                } finally {
                    this._pendingRefresh = null;
                }
            })();
        }

        return this._pendingRefresh;
    }

    async _callSignJwt(impersonatedToken, jwtPayload) {
        let url = this._iamCredentialsBaseUrl + SIGN_JWT_URL_TEMPLATE.replace('{email}', encodeURIComponent(this.targetServiceAccountEmail));
        let res;
        let responseJson;
        try {
            res = await this._fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                    Authorization: `Bearer ${impersonatedToken}`,
                    'User-Agent': USER_AGENT
                },
                body: JSON.stringify({ payload: JSON.stringify(jwtPayload) }),
                dispatcher: httpAgent.retry
            });
            responseJson = await res.json().catch(() => null);
        } catch (err) {
            throw makeError(`signJwt request failed: ${err.message}`, 'ESignJwt', null, { cause: err });
        }

        this._log('callSignJwt', 'POST', url, res.ok, res.status);

        if (!res.ok) {
            let retryAfter = null;
            if (res.status === 429) {
                let header = res.headers.get('retry-after');
                if (header) {
                    let parsed = parseInt(header, 10);
                    retryAfter = isNaN(parsed) ? null : parsed;
                }
            }
            throw makeError(`signJwt returned HTTP ${res.status}`, 'ESignJwt', res.status, {
                response: responseJson || null,
                retryAfter
            });
        }

        let signedJwt = responseJson && responseJson.signedJwt;
        if (typeof signedJwt !== 'string' || !signedJwt) {
            throw makeError('signJwt response did not include signedJwt', 'ESignJwt', res.status, { response: responseJson || null });
        }
        return signedJwt;
    }

    /**
     * Sign a JWT payload using the configured external account identity.
     * Returns the compact JWT string suitable for the `assertion` parameter
     * in a jwt-bearer grant exchange.
     */
    async sign(jwtPayload) {
        let impersonatedToken = await this._ensureImpersonatedToken();
        return this._callSignJwt(impersonatedToken, jwtPayload);
    }

    _log(fn, method, url, ok, status) {
        if (!this.logger) {
            return;
        }
        this.logger.info({
            msg: 'External account signer request',
            action: 'externalAccountFetch',
            fn,
            method,
            url,
            success: !!ok,
            status,
            credentialSource: this.describeCredentialSource().type,
            targetServiceAccountEmail: this.targetServiceAccountEmail
        });
    }

    // Test-only: clear the cached impersonated token.
    _clearCache() {
        this._cachedToken = null;
        this._cachedTokenExpiresAt = 0;
        this._pendingRefresh = null;
    }
}

module.exports.ExternalAccountSigner = ExternalAccountSigner;
module.exports.__test__ = { validateConfig, extractFromFormat, makeError, IMPERSONATION_URL_RE };
