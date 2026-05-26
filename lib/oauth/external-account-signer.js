'use strict';

const fs = require('fs');
const { fetch: undiciFetch } = require('undici');
const packageData = require('../../package.json');
const { httpAgent } = require('../tools');
const { makeError, validateConfig, extractFromFormat } = require('./external-account-config');

const STS_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const REQUESTED_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const DEFAULT_IAM_CREDENTIALS_BASE_URL = 'https://iamcredentials.googleapis.com';
const SIGN_JWT_URL_TEMPLATE = '/v1/projects/-/serviceAccounts/{email}:signJwt';
const TOKEN_EXPIRY_SKEW_MS = 60 * 1000;
const DEFAULT_FEDERATED_TOKEN_TTL_MS = 3600 * 1000;
const USER_AGENT = `${packageData.name}/${packageData.version} (+${packageData.homepage})`;

class ExternalAccountSigner {
    constructor(opts) {
        opts = opts || {};

        let { targetServiceAccountEmail } = validateConfig(opts.config);

        this.config = opts.config;
        // The service account whose Google-managed key signs the JWT. Exposed so
        // callers can keep the JWT `iss` claim consistent with the signing identity.
        this.serviceAccountEmail = targetServiceAccountEmail;
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

    // Exchange the subject token for a Google federated access token. The
    // federated identity (the workload principal) carries the cloud-platform
    // scope and, given roles/iam.serviceAccountTokenCreator on the target
    // service account, may call signJwt directly. Returns the access token and
    // its absolute expiry so it can be cached and reused across signJwt calls.
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

        let expiresInSec = responseJson && Number(responseJson.expires_in);
        let ttlMs = Number.isFinite(expiresInSec) && expiresInSec > 0 ? expiresInSec * 1000 : DEFAULT_FEDERATED_TOKEN_TTL_MS;

        return { accessToken: token, expiresAtMs: this._now() + ttlMs };
    }

    async _ensureFederatedToken() {
        if (this._cachedToken && this._now() + TOKEN_EXPIRY_SKEW_MS < this._cachedTokenExpiresAt) {
            return this._cachedToken;
        }

        // Deduplicate concurrent refreshes: when many accounts hit a cold cache
        // at once, share the single in-flight exchange rather than stampeding STS
        // with redundant token exchanges.
        if (!this._pendingRefresh) {
            this._pendingRefresh = (async () => {
                try {
                    let subjectToken = await this._readSubjectToken();
                    let { accessToken, expiresAtMs } = await this._exchangeAtSts(subjectToken);
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

    async _callSignJwt(accessToken, jwtPayload) {
        let url = this._iamCredentialsBaseUrl + SIGN_JWT_URL_TEMPLATE.replace('{email}', encodeURIComponent(this.serviceAccountEmail));
        let res;
        let responseJson;
        try {
            res = await this._fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                    Authorization: `Bearer ${accessToken}`,
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
        let accessToken = await this._ensureFederatedToken();
        return this._callSignJwt(accessToken, jwtPayload);
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
            targetServiceAccountEmail: this.serviceAccountEmail
        });
    }

    // Test-only: clear the cached federated token.
    _clearCache() {
        this._cachedToken = null;
        this._cachedTokenExpiresAt = 0;
        this._pendingRefresh = null;
    }
}

module.exports.ExternalAccountSigner = ExternalAccountSigner;
module.exports.__test__ = { validateConfig, extractFromFormat, makeError };
