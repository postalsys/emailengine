'use strict';

const { USER_AGENT, encodeBody, timedFetch, handleFailedResponse, parseJsonResponse } = require('./http-request');
const { fetchTokenRequest } = require('./token-fetch');
const { formatPartialSecretKey, formatOAuthRequestBody, formatOAuthResponse, httpAgent, formatTokenError } = require('../tools');

const MAIL_RU_SCOPES = ['userinfo', 'mail.imap'];

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    // TODO: handle errors
    // let { error, error_description: description } = err;

    return false;
};

class MailRuOauth {
    constructor(opts) {
        // The network route of the account this client acts for (see getAccountHttpRoute()). Every
        // token and API request it makes takes that route; null for an app-level client.
        this.route = opts.route || null;

        this.scopes = [].concat(opts.scopes || MAIL_RU_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.redirectUrl = opts.redirectUrl;

        this.logger = opts.logger;

        this.provider = 'mailRu';

        this.setFlag = opts.setFlag;
    }

    generateAuthUrl(opts) {
        opts = opts || {};

        const url = new URL(`https://oauth.mail.ru/login`);
        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', this.scopes.join(' '));
        url.searchParams.set('redirect_uri', this.redirectUrl);

        if (opts.state) {
            url.searchParams.set('state', opts.state);
        }

        url.searchParams.set('prompt_force', '1');

        return url.href;
    }

    getTokenRequest(opts) {
        opts = opts || {};

        if (!opts.code) {
            throw new Error('Authorization code not provided');
        }

        const url = new URL(`https://oauth.mail.ru/token`);

        url.searchParams.set('code', opts.code);
        url.searchParams.set('grant_type', 'authorization_code');
        url.searchParams.set('redirect_uri', this.redirectUrl);

        return {
            url: url.origin + url.pathname,
            body: url.searchParams.toString()
        };
    }

    async getToken(code) {
        let tokenRequest = this.getTokenRequest({
            code
        });

        let requestUrl = tokenRequest.url;
        let method = 'post';

        let res = await fetchTokenRequest(
            tokenRequest.url,
            {
                method,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': USER_AGENT,
                    Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`
                },
                body: tokenRequest.body
            },
            { grant: 'authorization_code', provider: this.provider, clientId: this.clientId },
            this.route
        );

        let responseJson;
        try {
            responseJson = await res.json();
        } catch (err) {
            if (this.logger) {
                this.logger.error({ msg: 'Failed to parse JSON response', url: requestUrl, status: res.status, err });
            }
        }

        if (this.logger) {
            this.logger.info({
                msg: 'OAuth2 authentication request',
                action: 'oauth2Fetch',
                fn: 'getToken',
                method,
                url: requestUrl,
                success: !!res.ok,
                status: res.status,
                request: formatOAuthRequestBody(tokenRequest.body),
                response: formatOAuthResponse(responseJson)
            });
        }

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.code = 'ETokenRefresh';

            err.tokenRequest = {
                url: requestUrl,
                method,
                grant: 'authorization_code',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                scopes: this.scopes,
                code: formatPartialSecretKey(code)
            };
            try {
                err.tokenRequest.response = responseJson || { error: 'Failed to parse response' };

                let flag = checkForFlags(err.tokenRequest.response);
                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
                }
            } catch (e) {
                // ignore
            }
            err.message = formatTokenError(this.provider, err.tokenRequest);
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        return responseJson;
    }

    async refreshToken(opts) {
        opts = opts || {};
        if (!opts.refreshToken) {
            throw new Error('Refresh token not provided');
        }

        const url = new URL(`https://oauth.mail.ru/token`);

        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('grant_type', 'refresh_token');
        url.searchParams.set('refresh_token', opts.refreshToken);

        let requestUrl = url.origin + url.pathname;
        let method = 'post';

        const bodyString = url.searchParams.toString();
        let res = await fetchTokenRequest(
            requestUrl,
            {
                method,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': USER_AGENT
                },
                body: bodyString
            },
            { grant: 'refresh_token', provider: this.provider, clientId: this.clientId },
            this.route
        );

        let responseJson;
        try {
            responseJson = await res.json();
        } catch (err) {
            if (this.logger) {
                this.logger.error({ msg: 'Failed to parse JSON response', url: requestUrl, status: res.status, err });
            }
        }

        if (this.logger) {
            this.logger.info({
                msg: 'OAuth2 authentication request',
                action: 'oauth2Fetch',
                fn: 'refreshToken',
                method,
                url: requestUrl,
                success: !!res.ok,
                status: res.status,
                request: formatOAuthRequestBody(url.searchParams),
                response: formatOAuthResponse(responseJson)
            });
        }

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.code = 'ETokenRefresh';

            err.tokenRequest = {
                url: requestUrl,
                method,
                grant: 'refresh_token',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                scopes: this.scopes
            };
            try {
                err.tokenRequest.response = responseJson || { error: 'Failed to parse response' };

                let flag = checkForFlags(err.tokenRequest.response);

                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
                }
            } catch (e) {
                // ignore
            }
            err.message = formatTokenError(this.provider, err.tokenRequest);
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        return responseJson;
    }

    /**
     * The fields that describe an API request in errors
     * @param {string} url - Request URL, without the access token
     * @param {string} method - Request method
     * @param {Response} res - The answer
     * @returns {Object}
     */
    logContext(url, method, res) {
        return { url, method, provider: this.provider, status: res.status, clientId: this.clientId };
    }

    async request(accessToken, url, method, payload, options) {
        method = method || 'get';
        let reqData = {
            method,
            headers: {
                'User-Agent': USER_AGENT
            },
            dispatcher: httpAgent.forRoute(this.route).retry
        };

        if (payload) {
            // A JSON body is a string rather than a Buffer, so a retry does not meet a detached ArrayBuffer
            encodeBody(reqData, payload, options?.contentType);
            if (Buffer.isBuffer(payload) && payload.length > 0) {
                // Non-empty buffers use non-retry dispatcher to prevent ArrayBuffer detachment
                reqData.dispatcher = httpAgent.forRoute(this.route).fetch;
            }
        }

        const requestUrl = new URL(url);
        requestUrl.searchParams.set('access_token', accessToken);

        let { res } = await timedFetch(requestUrl.href, reqData);

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = Object.assign(this.logContext(url, method, res), { scopes: this.scopes });
            await handleFailedResponse(this, res, err, { checkForFlags, recordFlag: true });
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        // Parse JSON response with handling for empty or invalid responses
        let responseText = await res.text();
        return parseJsonResponse(responseText, extra => Object.assign(this.logContext(url, method, res), extra));
    }
}

module.exports.MailRuOauth = MailRuOauth;
module.exports.MAIL_RU_SCOPES = MAIL_RU_SCOPES;
