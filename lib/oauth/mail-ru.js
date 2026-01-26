'use strict';

const packageData = require('../../package.json');
const { fetch: fetchCmd } = require('undici');
const { formatPartialSecretKey, structuredClone, retryAgent } = require('../tools');

const MAIL_RU_SCOPES = ['userinfo', 'mail.imap'];

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    // TODO: handle errors
    // let { error, error_description: description } = err;

    return false;
};

const formatFetchBody = (searchParams, logRaw) => {
    let data = Object.fromEntries(searchParams);

    for (let key of ['refresh_token', 'client_secret']) {
        if (data[key]) {
            data[key] = logRaw ? data[key] : formatPartialSecretKey(data[key]);
        }
    }

    return data;
};

const formatFetchResponse = (responseObj, logRaw) => {
    if (!responseObj || typeof responseObj !== 'object') {
        return responseObj;
    }

    let data = structuredClone(responseObj);
    for (let key of ['access_token', 'refresh_token']) {
        if (data[key]) {
            data[key] = logRaw ? data[key] : formatPartialSecretKey(data[key]);
        }
    }

    return data;
};

class MailRuOauth {
    constructor(opts) {
        this.scopes = [].concat(opts.scopes || MAIL_RU_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.redirectUrl = opts.redirectUrl;

        this.logRaw = opts.logRaw;
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
            body: url.searchParams
        };
    }

    async getToken(code) {
        let tokenRequest = this.getTokenRequest({
            code
        });

        let requestUrl = tokenRequest.url;
        let method = 'post';

        let res = await fetchCmd(tokenRequest.url, {
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
                Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`
            },
            body: tokenRequest.body,
            dispatcher: retryAgent
        });

        let responseJson;
        try {
            responseJson = await res.json();
        } catch (err) {
            if (this.logger) {
                this.logger.error({ msg: 'Failed to retrieve JSON', err });
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
                request: formatFetchBody(tokenRequest.body, this.logRaw),
                response: formatFetchResponse(responseJson, this.logRaw)
            });
        }

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.code = 'ETokenRefresh';

            err.tokenRequest = {
                url: requestUrl,
                method,
                authority: this.authority,
                grant: 'authorization_code',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                scopes: this.scopes,
                code
            };
            try {
                err.tokenRequest.response = responseJson;

                let flag = checkForFlags(err.tokenRequest.response);
                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
                }
            } catch (e) {
                // ignore
            }
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

        let res = await fetchCmd(requestUrl, {
            method: 'post',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: url.searchParams,
            dispatcher: retryAgent
        });

        let responseJson;
        try {
            responseJson = await res.json();
        } catch (err) {
            if (this.logger) {
                this.logger.error({ msg: 'Failed to retrieve JSON', err });
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
                request: formatFetchBody(url.searchParams, this.logRaw),
                response: formatFetchResponse(responseJson, this.logRaw)
            });
        }

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.code = 'ETokenRefresh';

            err.tokenRequest = {
                url: requestUrl,
                method,
                authority: this.authority,
                grant: 'refresh_token',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                scopes: this.scopes
            };
            try {
                err.tokenRequest.response = responseJson;

                let flag = checkForFlags(err.tokenRequest.response);

                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
                }
            } catch (e) {
                // ignore
            }
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        return responseJson;
    }

    async request(accessToken, url, method, payload, options) {
        method = method || 'get';
        let reqData = {
            method,
            headers: {
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            dispatcher: retryAgent
        };

        if (payload) {
            if (!Buffer.isBuffer(payload)) {
                reqData.headers.Accept = 'application/json';
                reqData.headers['Content-Type'] = options?.contentType || 'application/json';
                // Use string body instead of Buffer to avoid ArrayBuffer detachment on retry
                reqData.body = JSON.stringify(payload);
            } else {
                reqData.headers['Content-Type'] = options?.contentType || 'application/x-www-form-urlencoded';
                // Convert Buffer to string to avoid ArrayBuffer detachment on retry
                reqData.body = payload.toString('utf-8');
            }
        }

        const requestUrl = new URL(url);
        requestUrl.searchParams.set('access_token', accessToken);

        let res = await fetchCmd(requestUrl.href, reqData);

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = { url, method, provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes };
            try {
                err.oauthRequest.response = await res.json();

                let flag = checkForFlags(err.oauthRequest.response);
                if (flag) {
                    await this.setFlag(flag);
                    err.oauthRequest.flag = flag;
                }
            } catch (e) {
                // ignore
            }
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        // Parse JSON response with handling for empty or invalid responses
        let responseText = await res.text();
        if (!responseText || !responseText.trim()) {
            let err = new Error('Empty response from API');
            err.code = 'EmptyResponse';
            err.oauthRequest = { url, method, provider: this.provider, status: res.status, clientId: this.clientId };
            throw err;
        }

        try {
            return JSON.parse(responseText);
        } catch (parseErr) {
            let err = new Error('Invalid JSON response from API');
            err.code = 'InvalidJSON';
            err.oauthRequest = {
                url,
                method,
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                responseLength: responseText.length,
                responseStart: responseText.slice(0, 200),
                responseEnd: responseText.length > 200 ? responseText.slice(-200) : undefined
            };
            throw err;
        }
    }
}

module.exports.MailRuOauth = MailRuOauth;
module.exports.MAIL_RU_SCOPES = MAIL_RU_SCOPES;
