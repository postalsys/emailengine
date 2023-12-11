'use strict';

const packageData = require('../../package.json');
const { formatPartialSecretKey, pfStructuredClone } = require('../tools');

const { FETCH_TIMEOUT } = require('../consts');

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const OUTLOOK_SCOPES = ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send', 'offline_access', 'openid', 'profile'];

const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Invalid client secret is provided|The provided client secret keys are expired/i;

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    if (error === 'invalid_client' && /AADSTS7000222/i.test(description)) {
        return {
            message: 'OAuth Client Secret for Outlook is either expired or not yet valid'
        };
    }

    if (error === 'invalid_client' && /AADSTS700016/i.test(description)) {
        return {
            message: 'OAuth Application ID for Outlook is invalid'
        };
    }

    if (error === 'invalid_client' && /AADSTS7000215/i.test(description)) {
        return {
            message: 'OAuth Client Secret for Outlook is invalid'
        };
    }

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

    let data = pfStructuredClone(responseObj);
    for (let key of ['access_token', 'refresh_token']) {
        if (data[key]) {
            data[key] = logRaw ? data[key] : formatPartialSecretKey(data[key]);
        }
    }

    return data;
};

class OutlookOauth {
    constructor(opts) {
        this.scopes = [].concat(opts.scopes || OUTLOOK_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.authority = opts.authority;
        this.redirectUrl = opts.redirectUrl;

        this.logRaw = opts.logRaw;
        this.logger = opts.logger;

        this.provider = 'outlook';

        this.setFlag = opts.setFlag;
    }

    generateAuthUrl(opts) {
        opts = opts || {};

        const url = new URL(`https://login.microsoftonline.com/${this.authority}/oauth2/v2.0/authorize`);

        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('redirect_uri', this.redirectUrl);
        url.searchParams.set('response_mode', 'query');
        url.searchParams.set('client_info', '1');
        url.searchParams.set('prompt', 'select_account');

        if (opts.email) {
            url.searchParams.set('login_hint', opts.email);
        }

        url.searchParams.set('scope', this.scopes.join(' '));

        if (opts.state) {
            url.searchParams.set('state', opts.state);
        }

        return url.href;
    }

    getTokenRequest(opts) {
        opts = opts || {};

        if (!opts.code) {
            throw new Error('Authorization code not provided');
        }

        const url = new URL(`https://login.microsoftonline.com/${this.authority}/oauth2/v2.0/token`);

        url.searchParams.set('code', opts.code);

        url.searchParams.set('client_id', this.clientId);

        url.searchParams.set('scope', this.scopes.join(' '));

        url.searchParams.set('redirect_uri', this.redirectUrl);
        url.searchParams.set('grant_type', 'authorization_code');
        url.searchParams.set('client_secret', this.clientSecret);

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
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: tokenRequest.body,
            dispatcher: fetchAgent
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

                if (EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.tokenRequest.response.error_description)) {
                    // key might have been invalidated or renewed
                    err.tokenRequest.clientSecret = formatPartialSecretKey(this.clientSecret);
                }

                let flag = checkForFlags(err.tokenRequest.response);
                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
                }
            } catch (err) {
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

        const url = new URL(`https://login.microsoftonline.com/${this.authority}/oauth2/v2.0/token`);

        url.searchParams.set('refresh_token', opts.refreshToken);

        url.searchParams.set('client_id', this.clientId);

        url.searchParams.set('scope', this.scopes.join(' '));

        url.searchParams.set('redirect_uri', this.redirectUrl);
        url.searchParams.set('grant_type', 'refresh_token');
        url.searchParams.set('client_secret', this.clientSecret);

        let requestUrl = url.origin + url.pathname;
        let method = 'post';

        let res = await fetchCmd(requestUrl, {
            method: 'post',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: url.searchParams,
            dispatcher: fetchAgent
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
                request: formatFetchBody(url.searchParams, this.logRaw),
                response: formatFetchResponse(responseJson, this.logRaw)
            });
        }

        if (!res.ok) {
            let err = new Error('Token request failed');
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

                if (EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.tokenRequest.response.error_description)) {
                    // key might have been invalidated or renewed
                    err.tokenRequest.clientSecret = formatPartialSecretKey(this.clientSecret);
                }

                let flag = checkForFlags(err.tokenRequest.response);

                if (flag) {
                    await this.setFlag(flag);
                }
            } catch (err) {
                // ignore
            }
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        return responseJson;
    }

    async request(accessToken, url, method, payload) {
        method = method || 'get';
        let reqData = {
            method,
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            dispatcher: fetchAgent
        };

        if (payload) {
            reqData.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            reqData.body = payload;
        }

        let res = await fetchCmd(url, reqData);

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = { url, method, provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes };
            try {
                err.oauthRequest.response = await res.json();

                if (EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.oauthRequest.response.error_description)) {
                    // key might have been invalidated or renewed
                    err.oauthRequest.clientSecret = formatPartialSecretKey(this.clientSecret);
                }

                let flag = checkForFlags(err.oauthRequest.response);
                if (flag) {
                    await this.setFlag(flag);
                }
            } catch (err) {
                // ignore
            }
            throw err;
        }

        // clear potential auth flag
        await this.setFlag();

        return await res.json();
    }
}

module.exports.OutlookOauth = OutlookOauth;
module.exports.OUTLOOK_SCOPES = OUTLOOK_SCOPES;
