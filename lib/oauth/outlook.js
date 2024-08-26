'use strict';

const packageData = require('../../package.json');
const { formatPartialSecretKey, structuredClone } = require('../tools');

const { FETCH_TIMEOUT } = require('../consts');
const MAX_THROTTLING_RETRIES = 5;

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const outlookScopes = cloud => {
    switch (cloud) {
        case 'gcc-high':
            return {
                imap: ['https://outlook.office365.us/IMAP.AccessAsUser.All', 'https://outlook.office365.us/SMTP.Send', 'offline_access', 'openid', 'profile'],
                api: [
                    'https://graph.microsoft.us/Mail.ReadWrite',
                    'https://graph.microsoft.us/Mail.Send',
                    'offline_access',
                    'https://graph.microsoft.us/User.Read'
                ]
            };
        case 'dod':
            return {
                imap: ['https://outlook.office365.us/IMAP.AccessAsUser.All', 'https://outlook.office365.us/SMTP.Send', 'offline_access', 'openid', 'profile'],
                api: [
                    'https://dod-graph.microsoft.us/Mail.ReadWrite',
                    'https://dod-graph.microsoft.us/Mail.Send',
                    'offline_access',
                    'https://dod-graph.microsoft.us/User.Read'
                ]
            };
        case 'china':
            return {
                // no idea what the actual scope endpoints are for IMAP and SMTP
                imap: ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send', 'offline_access', 'openid', 'profile'],
                api: [
                    'https://microsoftgraph.chinacloudapi.cn/Mail.ReadWrite',
                    'https://microsoftgraph.chinacloudapi.cn/Mail.Send',
                    'offline_access',
                    'https://microsoftgraph.chinacloudapi.cn/User.Read'
                ]
            };
        case 'global':
        default:
            return {
                imap: ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send', 'offline_access', 'openid', 'profile'],
                api: [
                    'https://graph.microsoft.com/Mail.ReadWrite',
                    'https://graph.microsoft.com/Mail.Send',
                    'offline_access',
                    'https://graph.microsoft.com/User.Read'
                ]
            };
    }
};

const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Invalid client secret is provided|The provided client secret keys are expired/i;

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    if (error === 'invalid_client' && /AADSTS7000222/i.test(description)) {
        return {
            message: 'OAuth Client Secret for Outlook is either expired or not yet valid',
            description
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

const checkForUserFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    if (error === 'invalid_grant' && /user might have changed or reset their password/i.test(description)) {
        return {
            message: 'The user changed their email account password and OAuth2 grant was revoked. Ask the user to re-authenticate.',
            description
        };
    }

    if (error === 'invalid_grant') {
        return {
            message: 'Failed to renew the access token for the user',
            description
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

    let data = structuredClone(responseObj);
    for (let key of ['access_token', 'refresh_token']) {
        if (data[key]) {
            data[key] = logRaw ? data[key] : formatPartialSecretKey(data[key]);
        }
    }

    return data;
};

class OutlookOauth {
    constructor(opts) {
        this.cloud = opts.cloud || 'global';

        const defaultBaseScopes = (opts.baseScopes && outlookScopes(this.cloud)[opts.baseScopes]) || outlookScopes(this.cloud).imap;

        this.scopes = [].concat(opts.scopes || defaultBaseScopes);

        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.authority = opts.authority;
        this.redirectUrl = opts.redirectUrl;

        this.logRaw = opts.logRaw;
        this.logger = opts.logger;

        this.provider = 'outlook';

        this.setFlag = opts.setFlag;

        switch (opts.cloud) {
            case 'gcc-high':
                this.entraEndpoint = 'https://login.microsoftonline.us';
                this.apiBase = 'https://graph.microsoft.us';
                break;

            case 'dod':
                this.entraEndpoint = 'https://login.microsoftonline.us';
                this.apiBase = 'https://dod-graph.microsoft.us';
                break;

            case 'china':
                this.entraEndpoint = 'https://login.chinacloudapi.cn';
                this.apiBase = 'https://microsoftgraph.chinacloudapi.cn';
                break;

            case 'global':
            default:
                this.entraEndpoint = 'https://login.microsoftonline.com';
                this.apiBase = 'https://graph.microsoft.com/v1.0';
        }
    }

    generateAuthUrl(opts) {
        opts = opts || {};

        const url = new URL(`${this.entraEndpoint}/${this.authority}/oauth2/v2.0/authorize`);

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

        const url = new URL(`${this.entraEndpoint}/${this.authority}/oauth2/v2.0/token`);

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

        const url = new URL(`${this.entraEndpoint}/${this.authority}/oauth2/v2.0/token`);

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

                let userFlag = checkForUserFlags(err.tokenRequest.response);
                if (userFlag) {
                    err.tokenRequest.userFlag = userFlag;
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

    async request(accessToken, url, method, payload, options) {
        options = options || {};

        method = method || 'get';
        let reqData = {
            // Request will fail if using 'patch' instead of 'PATCH'
            method: method.toUpperCase(),
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            dispatcher: fetchAgent
        };

        if (options.headers) {
            reqData.headers = Object.assign({}, options.headers, reqData.headers);
        }

        if (payload && method !== 'get') {
            if (!Buffer.isBuffer(payload)) {
                reqData.headers.Accept = 'application/json';
                reqData.headers['Content-Type'] = options?.contentType || 'application/json';
                payload = Buffer.from(JSON.stringify(payload));
            } else {
                reqData.headers['Content-Type'] = options?.contentType || 'application/x-www-form-urlencoded';
            }
            reqData.body = payload;
        } else if (payload && method === 'get') {
            let parsedUrl = new URL(url);
            for (let key of Object.keys(payload)) {
                if (typeof payload[key] === 'undefined') {
                    continue;
                }
                parsedUrl.searchParams.append(key, payload[key].toString());
            }
            url = parsedUrl.href;
        }

        let retryCount = 0;

        let startTime = Date.now();

        let res;

        while (++retryCount < MAX_THROTTLING_RETRIES) {
            res = await fetchCmd(url, reqData);

            let retryAfter;
            if (res.status === 429 && res.headers.has('retry-after')) {
                retryAfter = !isNaN(res.headers.has('retry-after')) ? Number(res.headers.has('retry-after')) * 1000 : undefined;
                if (retryAfter && retryAfter > 0) {
                    if (this.logger) {
                        this.logger.error({ msg: 'API request was throttled, retrying', reqData, retryCount, retryAfter });
                    }
                    await new Promise(r => setTimeout(r, retryAfter));
                    continue;
                }
            }
            break;
        }

        let reqTime = Date.now() - startTime;

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = {
                url,
                method,
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                scopes: this.scopes,
                retryCount,
                reqTime
            };
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
            } finally {
                if (this.logger) {
                    this.logger.error(Object.assign({ msg: 'API request failed' }, err.oauthRequest));
                }
            }
            throw err;
        }

        if (this.logger) {
            this.logger.info(
                Object.assign(
                    { msg: 'API request completed' },
                    {
                        url,
                        method,
                        provider: this.provider,
                        status: res.status,
                        clientId: this.clientId,
                        reqTime
                    }
                )
            );
        }

        // clear potential auth flag
        await this.setFlag();

        if (options.returnText) {
            return await res.text();
        }

        return await res.json();
    }
}

module.exports.OutlookOauth = OutlookOauth;
module.exports.outlookScopes = outlookScopes;
