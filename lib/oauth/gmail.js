'use strict';

const packageData = require('../../package.json');
const { formatPartialSecretKey, pfStructuredClone } = require('../tools');
const crypto = require('crypto');

const { FETCH_TIMEOUT } = require('../consts');

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const GMAIL_SCOPES = {
    imap: ['https://mail.google.com/'],
    api: ['https://www.googleapis.com/auth/gmail.modify']
};

const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Unauthorized/i;

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    if (error && typeof error === 'object') {
        let activationLink;
        if (/API has not been used/.test(error.message) && Array.isArray(error.details)) {
            for (let detail of error.details) {
                if (!detail || !Array.isArray(detail.links)) {
                    continue;
                }
                activationLink = (detail.links.find(link => /Google developers console API activation/.test(link.description) && link.url) || {}).url;
                if (activationLink) {
                    return {
                        message: 'Gmail API needs to be enabled before it can be used',
                        url: activationLink
                    };
                }
            }
        }
    }

    if (error === 'invalid_client' && /The OAuth client was not found/i.test(description)) {
        return {
            message: 'OAuth Client ID for Google is invalid'
        };
    }

    if (error === 'invalid_client' && /Unauthorized/i.test(description)) {
        return {
            message: 'OAuth Client Secret for Google is invalid'
        };
    }

    if (error === 'unauthorized_client' && /Client is unauthorized to retrieve access tokens/i.test(description)) {
        return {
            message: 'Verify OAuth2 scopes and domain-wide delegation setup for you project'
        };
    }

    return false;
};

const formatFetchBody = (searchParams, logRaw) => {
    let data = Object.fromEntries(searchParams);

    if (logRaw) {
        // no changes needed
        return data;
    }

    for (let key of ['refresh_token', 'client_secret']) {
        if (data[key]) {
            data[key] = formatPartialSecretKey(data[key]);
        }
    }

    if (data.assertion && !logRaw) {
        let [payload, signature] = data.assertion.toString().split('.');
        data.assertion = [payload, formatPartialSecretKey(signature)].join('.');
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

class GmailOauth {
    constructor(opts) {
        const defaultBaseScopes = (opts.baseScopes && GMAIL_SCOPES[opts.baseScopes]) || GMAIL_SCOPES.imap;

        this.scopes = [].concat(opts.scopes || defaultBaseScopes);

        this.serviceClient = opts.serviceClient;
        this.serviceKey = opts.serviceKey;

        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.redirectUrl = opts.redirectUrl;

        this.logRaw = opts.logRaw;
        this.logger = opts.logger;

        this.provider = opts.provider || 'gmail';

        this.setFlag = opts.setFlag;

        this.tokenUrl = `https://oauth2.googleapis.com/token`;
    }

    generateAuthUrl(opts) {
        opts = opts || {};

        const url = new URL(`https://accounts.google.com/o/oauth2/v2/auth`);
        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('redirect_uri', this.redirectUrl);
        url.searchParams.set('response_mode', 'query');
        url.searchParams.set('scope', this.scopes.join(' '));
        url.searchParams.set('access_type', 'offline');

        if (opts.email) {
            url.searchParams.set('login_hint', opts.email);
        }

        url.searchParams.set('prompt', opts.prompt || 'consent');

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

        const url = new URL(this.tokenUrl);

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

        const fetchOpts = {
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: tokenRequest.body
        };

        let res = await fetchCmd(
            requestUrl,
            Object.assign(fetchOpts, {
                dispatcher: fetchAgent
            })
        );

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
                grant: 'authorization_code',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                serviceClient: this.serviceClient,
                scopes: this.scopes,
                code
            };
            try {
                err.tokenRequest.response = responseJson;

                if (this.clientSecret && EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.tokenRequest.response.error_description)) {
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

        const url = new URL(`https://oauth2.googleapis.com/token`);

        if (this.serviceClient) {
            // refresh using JWT
            let requestData = this.generateServiceRequest(opts.user);
            for (let key of Object.keys(requestData.payload)) {
                url.searchParams.set(key, requestData.payload[key]);
            }
        } else {
            // refresh with refresh key

            if (!opts.refreshToken) {
                throw new Error('Refresh token not provided');
            }

            url.searchParams.set('refresh_token', opts.refreshToken);
            url.searchParams.set('client_id', this.clientId);
            url.searchParams.set('scope', this.scopes.join(' '));

            url.searchParams.set('redirect_uri', this.redirectUrl);
            url.searchParams.set('grant_type', 'refresh_token');
            url.searchParams.set('client_secret', this.clientSecret);
        }

        let requestUrl = url.origin + url.pathname;
        let method = 'post';

        const fetchOpts = {
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: url.searchParams
        };

        let res = await fetchCmd(
            requestUrl,
            Object.assign(fetchOpts, {
                dispatcher: fetchAgent
            })
        );

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
            err.tokenRequest = {
                url: requestUrl,
                method,
                grant: 'refresh_token',
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                serviceClient: this.serviceClient,
                scopes: this.scopes
            };
            try {
                err.tokenRequest.response = responseJson;

                if (this.clientSecret && EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.tokenRequest.response.error_description)) {
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

        return await responseJson;
    }

    async request(accessToken, url, method, payload) {
        method = (method || '').toString().toLowerCase().trim() || 'get';
        let reqData = {
            method,
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            dispatcher: fetchAgent
        };

        if (payload && method !== 'get') {
            reqData.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            reqData.body = payload;
        } else if (payload && method === 'get') {
            let parsedUrl = new URL(url);
            for (let key of Object.keys(payload)) {
                parsedUrl.searchParams.append(key, payload[key].toString());
            }
            url = parsedUrl.href;
        }

        let res = await fetchCmd(url, reqData);

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = {
                url,
                method,
                provider: this.provider,
                status: res.status,
                clientId: this.clientId,
                serviceClient: this.serviceClient,
                scopes: this.scopes
            };
            try {
                err.oauthRequest.response = await res.json();

                if (this.clientSecret && EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.oauthRequest.response.error_description)) {
                    // key might have been invalidated or renewed
                    err.oauthRequest.clientSecret = formatPartialSecretKey(this.clientSecret);
                }

                let flag = checkForFlags(err.oauthRequest.response);
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

        return await res.json();
    }

    generateServiceRequest(user) {
        let iat = Math.floor(Date.now() / 1000); // unix time
        let tokenData = {
            iss: this.serviceClient,
            scope: this.scopes.join(' '),
            sub: user,
            aud: this.tokenUrl,
            iat,
            exp: iat + 3600
        };

        let token = this.jwtSignRS256(tokenData);

        return {
            tokenData,
            payload: {
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: token
            }
        };
    }

    jwtSignRS256(payload) {
        const encodedPayload = ['{"alg":"RS256","typ":"JWT"}', JSON.stringify(payload)].map(val => Buffer.from(val).toString('base64url')).join('.');
        const signature = crypto.createSign('RSA-SHA256').update(encodedPayload).sign(this.serviceKey);
        return [encodedPayload, Buffer.from(signature).toString('base64url')].join('.');
    }
}

module.exports.GmailOauth = GmailOauth;
module.exports.GMAIL_SCOPES = GMAIL_SCOPES;
