'use strict';

const packageData = require('../../package.json');
const { formatPartialSecretKey, structuredClone, retryAgent } = require('../tools');
const crypto = require('crypto');

const { fetch: fetchCmd } = require('undici');

const GMAIL_SCOPES = {
    imap: ['https://mail.google.com/'],
    api: ['https://www.googleapis.com/auth/gmail.modify'],
    pubsub: ['https://www.googleapis.com/auth/pubsub']
};

const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Unauthorized/i;

const checkForFlags = (err, isPrincipal) => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    const { error, error_description: description } = err;

    if (error && typeof error === 'object') {
        let activationLink;
        if (/API has not been used/.test(error.message) && Array.isArray(error.details)) {
            for (const detail of error.details) {
                if (!detail || !Array.isArray(detail.links)) {
                    continue;
                }
                activationLink = (detail.links.find(link => /Google developers console API activation/.test(link.description) && link.url) || {}).url;
                if (activationLink) {
                    return {
                        message: 'Please enable the Gmail API in your Google Developer Console to use this feature.',
                        code: 'GMAIL_API_NOT_ENABLED',
                        url: activationLink
                    };
                }
            }
        }

        if (/insufficient authentication scopes/i.test(error.message)) {
            return {
                message:
                    'The current OAuth2 permission scopes are not sufficient to process Gmail API requests. Please update the scopes in your configuration.',
                code: 'INSUFFICIENT_AUTH_SCOPES'
            };
        }

        if (/Invalid topicName does not match/.test(error.message)) {
            return {
                message:
                    'There is a mismatch between your Cloud Pub/Sub configuration and the Gmail API OAuth2 application project. Please ensure both are associated with the same project.',
                code: 'PROJECT_MISMATCH'
            };
        }
    }

    if (error === 'invalid_client' && /The OAuth client was not found/i.test(description)) {
        return {
            message: 'The OAuth Client ID is invalid. Please verify that your Google integration is configured with the correct Client ID.',
            code: 'INVALID_CLIENT_ID'
        };
    }

    if (error === 'invalid_client' && /Unauthorized/i.test(description)) {
        return {
            message: 'The OAuth Client Secret is incorrect. Please verify that you have provided the correct Client Secret for your Google integration.',
            code: 'INVALID_CLIENT_SECRET'
        };
    }

    if (error === 'unauthorized_client' && /Client is unauthorized to retrieve access tokens/i.test(description)) {
        return {
            message:
                'The client is not authorized to retrieve access tokens. Check your OAuth2 scopes and ensure domain-wide delegation is set up correctly for your project.',
            code: 'UNAUTHORIZED_CLIENT'
        };
    }

    if (error === 'invalid_request' && /Invalid principal/i.test(description)) {
        return {
            message: 'The OAuth Client Email provided is invalid. Please review your Google integration settings and correct the email if needed.',
            code: 'INVALID_CLIENT_EMAIL'
        };
    }

    if (isPrincipal && error === 'invalid_grant' && /account not found/i.test(description)) {
        return {
            message: 'The Service Client Email is invalid or unrecognized. Please verify that your service account credentials are correct.',
            code: 'INVALID_SERVICE_CLIENT_EMAIL'
        };
    }

    return false;
};

const checkForUserFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    if (description && typeof description === 'string' && description.indexOf('Token has been expired or revoked')) {
        description = `Refresh token has expired or been revoked. This usually happens if you're using a public OAuth2 application that hasn't passed Google's security verification process—in such cases, refresh tokens expire after 7 days. It may also occur if the user has revoked your app's access to their email account. To fix this, consider completing the verification process or ask the user to reauthorize your app.`;
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

    let data = structuredClone(responseObj);
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
        this.googleProjectId = opts.googleProjectId;

        this.serviceClientEmail = opts.serviceClientEmail;
        this.serviceKey = opts.serviceKey;

        this.workspaceAccounts = !!opts.workspaceAccounts;

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

        if (this.workspaceAccounts) {
            url.searchParams.set('hd', '*');
        }

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
                dispatcher: retryAgent
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
                googleProjectId: this.googleProjectId,
                serviceClientEmail: this.serviceClientEmail,
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
            let requestData = this.generateServiceRequest(opts.user, opts.isPrincipal);
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
                dispatcher: retryAgent
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
                googleProjectId: this.googleProjectId,
                serviceClientEmail: this.serviceClientEmail,
                scopes: this.scopes
            };
            try {
                err.tokenRequest.response = responseJson;

                if (this.clientSecret && EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(err.tokenRequest.response.error_description)) {
                    // key might have been invalidated or renewed
                    err.tokenRequest.clientSecret = formatPartialSecretKey(this.clientSecret);
                }

                let flag = checkForFlags(err.tokenRequest.response, opts.isPrincipal);

                if (flag) {
                    await this.setFlag(flag);
                    err.tokenRequest.flag = flag;
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

        return await responseJson;
    }

    async request(accessToken, url, method, payload, options) {
        options = options || {};

        method = (method || '').toString().toLowerCase().trim() || 'get';
        let reqData = {
            method,
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            dispatcher: retryAgent
        };

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
                if (typeof payload[key] === 'undefined' || payload[key] === null) {
                    continue;
                }
                parsedUrl.searchParams.append(key, payload[key].toString());
            }
            url = parsedUrl.href;
        }

        let startTime = Date.now();

        let res = await fetchCmd(url, reqData);

        let reqTime = Date.now() - startTime;

        let contentType = (res.headers?.get('content-type') || '').toString().split(';').shift().trim().toLowerCase();

        if (!res.ok) {
            let err = new Error('OAuth2 request failed');
            err.oauthRequest = {
                o: 1,
                url,
                method,
                provider: this.provider,
                status: res.status,
                contentType,
                clientId: this.clientId,
                serviceClient: this.serviceClient,
                googleProjectId: this.googleProjectId,
                serviceClientEmail: this.serviceClientEmail,
                scopes: this.scopes,
                reqTime
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
                    if (flag.code && !err.code) {
                        err.code = flag.code;
                    }
                }
            } catch (E) {
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
                    { msg: 'External API request completed' },
                    {
                        o: 2,
                        url,
                        method,
                        provider: this.provider,
                        status: res.status,
                        contentType,
                        clientId: this.clientId,
                        serviceClient: this.serviceClient,
                        googleProjectId: this.googleProjectId,
                        serviceClientEmail: this.serviceClientEmail,
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

        if (!['application/json', 'text/json'].includes(contentType)) {
            let error = new Error('Expected JSON response for OAuth2 request');
            error.oauthRequest = {
                o: 3,
                url,
                method,
                provider: this.provider,
                status: res.status,
                contentType,
                clientId: this.clientId,
                serviceClient: this.serviceClient,
                googleProjectId: this.googleProjectId,
                serviceClientEmail: this.serviceClientEmail,
                scopes: this.scopes,
                reqTime
            };

            let responseText;
            try {
                responseText = ((await res.text()) || '').toString();
            } catch (err) {
                responseText = err.message;
            }

            error.oauthRequest.response = {
                lentgh: responseText.length,
                text: responseText.toString().substring(0, 5 * 1024)
            };
            throw error;
        }

        let result = await res.json();

        return result;
    }

    generateServiceRequest(principal, isPrincipal) {
        let iat = Math.floor(Date.now() / 1000); // unix time

        let tokenData = isPrincipal
            ? {
                  iss: this.serviceClientEmail,
                  scope: this.scopes.join(' '),
                  aud: this.tokenUrl,
                  iat,
                  exp: iat + 3600
              }
            : {
                  iss: this.serviceClient,
                  scope: this.scopes.join(' '),
                  sub: principal,
                  aud: this.tokenUrl,
                  iat,
                  exp: iat + 3600
              };

        let token = this.jwtSignRS256(tokenData, isPrincipal);

        return {
            tokenData,
            payload: {
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: token
            }
        };
    }

    jwtSignRS256(payload, useKid) {
        const encodedPayload = [`{"alg":"RS256","typ":"JWT"${useKid ? `,"kid":"${this.serviceClient}"` : ''}}`, JSON.stringify(payload)]
            .map(val => Buffer.from(val).toString('base64url'))
            .join('.');
        const signature = crypto.createSign('RSA-SHA256').update(encodedPayload).sign(this.serviceKey);
        return [encodedPayload, Buffer.from(signature).toString('base64url')].join('.');
    }
}

module.exports.GmailOauth = GmailOauth;
module.exports.GMAIL_SCOPES = GMAIL_SCOPES;
