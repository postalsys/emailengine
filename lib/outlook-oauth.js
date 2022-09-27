'use strict';

const packageData = require('../package.json');
const { formatPartialSecretKey } = require('./tools');

const nodeFetch = require('node-fetch');
const fetchCmd = global.fetch || nodeFetch;

// const OUTLOOK_SCOPES = ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send', 'offline_access', 'openid', 'profile'];
const OUTLOOK_SCOPES = [
    'https://graph.microsoft.com/IMAP.AccessAsUser.All',
    'https://graph.microsoft.com/SMTP.Send',
    'https://graph.microsoft.com/offline_access',
    'https://graph.microsoft.com/openid',
    'https://graph.microsoft.com/profile'
];

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

class OutlookOauth {
    constructor(opts) {
        this.scopes = [].concat(opts.scopes || OUTLOOK_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.authority = opts.authority;
        this.redirectUrl = opts.redirectUrl;

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

        console.log(
            'REQUESTING OUTLOOK TOKEN',
            JSON.stringify({
                url: tokenRequest.url,
                payload: {
                    method,
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                    },
                    body: tokenRequest.body
                }
            })
        );

        let res = await fetchCmd(tokenRequest.url, {
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: tokenRequest.body
        });

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
                err.tokenRequest.response = await res.json();

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

        let result = await res.json();
        console.log('OUTLOOK TOKEN REQUEST RESULT', JSON.stringify(result));

        return result;
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

        console.log(
            'REFRESHING OUTLOOK TOKEN',
            JSON.stringify({
                url: requestUrl,
                payload: {
                    method,
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                    },
                    body: url.searchParams
                }
            })
        );

        let res = await fetchCmd(requestUrl, {
            method: 'post',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: url.searchParams
        });

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
                err.tokenRequest.response = await res.json();

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

        let result = await res.json();
        console.log('OUTLOOK TOKEN REFRESH RESULT', JSON.stringify(result));

        return result;
    }

    async request(accessToken, url, method, payload) {
        method = method || 'get';
        let reqData = {
            method,
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            }
        };

        if (payload) {
            reqData.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            reqData.body = payload;
        }

        console.log(
            'OUTLOOK API REQUEST',
            JSON.stringify({
                url,
                payload: reqData
            })
        );

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

        let result = await res.json();
        console.log('OUTLOOK API RESULT', JSON.stringify(result));

        return result;
    }
}

module.exports.OutlookOauth = OutlookOauth;
module.exports.OUTLOOK_SCOPES = OUTLOOK_SCOPES;
