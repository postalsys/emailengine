'use strict';

const fetch = require('node-fetch');
const packageData = require('../package.json');

const MAIL_RU_SCOPES = ['userinfo', 'mail.imap'];

const checkForFlags = err => {
    if (!err || typeof err !== 'object') {
        return false;
    }

    let { error, error_description: description } = err;

    console.log('MAILRU ERROR', error, description);

    return false;
};

class MailRuOauth {
    constructor(opts) {
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

        console.log('AUTH URL', url.href, this.scopes);

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

        let res = await fetch(tokenRequest.url, {
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
                Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`
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

        return await res.json();
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

        let res = await fetch(requestUrl, {
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

        return await res.json();
    }

    async request(accessToken, url, method, payload) {
        method = method || 'get';
        let reqData = {
            method,
            headers: {
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            }
        };

        if (payload) {
            reqData.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            reqData.body = payload;
        }

        const requestUrl = new URL(url);
        requestUrl.searchParams.set('access_token', accessToken);

        let res = await fetch(requestUrl.href, reqData);

        if (!res.ok) {
            let err = new Error('Oauth2 request failed');
            err.oauthRequest = { url, method, provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes };
            try {
                err.oauthRequest.response = await res.json();

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

module.exports.MailRuOauth = MailRuOauth;
module.exports.MAIL_RU_SCOPES = MAIL_RU_SCOPES;
