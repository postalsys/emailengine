'use strict';

const fetch = require('node-fetch');
const packageData = require('../package.json');

const GMAIL_SCOPES = ['https://mail.google.com/'];

class GmailOauth {
    constructor(opts) {
        this.scopes = [].concat(opts.scopes || GMAIL_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.redirectUrl = opts.redirectUrl;

        this.logger = opts.logger;

        this.provider = 'gmail';
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

        const url = new URL(`https://oauth2.googleapis.com/token`);

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

        let res = await fetch(tokenRequest.url, {
            method: 'post',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: tokenRequest.body
        });

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.tokenRequest = { grant: 'authorization_code', provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes, code };
            try {
                err.tokenRequest.response = await res.json();
            } catch (err) {
                // ignore
            }
            throw err;
        }

        return await res.json();
    }

    async refreshToken(opts) {
        opts = opts || {};
        if (!opts.refreshToken) {
            throw new Error('Refresh token not provided');
        }

        const url = new URL(`https://oauth2.googleapis.com/token`);

        url.searchParams.set('refresh_token', opts.refreshToken);

        url.searchParams.set('client_id', this.clientId);

        url.searchParams.set('scope', this.scopes.join(' '));

        url.searchParams.set('redirect_uri', this.redirectUrl);
        url.searchParams.set('grant_type', 'refresh_token');
        url.searchParams.set('client_secret', this.clientSecret);

        let res = await fetch(url.origin + url.pathname, {
            method: 'post',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            },
            body: url.searchParams
        });

        if (!res.ok) {
            let err = new Error('Token request failed');
            err.tokenRequest = { grant: 'refresh_token', provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes };
            try {
                err.tokenRequest.response = await res.json();
            } catch (err) {
                // ignore
            }
            throw err;
        }

        return await res.json();
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

        let res = await fetch(url, reqData);

        if (!res.ok) {
            let err = new Error('Oauth2 request failed');
            err.oauthRequest = { url, method, provider: this.provider, status: res.status, clientId: this.clientId, scopes: this.scopes };
            try {
                err.oauthRequest.response = await res.json();
            } catch (err) {
                // ignore
            }
            throw err;
        }

        return await res.json();
    }
}

module.exports.GmailOauth = GmailOauth;
module.exports.GMAIL_SCOPES = GMAIL_SCOPES;
