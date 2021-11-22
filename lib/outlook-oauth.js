'use strict';

const fetch = require('node-fetch');

const OUTLOOK_SCOPES = ['https://outlook.office.com/IMAP.AccessAsUser.All', 'https://outlook.office.com/SMTP.Send', 'offline_access', 'openid', 'profile'];

class OutlookOauth {
    constructor(opts) {
        this.scopes = [].concat(opts.scopes || OUTLOOK_SCOPES);
        this.clientId = opts.clientId;
        this.clientSecret = opts.clientSecret;
        this.authority = opts.authority;
        this.redirectUrl = opts.redirectUrl;

        this.logger = opts.logger;
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

        let res = await fetch(tokenRequest.url, {
            method: 'post',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tokenRequest.body
        });

        if (!res.ok) {
            throw new Error('Token request failed');
        }

        return await res.json();
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

        let res = await fetch(url.origin + url.pathname, {
            method: 'post',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: url.searchParams
        });

        if (!res.ok) {
            throw new Error('Token request failed');
        }

        return await res.json();
    }
}

module.exports.OutlookOauth = OutlookOauth;
