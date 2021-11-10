'use strict';

const settings = require('./settings');
const Boom = require('@hapi/boom');
const { OAuth2Client } = require('google-auth-library');
const { OutlookOauth } = require('./outlook-oauth');

const getOAuth2Client = async provider => {
    switch (provider) {
        case 'gmail': {
            let keys = {
                clientId: await settings.get('gmailClientId'),
                clientSecret: await settings.get('gmailClientSecret'),
                redirectUrl: await settings.get('gmailRedirectUrl')
            };

            if (!keys.clientId || !keys.clientSecret || !keys.redirectUrl) {
                let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                throw error;
            }

            return new OAuth2Client(keys.clientId, keys.clientSecret, keys.redirectUrl);
        }

        case 'outlook': {
            let authority = await settings.get('outlookAuthority');
            let clientId = await settings.get('outlookClientId');
            let clientSecret = await settings.get('outlookClientSecret');
            let redirectUrl = await settings.get('outlookRedirectUrl');

            if (!clientId || !clientSecret || !authority || !redirectUrl) {
                let error = Boom.boomify(new Error('OAuth2 credentials not set up for Outlook'), { statusCode: 400 });
                throw error;
            }

            return new OutlookOauth({
                authority,
                clientId,
                clientSecret,
                redirectUrl
            });
        }

        default: {
            let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
            throw error;
        }
    }
};

module.exports.getOAuth2Client = getOAuth2Client;
