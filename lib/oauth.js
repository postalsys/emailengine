'use strict';

const settings = require('./settings');
const Boom = require('@hapi/boom');

const { OutlookOauth } = require('./outlook-oauth');
const { GmailOauth } = require('./gmail-oauth');

const getOAuth2Client = async provider => {
    switch (provider) {
        case 'gmail': {
            let clientId = await settings.get('gmailClientId');
            let clientSecret = await settings.get('gmailClientSecret');
            let redirectUrl = await settings.get('gmailRedirectUrl');

            if (!clientId || !clientSecret || !redirectUrl) {
                let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                throw error;
            }

            return new GmailOauth({
                clientId,
                clientSecret,
                redirectUrl,
                async setFlag(flag) {
                    try {
                        if (flag) {
                            await settings.set('gmailAuthFlag', flag);
                        } else {
                            await settings.set('gmailAuthFlag', flag);
                        }
                    } catch (err) {
                        // ignore
                    }
                }
            });
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
                redirectUrl,
                async setFlag(flag) {
                    try {
                        if (flag) {
                            await settings.set('outlookAuthFlag', flag);
                        } else {
                            await settings.set('outlookAuthFlag', flag);
                        }
                    } catch (err) {
                        // ignore
                    }
                }
            });
        }

        default: {
            let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
            throw error;
        }
    }
};

module.exports.getOAuth2Client = getOAuth2Client;
