'use strict';

const settings = require('./settings');
const Boom = require('@hapi/boom');

const { OutlookOauth } = require('./outlook-oauth');
const { GmailOauth } = require('./gmail-oauth');
const { MailRuOauth } = require('./mail-ru-oauth');

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

        case 'gmailService': {
            let serviceClient = await settings.get('gmailServiceClient');
            let serviceKey = await settings.get('gmailServiceKey');

            if (!serviceClient || !serviceKey) {
                let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                throw error;
            }

            return new GmailOauth({
                serviceClient,
                serviceKey,
                async setFlag(flag) {
                    try {
                        if (flag) {
                            await settings.set('gmailServiceAuthFlag', flag);
                        } else {
                            await settings.set('gmailServiceAuthFlag', flag);
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

        case 'mailRu': {
            let clientId = await settings.get('mailRuClientId');
            let clientSecret = await settings.get('mailRuClientSecret');
            let redirectUrl = await settings.get('mailRuRedirectUrl');

            if (!clientId || !clientSecret || !redirectUrl) {
                let error = Boom.boomify(new Error('OAuth2 credentials not set up for Mail.ru'), { statusCode: 400 });
                throw error;
            }

            return new MailRuOauth({
                clientId,
                clientSecret,
                redirectUrl,
                async setFlag(flag) {
                    try {
                        if (flag) {
                            await settings.set('mailRuAuthFlag', flag);
                        } else {
                            await settings.set('mailRuAuthFlag', flag);
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
