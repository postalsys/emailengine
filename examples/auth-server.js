'use strict';

const Hapi = require('@hapi/hapi');
const hapiPino = require('hapi-pino');
const XOAuth2 = require('nodemailer/lib/xoauth2');

// Gmail oauth app credentials. Must have https://mail.google.com scope set
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID;
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET;

// Single user specific credentials as our demo only provides tokens for a single user
const USER_ADDRESS = process.env.USER_ADDRESS;
const USER_REFRESH_TOKEN = process.env.USER_REFRESH_TOKEN;

const init = async () => {
    const server = Hapi.server({
        port: 3080,
        host: 'localhost'
    });

    await server.register({
        plugin: hapiPino,
        options: {
            level: 'trace'
        }
    });

    server.route({
        method: 'GET',
        path: '/credentials',

        async handler(request) {
            switch (request.query.account) {
                case 'example':
                    return {
                        user: 'myuser2',
                        pass: 'verysecret'
                    };
            }

            switch (request.query.account) {
                case 'oauth-user':
                    return {
                        user: USER_ADDRESS,
                        accessToken: await getAccessToken(USER_ADDRESS, USER_REFRESH_TOKEN)
                    };
            }

            return false;
        }
    });

    await server.start();
    console.log('Authentication Server URL: %s/credentials', server.info.uri);
};

const tokens = new Map();
async function getAccessToken(user, refreshToken) {
    // check cache first
    if (tokens.has(user)) {
        let token = tokens.get(user);
        if (token.expires > new Date()) {
            // use cached token
            return token.accessToken;
        }
        // clear expired token
        tokens.delete(user);
    }

    // generate new token
    let token = await new Promise((resolve, reject) => {
        let xoauth = new XOAuth2({
            user,
            clientId: OAUTH2_CLIENT_ID,
            clientSecret: OAUTH2_CLIENT_SECRET,
            refreshToken,
            accessUrl: 'https://accounts.google.com/o/oauth2/token'
        });
        xoauth.generateToken(err => {
            if (err) {
                return reject(err);
            }
            if (!xoauth.accessToken) {
                return reject(new Error('Could not generate new access token'));
            }
            resolve({
                accessToken: xoauth.accessToken,
                expires: xoauth.expires
            });
        });
    });

    // update cache
    tokens.set(user, token);

    return token.accessToken;
}

init();
