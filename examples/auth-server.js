'use strict';

/**
 * Example Authentication Server for EmailEngine
 *
 * EmailEngine calls this server to resolve credentials when an account
 * is configured to use an external authentication server.
 *
 * Request format:
 *   GET /?account=<account_id>&proto=<imap|smtp|api>
 *
 * Response format (JSON):
 *   For password auth: { "user": "username", "pass": "password" }
 *   For OAuth2:        { "user": "email@example.com", "accessToken": "..." }
 *
 * Configure in EmailEngine: Settings -> Configuration -> Authentication Server URL
 */

const Hapi = require('@hapi/hapi');
const hapiPino = require('hapi-pino');

// Optional: OAuth2 credentials for token-based authentication
// Only required if you have accounts using OAuth2
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID;
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET;

// Example OAuth2 user credentials (for demo purposes)
const OAUTH2_USER_EMAIL = process.env.OAUTH2_USER_EMAIL;
const OAUTH2_USER_REFRESH_TOKEN = process.env.OAUTH2_USER_REFRESH_TOKEN;

// In-memory token cache (in production, use Redis or similar)
const tokenCache = new Map();

async function init() {
    const server = Hapi.server({
        port: process.env.AUTH_SERVER_PORT || 3080,
        host: process.env.AUTH_SERVER_HOST || 'localhost'
    });

    await server.register({
        plugin: hapiPino,
        options: {
            level: process.env.LOG_LEVEL || 'info'
        }
    });

    // Main authentication endpoint
    server.route({
        method: 'GET',
        path: '/',
        async handler(request, h) {
            const { account, proto } = request.query;

            request.logger.info({ account, proto }, 'Authentication request');

            // Look up credentials based on account ID
            // In production, this would query a database
            try {
                const credentials = await getCredentials(account, proto);
                if (!credentials) {
                    return h.response({ error: 'Account not found' }).code(404);
                }
                return credentials;
            } catch (err) {
                request.logger.error({ err, account, proto }, 'Failed to resolve credentials');
                return h.response({ error: 'Authentication failed' }).code(500);
            }
        }
    });

    await server.start();
    console.log('Authentication Server running at: %s', server.info.uri);
}

/**
 * Resolve credentials for an account
 * @param {string} account - The account ID
 * @param {string} proto - The protocol (imap, smtp, or api)
 * @returns {Promise<{user: string, pass?: string, accessToken?: string}|null>}
 */
async function getCredentials(account, proto) {
    switch (account) {
        // Example 1: Password-based authentication
        case 'example':
            return {
                user: 'myuser@example.com',
                pass: 'verysecret'
            };

        // Example 2: OAuth2 token-based authentication
        case 'oauth-user':
            if (!OAUTH2_CLIENT_ID || !OAUTH2_CLIENT_SECRET) {
                throw new Error('OAuth2 credentials not configured');
            }
            if (!OAUTH2_USER_EMAIL || !OAUTH2_USER_REFRESH_TOKEN) {
                throw new Error('OAuth2 user credentials not configured');
            }
            return {
                user: OAUTH2_USER_EMAIL,
                accessToken: await getAccessToken(OAUTH2_USER_EMAIL, OAUTH2_USER_REFRESH_TOKEN)
            };

        // Example 3: Different credentials per protocol
        case 'multi-proto':
            if (proto === 'smtp') {
                return { user: 'smtp-user@example.com', pass: 'smtp-password' };
            }
            return { user: 'imap-user@example.com', pass: 'imap-password' };

        default:
            return null;
    }
}

/**
 * Get OAuth2 access token, using cache when possible
 */
async function getAccessToken(user, refreshToken) {
    // Check cache
    const cached = tokenCache.get(user);
    if (cached && cached.expires > Date.now()) {
        return cached.accessToken;
    }

    // Generate new token using Google's OAuth2 endpoint
    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: OAUTH2_CLIENT_ID,
            client_secret: OAUTH2_CLIENT_SECRET,
            refresh_token: refreshToken,
            grant_type: 'refresh_token'
        })
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Token refresh failed: ${response.status} ${text}`);
    }

    const data = await response.json();

    // Cache with 5-minute buffer before expiry
    tokenCache.set(user, {
        accessToken: data.access_token,
        expires: Date.now() + (data.expires_in - 300) * 1000
    });

    return data.access_token;
}

init().catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
