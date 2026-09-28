#!/usr/bin/env node

'use strict';

const { fetch } = require('undici');
const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

require('dotenv').config();

const SCOPE_PROFILES = {
    full: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/gmail.modify'],
    sendonly: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/gmail.send']
};

const REDIRECT_URI = 'http://127.0.0.1:3000/oauth';

let currentAccount = null; // the account whose client credentials the browser flow below uses

// The two OAuth2 calls the flow needs, made against Google's endpoints directly: the googleapis
// client this script used to require is not a dependency of the repository
function buildAuthUrl(email, scopes) {
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', currentAccount.clientId);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', scopes.join(' '));
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('login_hint', email);
    authUrl.searchParams.set('prompt', 'consent');
    return authUrl.href;
}

async function exchangeCode(code) {
    const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: currentAccount.clientId,
            client_secret: currentAccount.clientSecret,
            redirect_uri: REDIRECT_URI,
            grant_type: 'authorization_code'
        }).toString()
    });
    const tokens = await res.json();
    if (!res.ok) {
        throw new Error(`Token exchange failed (${res.status}): ${tokens.error || ''} ${tokens.error_description || ''}`.trim());
    }
    return tokens;
}

async function updateEnvFile(email, refreshToken, accountType) {
    const envPath = path.join(__dirname, '..', '.env');
    let envContent = fs.readFileSync(envPath, 'utf8');

    if (accountType === 'sendonly') {
        envContent = envContent.replace(/GMAIL_SENDONLY_ACCOUNT_REFRESH="[^"]*"/, `GMAIL_SENDONLY_ACCOUNT_REFRESH="${refreshToken}"`);
    } else if (email === process.env.GMAIL_API_ACCOUNT_EMAIL_1) {
        envContent = envContent.replace(/GMAIL_API_ACCOUNT_REFRESH_1="[^"]*"/, `GMAIL_API_ACCOUNT_REFRESH_1="${refreshToken}"`);
    } else if (email === process.env.GMAIL_API_ACCOUNT_EMAIL_2) {
        envContent = envContent.replace(/GMAIL_API_ACCOUNT_REFRESH_2="[^"]*"/, `GMAIL_API_ACCOUNT_REFRESH_2="${refreshToken}"`);
    }

    fs.writeFileSync(envPath, envContent, 'utf8');
    console.log(`Updated .env file with new refresh token for ${email} (${accountType || 'full'})`);
}

async function getNewTokens(email, scopes, accountType) {
    return new Promise((resolve, reject) => {
        const authUrl = buildAuthUrl(email, scopes);

        console.log('\n' + '='.repeat(80));
        console.log(`Authorize account: ${email}`);
        console.log('='.repeat(80));
        console.log('\nOpen this URL in your browser:\n');
        console.log(authUrl);
        console.log('\n');

        const server = http
            .createServer(async (req, res) => {
                try {
                    if (req.url.indexOf('/oauth') > -1) {
                        const qs = new url.URL(req.url, 'http://127.0.0.1:3000').searchParams;
                        const code = qs.get('code');

                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end('<h1>Authentication successful!</h1><p>You can close this window and return to the terminal.</p>');

                        server.close();

                        const tokens = await exchangeCode(code);

                        console.log('\nTokens received:');
                        console.log('Access Token:', tokens.access_token.substring(0, 20) + '...');
                        console.log('Refresh Token:', tokens.refresh_token);
                        console.log('Expires:', new Date(Date.now() + tokens.expires_in * 1000).toISOString());
                        console.log('Scope:', tokens.scope);

                        await updateEnvFile(email, tokens.refresh_token, accountType);

                        resolve(tokens);
                    }
                } catch (e) {
                    reject(e);
                }
            })
            .listen(3000, '127.0.0.1', () => {
                console.log('Waiting for authentication... (listening on http://127.0.0.1:3000)');
            });
    });
}

async function main() {
    console.log('Gmail OAuth2 Token Refresh Helper');
    console.log('==================================\n');

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const question = query => new Promise(resolve => rl.question(query, resolve));

    console.log('Available accounts:');
    console.log(`1. ${process.env.GMAIL_API_ACCOUNT_EMAIL_1} (Full access - gmail.modify)`);
    console.log(`2. ${process.env.GMAIL_API_ACCOUNT_EMAIL_2} (Full access - gmail.modify)`);
    console.log(`3. ${process.env.GMAIL_SENDONLY_ACCOUNT_EMAIL} (Send-only - gmail.send)`);
    console.log('4. All accounts\n');

    const choice = await question('Which account do you want to refresh? (1/2/3/4): ');

    const accounts = [];
    if (choice === '1') {
        accounts.push({
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            clientId: process.env.GMAIL_API_CLIENT_ID,
            clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.full,
            type: 'full'
        });
    } else if (choice === '2') {
        accounts.push({
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_2,
            clientId: process.env.GMAIL_API_CLIENT_ID,
            clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.full,
            type: 'full'
        });
    } else if (choice === '3') {
        accounts.push({
            email: process.env.GMAIL_SENDONLY_ACCOUNT_EMAIL,
            clientId: process.env.GMAIL_SENDONLY_CLIENT_ID,
            clientSecret: process.env.GMAIL_SENDONLY_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.sendonly,
            type: 'sendonly'
        });
    } else if (choice === '4') {
        accounts.push({
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            clientId: process.env.GMAIL_API_CLIENT_ID,
            clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.full,
            type: 'full'
        });
        accounts.push({
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_2,
            clientId: process.env.GMAIL_API_CLIENT_ID,
            clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.full,
            type: 'full'
        });
        accounts.push({
            email: process.env.GMAIL_SENDONLY_ACCOUNT_EMAIL,
            clientId: process.env.GMAIL_SENDONLY_CLIENT_ID,
            clientSecret: process.env.GMAIL_SENDONLY_CLIENT_SECRET,
            scopes: SCOPE_PROFILES.sendonly,
            type: 'sendonly'
        });
    } else {
        console.log('Invalid choice');
        rl.close();
        return;
    }

    rl.close();

    for (const account of accounts) {
        try {
            // The browser flow reads the client credentials of this account
            currentAccount = account;

            await getNewTokens(account.email, account.scopes, account.type);
            console.log(`\n✓ Successfully refreshed tokens for ${account.email} (${account.type})\n`);
        } catch (error) {
            console.error(`\n✗ Error refreshing tokens for ${account.email}:`, error.message);
        }
    }

    console.log('\n' + '='.repeat(80));
    console.log('All done! The .env file has been updated.');
    console.log('='.repeat(80));
}

main().catch(console.error);
