#!/usr/bin/env node

'use strict';

const { google } = require('googleapis');
const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

require('dotenv').config();

const SCOPE_PROFILES = {
    full: [
        'openid',
        'email',
        'profile',
        'https://www.googleapis.com/auth/gmail.modify'
    ],
    sendonly: [
        'openid',
        'email',
        'profile',
        'https://www.googleapis.com/auth/gmail.send'
    ]
};

let oauth2Client = null; // Will be initialized based on account selection

async function updateEnvFile(email, refreshToken, accountType) {
    const envPath = path.join(__dirname, '..', '.env');
    let envContent = fs.readFileSync(envPath, 'utf8');

    if (accountType === 'sendonly') {
        envContent = envContent.replace(
            /GMAIL_SENDONLY_ACCOUNT_REFRESH="[^"]*"/,
            `GMAIL_SENDONLY_ACCOUNT_REFRESH="${refreshToken}"`
        );
    } else if (email === process.env.GMAIL_API_ACCOUNT_EMAIL_1) {
        envContent = envContent.replace(
            /GMAIL_API_ACCOUNT_REFRESH_1="[^"]*"/,
            `GMAIL_API_ACCOUNT_REFRESH_1="${refreshToken}"`
        );
    } else if (email === process.env.GMAIL_API_ACCOUNT_EMAIL_2) {
        envContent = envContent.replace(
            /GMAIL_API_ACCOUNT_REFRESH_2="[^"]*"/,
            `GMAIL_API_ACCOUNT_REFRESH_2="${refreshToken}"`
        );
    }

    fs.writeFileSync(envPath, envContent, 'utf8');
    console.log(`Updated .env file with new refresh token for ${email} (${accountType || 'full'})`);
}

async function getNewTokens(email, scopes, accountType) {
    return new Promise((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopes,
            login_hint: email,
            prompt: 'consent'
        });

        console.log('\n' + '='.repeat(80));
        console.log(`Authorize account: ${email}`);
        console.log('='.repeat(80));
        console.log('\nOpen this URL in your browser:\n');
        console.log(authUrl);
        console.log('\n');

        const server = http.createServer(async (req, res) => {
            try {
                if (req.url.indexOf('/oauth') > -1) {
                    const qs = new url.URL(req.url, 'http://127.0.0.1:3000').searchParams;
                    const code = qs.get('code');

                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end('<h1>Authentication successful!</h1><p>You can close this window and return to the terminal.</p>');

                    server.close();

                    const { tokens } = await oauth2Client.getToken(code);

                    console.log('\nTokens received:');
                    console.log('Access Token:', tokens.access_token.substring(0, 20) + '...');
                    console.log('Refresh Token:', tokens.refresh_token);
                    console.log('Expires:', new Date(tokens.expiry_date).toISOString());
                    console.log('Scope:', tokens.scope);

                    await updateEnvFile(email, tokens.refresh_token, accountType);

                    resolve(tokens);
                }
            } catch (e) {
                reject(e);
            }
        }).listen(3000, '127.0.0.1', () => {
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

    const question = (query) => new Promise(resolve => rl.question(query, resolve));

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
            // Initialize OAuth2 client for this specific account
            oauth2Client = new google.auth.OAuth2(
                account.clientId,
                account.clientSecret,
                'http://127.0.0.1:3000/oauth'
            );

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
