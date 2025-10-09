# Scripts

## refresh-test-tokens.js

Helper script to refresh OAuth2 tokens for Gmail test accounts.

### Usage

```bash
node scripts/refresh-test-tokens.js
```

### What it does

1. Prompts you to select which test account(s) to refresh
2. Generates an OAuth2 authorization URL for each account
3. Starts a local web server on port 3000 to receive the OAuth callback
4. Opens your browser to authenticate with Google
5. Exchanges the authorization code for new access and refresh tokens
6. Automatically updates the `.env` file with the new refresh tokens

### Requirements

- `googleapis` package (installed as dev dependency)
- `.env` file with the following variables:

**Full access accounts (gmail.modify scope):**
  - `GMAIL_API_CLIENT_ID`
  - `GMAIL_API_CLIENT_SECRET`
  - `GMAIL_API_ACCOUNT_EMAIL_1`
  - `GMAIL_API_ACCOUNT_REFRESH_1`
  - `GMAIL_API_ACCOUNT_EMAIL_2`
  - `GMAIL_API_ACCOUNT_REFRESH_2`

**Send-only account (gmail.send scope only):**
  - `GMAIL_SENDONLY_CLIENT_ID`
  - `GMAIL_SENDONLY_CLIENT_SECRET`
  - `GMAIL_SENDONLY_ACCOUNT_EMAIL`
  - `GMAIL_SENDONLY_ACCOUNT_REFRESH`

### Notes

- The script requests `offline` access to get refresh tokens
- It uses `prompt=consent` to ensure a new refresh token is issued
- The OAuth redirect URI is set to `http://127.0.0.1:3000/oauth`
- Make sure port 3000 is available before running the script
- The script binds to 127.0.0.1 (not 0.0.0.0) for security
