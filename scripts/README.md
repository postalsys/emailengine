# Scripts

## build-icon.js

Regenerates `static/emailengine.ico` from `static/logo.png`. The result is committed, so run
this only when the logo artwork changes - a normal build does not need ImageMagick.

### Usage

```bash
brew install imagemagick
npm run build:icon
```

### What it does

Builds a 7-image icon (256, 128, 64, 48, 32, 24, 16), PNG-compressing the two largest members
and using uncompressed 32-bit DIBs for the rest.

### Notes

- Do not replace it with a plain `magick -define icon:auto-resize=...` call. ImageMagick writes
  every member as an uncompressed BMP, and the resulting icon is large enough to break the
  packaged Windows executable outright. The header comment in the script explains why.
- `winconf.js` prints the remaining `.rsrc` headroom on every build. That number is the budget
  for any future icon or resource change.

## refresh-test-tokens.js

Helper script to refresh OAuth2 tokens for Gmail test accounts.

### Usage

```bash
npm install googleapis
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
