'use strict';

/**
 * Test configuration for EmailEngine test suite
 * Timeout values are configured to handle Gmail API operations
 * which may take longer due to network latency and API processing
 */

module.exports = {
    // Default timeout for standard operations
    DEFAULT_TIMEOUT: 30000, // 30 seconds

    // Timeout for Gmail API operations
    GMAIL_TIMEOUT: 90000, // 90 seconds

    // Timeout for a Google Workspace mailbox to connect over IMAP XOAUTH2. A healthy login is done
    // in 1-2 s, but Gmail has been seen answering every command of one at 13-37 s (AUTHENTICATE
    // 37 s, NAMESPACE 21 s, COMPRESS 15 s, ENABLE 13 s), still mid-LIST at 90 s, with EmailEngine
    // writing each command at once. Sized for that, and below the runner's 180 s per-test cap
    GMAIL_IMAP_CONNECT_TIMEOUT: 160000, // 160 seconds

    // Timeout for Outlook Graph API operations
    OUTLOOK_TIMEOUT: 90000, // 90 seconds

    // Timeout for waiting for account connections
    CONNECTION_TIMEOUT: 60000, // 60 seconds

    // Timeout for webhook notifications
    WEBHOOK_TIMEOUT: 30000, // 30 seconds

    // Polling interval for checking conditions
    POLL_INTERVAL: 1000, // 1 second

    // Environment-specific overrides
    ...(process.env.CI
        ? {
              // Increase timeouts in CI environment
              GMAIL_TIMEOUT: 120000, // 2 minutes in CI
              OUTLOOK_TIMEOUT: 120000, // 2 minutes in CI
              CONNECTION_TIMEOUT: 90000, // 90 seconds in CI
              WEBHOOK_TIMEOUT: 60000 // 60 seconds in CI
          }
        : {})
};
