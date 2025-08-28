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
              CONNECTION_TIMEOUT: 90000, // 90 seconds in CI
              WEBHOOK_TIMEOUT: 60000 // 60 seconds in CI
          }
        : {})
};
