'use strict';

// Playwright config for the EmailEngine happy-path e2e suite (test/e2e). Boots a fresh
// EmailEngine via the webServer command (flush the isolated Redis db 14, then `node server.js`
// with NODE_ENV=e2e -> config/e2e.toml) and drives it with a real browser.
//
// Run once:  npm run test:e2e:install   (fetch the Chromium browser)
// Run suite: npm run test:e2e

const { defineConfig, devices } = require('@playwright/test');

const { BASE_URL } = require('./test/e2e/helpers/bootstrap');

module.exports = defineConfig({
    testDir: './test/e2e',
    testMatch: '**/*.spec.js',
    // One worker against one app + one database keeps the fresh-instance flow predictable.
    fullyParallel: false,
    workers: 1,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    // The single happy-path test chains several slow external steps (Ethereal provisioning,
    // trial activation against postalsys.com, IMAP connect, message read-back).
    timeout: 300000,
    reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
    use: {
        baseURL: BASE_URL,
        trace: 'on-first-retry'
    },
    projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
    webServer: {
        // Flush the isolated e2e Redis DB so every run starts from a clean, unconfigured instance.
        command: 'node test/e2e/flush-redis.js && node server.js',
        url: BASE_URL,
        timeout: 120000,
        // Always boot fresh: the suite asserts fresh-instance behaviour (enabling auth, activating
        // the trial), so a reused server with those already set would break it. The dedicated
        // db 14 makes the pre-boot flush safe.
        reuseExistingServer: false,
        stdout: 'pipe',
        stderr: 'pipe',
        // EENGINE_DOCUMENT_STORE_ENABLED opens the deprecated Document Store
        // gate so its admin pages render (they 404 with the gate off) - the
        // pages-admin spec smoke-tests them
        env: Object.assign({}, process.env, { NODE_ENV: 'e2e', EENGINE_DOCUMENT_STORE_ENABLED: 'true' })
    }
});
