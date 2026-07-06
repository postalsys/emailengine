'use strict';

const config = require('@zone-eu/wild-config');

module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        shell: {
            eslint: {
                // Globs are quoted so eslint expands them itself - unquoted, sh (no globstar)
                // expands lib/**/*.js to depth-2 files only and skips most of lib/
                command: "npx eslint 'lib/**/*.js' 'workers/**/*.js' server.js Gruntfile.js"
            },
            server: {
                // Short Gmail fallback-poll interval so gmail-polling-test can exercise the poller
                // quickly. Harmless for push-based Gmail accounts in api-test: notifications keep
                // resetting the timer, and a stray fallback sync is coalesced/idempotent.
                command: 'EENGINE_GMAIL_FALLBACK_POLL_INTERVAL=15000 node server.js',
                options: {
                    async: true
                }
            },
            flush: {
                command: `redis-cli -u "${config.dbs.redis}" flushdb`
            },
            waitServer: {
                // Polls /health until the server reports ready (all IMAP workers up,
                // Redis responding) instead of sleeping for a fixed delay
                command: 'node test/helpers/wait-for-server.js'
            },
            testUnit: {
                // Self-contained tests - need Redis but not the live server.
                // Run with default --test concurrency; the suite is verified to pass in parallel.
                // The *-test.js pattern keeps helper modules out of the test runner
                command: 'node --test --test-timeout=180000 test/*-test.js'
            },
            testIntegration: {
                // Tests that run against the live server started by shell:server
                command: 'node --test --test-concurrency=1 --test-timeout=180000 test/integration/*-test.js'
            },
            options: {
                stdout: data => console.log(data.toString().trim()),
                stderr: data => console.log(data.toString().trim()),
                failOnError: true
            }
        }
    });

    // Load the plugin(s)
    grunt.loadNpmTasks('grunt-shell-spawn');

    // Tasks
    grunt.registerTask('test-unit', ['shell:flush', 'shell:testUnit']);
    grunt.registerTask('test-integration', ['shell:flush', 'shell:server', 'shell:waitServer', 'shell:testIntegration', 'shell:server:kill']);
    grunt.registerTask('test', ['test-unit', 'test-integration']);

    grunt.registerTask('default', ['shell:eslint', 'test']);
};
