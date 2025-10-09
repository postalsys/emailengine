'use strict';

const config = require('wild-config');

module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        wait: {
            server: {
                options: {
                    delay: 20 * 1000 // Increased from 12s to 20s for Gmail API operations
                }
            }
        },

        shell: {
            eslint: {
                command: 'npx eslint lib/**/*.js workers/**/*.js server.js Gruntfile.js',
                options: {
                    async: false
                }
            },
            server: {
                command: 'node server.js',
                options: {
                    async: true
                }
            },
            flush: {
                command: `redis-cli -u "${config.dbs.redis}" flushdb`,
                options: {
                    async: false
                }
            },
            test: {
                command: 'node --test --test-concurrency=1 --test-timeout=120000 test/*.js', // Added 2-minute timeout for tests
                options: {
                    async: false
                }
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
    grunt.loadNpmTasks('grunt-wait');

    // Tasks
    grunt.registerTask('test', ['shell:flush', 'shell:server', 'wait:server', 'shell:test', 'shell:server:kill']);

    grunt.registerTask('default', ['shell:eslint', 'test']);
};
