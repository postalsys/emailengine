'use strict';

const config = require('wild-config');

module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        eslint: {
            all: ['lib/**/*.js', 'server.js', 'worker.js', 'Gruntfile.js']
        },

        wait: {
            server: {
                options: {
                    delay: 12 * 1000
                }
            }
        },

        shell: {
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
                command: 'node --test test/',
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
    grunt.loadNpmTasks('grunt-eslint');
    grunt.loadNpmTasks('grunt-shell-spawn');
    grunt.loadNpmTasks('grunt-wait');

    // Tasks
    grunt.registerTask('test', ['shell:flush', 'shell:server', 'wait:server', 'shell:test', 'shell:server:kill']);

    grunt.registerTask('default', ['eslint', 'test']);
};
