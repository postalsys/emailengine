'use strict';

// Shared lint baseline for the Postal Systems / Nodemailer packages: eslint:recommended
// plus the rules of the retired eslint-config-nodemailer, with formatting left to Prettier.
// Keep this file identical across repos except for the "Repo-specific" block at the end.

const js = require('@eslint/js');
const prettier = require('eslint-config-prettier');
const globals = require('globals');

module.exports = [
    {
        ignores: ['node_modules/**', 'coverage/**', 'dist/**', 'ee-dist/**', 'static/**']
    },
    js.configs.recommended,
    {
        files: ['**/*.js', '**/*.cjs'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: { ...globals.node }
        },
        rules: {
            'no-await-in-loop': 'error',
            'no-div-regex': 'error',
            strict: ['error', 'global'],
            eqeqeq: 'error',
            'dot-notation': 'error',
            curly: 'error',
            'no-unused-expressions': ['error', { allowShortCircuit: true }],
            'no-unused-vars': ['error', { varsIgnorePattern: '^_', argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
            'handle-callback-err': 'error',
            'no-new': 'error',
            'new-cap': 'error',
            'no-eval': 'error',
            'no-invalid-this': 'error',
            radix: ['error', 'always'],
            'no-use-before-define': ['error', 'nofunc'],
            'callback-return': ['error', ['callback', 'cb', 'done']],
            'no-redeclare': 'error',
            'block-scoped-var': 'error',
            'no-sequences': 'error',
            'no-throw-literal': 'error',
            'no-useless-call': 'error',
            'no-useless-concat': 'error',
            'no-void': 'error',
            yoda: 'error',
            'no-var': 'error',
            'no-bitwise': 'error',
            'no-lonely-if': 'error',
            'arrow-body-style': ['error', 'as-needed'],
            'prefer-arrow-callback': 'error',
            'object-shorthand': 'error',
            'prefer-spread': 'error',
            'no-prototype-builtins': 'off'
        }
    },
    {
        files: ['test/**'],
        languageOptions: {
            globals: { ...globals.node, ...globals.mocha }
        }
    },
    // Repo-specific: overrides go here, each with a one-line reason
    {
        // The vendored imap-core suite (lib/imapproxy/imap-core/test) is mocha-shaped and lives outside test/
        files: ['lib/imapproxy/imap-core/test/**'],
        languageOptions: {
            globals: { ...globals.node, ...globals.mocha }
        }
    },
    {
        rules: {
            // 524 violations: workers and sync loops await sequentially on purpose (ordering, backpressure, rate limits)
            'no-await-in-loop': 'off',
            // 264 violations: 256 unused catch bindings (optional catch binding would churn 100+ files) and 8 named
            // parameters kept for documented interfaces (base-class stubs, provider overrides, test doubles)
            'no-unused-vars': ['error', { varsIgnorePattern: '^_', args: 'none', caughtErrors: 'none' }],
            // 48 violations: IMAP/MIME parsers, crypto, flag masks and hashing need bitwise operators
            'no-bitwise': 'off',
            // 20 violations: closures and hoisted helpers referencing later module-level bindings, fixing means reordering modules
            'no-use-before-define': 'off',
            // 13 violations: SCREAMING_CASE factory constants, the TLS SNICallback option and node:test's lowercase spec reporter class
            'new-cap': 'off',
            // 11 violations: Handlebars helpers and test stubs use the call-site this by design
            'no-invalid-this': 'off',
            // 10 violations: stream transform callbacks followed by other statements, rewriting them risks changing flow
            'callback-return': 'off',
            // 9 violations, all deliberate x == null / x != null checks that cover both null and undefined
            eqeqeq: ['error', 'always', { null: 'ignore' }]
        }
    },
    prettier
];
