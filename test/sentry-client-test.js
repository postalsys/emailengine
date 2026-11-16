'use strict';

// lib/sentry.js builds its client from @sentry/core with EmailEngine's own ContextLines, Context and
// Modules integrations (lib/sentry-integrations.js), which replaced @sentry/node-core. The first
// test captures an event through the real client and a stub transport and checks the fields the
// node-core SDK used to send are all there.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const pathlib = require('node:path');

const { createTransport } = require('@sentry/core');
const { startSentry, SENTRY_RELEASE, createGetModuleFromFilename } = require('../lib/sentry');
const { addContextToFrame, getOsContext, collectModules, packageDirOf } = require('../lib/sentry-integrations');
const logger = require('../lib/logger');
const exitWhenStandalone = require('./helpers/exit-standalone');

exitWhenStandalone();

function thrower() {
    const err = new Error('outer', { cause: new TypeError('inner') });
    err.code = 'ETEST';
    throw err;
}

test('an event carries what the node-core SDK sent', async () => {
    const envelopes = [];
    startSentry('https://public@sentry.example.com/1', {
        transport: options =>
            createTransport(options, async request => {
                envelopes.push(String(request.body));
                return { statusCode: 200, headers: {} };
            })
    });

    try {
        thrower();
    } catch (err) {
        logger.notifyError(err, { tags: { component: 'test' }, meta: { account: 'a1' }, user: 'u1', level: 'warning' });
    }
    await logger.flushNotifications();

    assert.equal(envelopes.length, 1);
    const event = JSON.parse(envelopes[0].split('\n')[2]);

    assert.equal(event.platform, 'node');
    assert.equal(event.release, SENTRY_RELEASE);
    assert.equal(event.environment, 'production');
    assert.equal(event.level, 'warning');
    assert.ok(event.server_name);
    assert.deepEqual(event.user, { id: 'u1' });
    assert.equal(event.tags.component, 'test');
    assert.deepEqual(event.contexts.ee, { account: 'a1' });
    assert.deepEqual(event.contexts.runtime, { name: 'node', version: process.version });

    for (const key of ['app_start_time', 'app_memory']) {
        assert.ok(key in event.contexts.app, `app.${key}`);
    }
    for (const key of ['boot_time', 'arch', 'memory_size', 'free_memory', 'processor_count', 'cpu_description']) {
        assert.ok(key in event.contexts.device, `device.${key}`);
    }
    for (const key of ['name', 'kernel_version']) {
        assert.ok(event.contexts.os[key], `os.${key}`);
    }
    assert.ok(event.contexts.culture.timezone);

    assert.equal(event.sdk.name, 'sentry.javascript.node');
    assert.deepEqual(event.sdk.integrations, ['EventFilters', 'FunctionToString', 'LinkedErrors', 'ContextLines', 'Context', 'Modules']);

    // the cause is linked, and each frame of this file has its module name and source lines
    assert.deepEqual(
        event.exception.values.map(value => [value.type, value.value]),
        [
            ['TypeError', 'inner'],
            ['Error', 'outer']
        ]
    );
    const frame = event.exception.values[1].stacktrace.frames.find(f => f.function === 'thrower');
    assert.equal(frame.module, 'test:sentry-client-test');
    assert.equal(frame.in_app, true);
    assert.equal(frame.context_line.trim(), "const err = new Error('outer', { cause: new TypeError('inner') });");
    assert.equal(frame.pre_context.length, 7);
    assert.equal(frame.post_context.length, 7);

    assert.equal(event.modules['@sentry/core'], require('@sentry/core/package.json').version);
    assert.equal(event.modules['@hapi/hapi'], require('../package.json').dependencies['@hapi/hapi']);
});

test('context lines', async t => {
    const lines = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`);

    await t.test('takes seven lines either side', () => {
        const frame = { lineno: 10 };
        addContextToFrame(frame, lines);
        assert.deepEqual(frame.pre_context, lines.slice(2, 9));
        assert.equal(frame.context_line, 'line 10');
        assert.deepEqual(frame.post_context, lines.slice(10, 17));
    });

    await t.test('stops at the start and the end of the file', () => {
        const first = { lineno: 1 };
        addContextToFrame(first, lines);
        assert.deepEqual(first.pre_context, []);
        const last = { lineno: 20 };
        addContextToFrame(last, lines);
        assert.deepEqual(last.post_context, []);
    });

    await t.test('leaves a frame whose line is not in the file alone', () => {
        const frame = { lineno: 21 };
        addContextToFrame(frame, lines);
        assert.equal(frame.context_line, undefined);
        assert.equal(frame.pre_context, undefined);
    });
});

test('os context', async t => {
    const fakeOs = { release: () => '25.6.0', version: () => 'Darwin Kernel Version 25.6.0' };

    await t.test('macOS from SystemVersion.plist', async () => {
        const plist =
            '<dict><key>ProductBuildVersion</key>\n<string>25G83</string><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>26.6.2</string></dict>';
        const context = await getOsContext({ platform: 'darwin', os: fakeOs, readFile: async () => plist });
        assert.deepEqual(context, { kernel_version: '25.6.0', name: 'macOS', version: '26.6.2', build: '25G83' });
    });

    await t.test('macOS from the kernel version when the plist cannot be read', async () => {
        const failing = async () => {
            throw new Error('ENOENT');
        };
        assert.equal((await getOsContext({ platform: 'darwin', os: fakeOs, readFile: failing })).version, '26');
        assert.equal((await getOsContext({ platform: 'darwin', os: { ...fakeOs, release: () => '24.1.0' }, readFile: failing })).version, '15');
        assert.equal((await getOsContext({ platform: 'darwin', os: { ...fakeOs, release: () => '19.6.0' }, readFile: failing })).version, '10.15');
    });

    await t.test('Linux from /etc/os-release', async () => {
        const content = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n';
        const context = await getOsContext({ platform: 'linux', os: { release: () => '6.8.0-45-generic' }, readFile: async () => content });
        assert.deepEqual(context, { kernel_version: '6.8.0-45-generic', name: 'Ubuntu', version: '24.04' });
    });

    await t.test('Linux without /etc/os-release', async () => {
        const context = await getOsContext({
            platform: 'linux',
            os: { release: () => '6.8.0' },
            readFile: async () => {
                throw new Error('ENOENT');
            }
        });
        assert.deepEqual(context, { kernel_version: '6.8.0', name: 'Linux' });
    });

    await t.test('Windows', async () => {
        const context = await getOsContext({
            platform: 'win32',
            os: { release: () => '10.0.22631', version: () => 'Windows 11 Pro' },
            readFile: async () => ''
        });
        assert.deepEqual(context, { name: 'Windows', version: '10.0.22631', kernel_version: 'Windows 11 Pro' });
    });

    await t.test('runs no command', () => {
        const source = fs.readFileSync(pathlib.join(__dirname, '..', 'lib', 'sentry-integrations.js'), 'utf8');
        assert.doesNotMatch(source, /child_process/);
    });
});

test('modules', async t => {
    await t.test('finds the package a loaded file belongs to', () => {
        const sep = pathlib.sep;
        const nm = ['', 'app', 'node_modules'].join(sep);
        assert.equal(packageDirOf([nm, 'undici', 'lib', 'index.js'].join(sep)), [nm, 'undici'].join(sep));
        assert.equal(packageDirOf([nm, '@hapi', 'hapi', 'lib', 'server.js'].join(sep)), [nm, '@hapi', 'hapi'].join(sep));
        assert.equal(packageDirOf([nm, 'a', 'node_modules', 'b', 'index.js'].join(sep)), [nm, 'a', 'node_modules', 'b'].join(sep));
        assert.equal(packageDirOf(['', 'app', 'lib', 'tools.js'].join(sep)), null);
    });

    await t.test('lists the dependencies and the versions actually loaded', () => {
        const modules = collectModules([require.resolve('@hapi/hapi'), require.resolve('@sentry/core')]);
        assert.equal(modules['@hapi/hapi'], require('@hapi/hapi/package.json').version);
        assert.equal(modules['@sentry/core'], require('@sentry/core/package.json').version);
        // the application's dependency list is in, its devDependencies are not
        assert.ok('undici' in modules);
        assert.ok(!('eslint' in modules));
    });
});

test('module names of stack frames', () => {
    const getModule = createGetModuleFromFilename('/app');
    assert.equal(getModule('/app/lib/tools.js'), 'lib:tools');
    assert.equal(getModule('/app/server.js'), 'server');
    assert.equal(getModule('/app/node_modules/@hapi/hapi/lib/server.js'), '@hapi.hapi.lib:server');
    assert.equal(getModule('/elsewhere/file.cjs'), 'file');
    // Windows paths, as a binary on Windows reports them
    assert.equal(createGetModuleFromFilename('C:\\app')('C:\\app\\lib\\tools.js'), 'lib:tools');
    assert.equal(createGetModuleFromFilename('C:\\app')('C:\\app\\node_modules\\undici\\index.js'), 'undici:index');
    assert.equal(getModule(undefined), undefined);
});
