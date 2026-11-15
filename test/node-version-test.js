'use strict';

// The two Node.js thresholds server.js and the dashboard act on, and the guardrail that keeps the
// supported range equal to the engines field npm reads.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');
const { execFileSync } = require('node:child_process');

const { MIN_NODE, SUPPORTED_RANGE_TEXT, nodeSupport, nodeUpgradeHint, nodeRuntimeView } = require('../lib/node-version');

test('nodeSupport()', async t => {
    await t.test('releases EmailEngine can not start on are unsupported', () => {
        for (const version of ['18.20.4', '20.0.0', '20.19.0', '20.20.2', '21.7.3', '22.0.0', '22.18.99', 'v22.12.0']) {
            assert.equal(nodeSupport(version), 'unsupported', version);
        }
    });

    await t.test('releases that start but are outside the declared range are flagged', () => {
        for (const version of ['22.19.0', '22.22.1', '23.11.0', '24.0.0', '24.14.1', '25.9.0', 'v24.14.0']) {
            assert.equal(nodeSupport(version), 'outside-range', version);
        }
    });

    await t.test('releases in the declared range are fine', () => {
        for (const version of ['22.22.2', '22.30.0', '24.15.0', '24.21.0', '26.0.0', '26.11.1', '27.0.0', '30.1.0', 'v24.15.0']) {
            assert.equal(nodeSupport(version), 'ok', version);
        }
    });

    await t.test('a component compared numerically, not as text', () => {
        // '22.9.0' sorts after '22.19.0' as a string
        assert.equal(nodeSupport('22.9.0'), 'unsupported');
        assert.equal(nodeSupport('24.100.0'), 'ok');
    });

    await t.test('a version that can not be read does not stop the start', () => {
        for (const version of ['', 'abc', null, undefined]) {
            assert.equal(nodeSupport(version), 'ok', String(version));
        }
    });

    await t.test('the running Node starts, since CI only runs supported releases here', () => {
        assert.notEqual(nodeSupport(process.versions.node), 'unsupported');
    });
});

test('nodeRuntimeView() flags what the dashboard warns about', () => {
    const view = nodeRuntimeView('v24.14.1');
    assert.equal(view.version, '24.14.1');
    assert.equal(view.supported, '22.x from 22.22.2, 24.x from 24.15.0, or 26 and newer');
    assert.equal(view.outsideRange, true);
    assert.match(view.upgradeCommands.join('\n'), /setup_24\.x[\s\S]*systemctl restart emailengine/);
    // a binary carries its own Node.js, so its operator has nothing to upgrade but EmailEngine
    assert.equal(nodeRuntimeView('24.14.1', true).outsideRange, false);
    assert.equal(nodeRuntimeView('22.19.0').outsideRange, true);
    assert.equal(nodeRuntimeView('24.15.0').outsideRange, false);
    assert.equal(nodeRuntimeView('26.11.1').outsideRange, false);
});

test('the supported range matches engines.node in package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(pathlib.join(__dirname, '..', 'package.json'), 'utf-8'));
    assert.equal(pkg.engines.node, SUPPORTED_RANGE_TEXT);
});

test('the minimum is the floor undici sets', () => {
    // undici is what makes an older release fail at startup; if it ever asks for less, MIN_NODE can follow
    const undiciPkg = require('undici/package.json');
    assert.equal(undiciPkg.engines.node, `>=${MIN_NODE}`);
});

test('the upgrade hint names the commands, not a link that may not exist', () => {
    const hint = nodeUpgradeHint();
    assert.match(hint, /deb\.nodesource\.com\/setup_24\.x/);
    assert.match(hint, /systemctl restart emailengine/);
});

test('server.js checks the version before it requires anything that could fail on an old release', () => {
    const source = fs.readFileSync(pathlib.join(__dirname, '..', 'server.js'), 'utf-8');
    const check = source.indexOf("require('./lib/node-version')");
    assert.ok(check > 0);
    // Everything server.js requires before the check has to load on any Node.js release
    const before = [...source.slice(0, check).matchAll(/require\('([^']+)'\)/g)].map(match => match[1]);
    assert.deepEqual(before, ['dotenv', './lib/read-env-value']);
    assert.ok(source.indexOf("require('undici')") > check);
});

test('lib/node-version.js loads with nothing but its own dependency-free helper', () => {
    const output = execFileSync(
        process.execPath,
        ['-e', "require('./lib/node-version'); console.log(Object.keys(require.cache).map(f => require('path').relative(process.cwd(), f)).sort().join(','))"],
        { cwd: pathlib.join(__dirname, '..'), encoding: 'utf-8' }
    ).trim();
    assert.equal(output, ['lib/node-version.js', 'lib/utils/version.js'].join(','));
});
