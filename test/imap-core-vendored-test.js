'use strict';

// Runs the test suite bundled with the vendored lib/imapproxy/imap-core fork.
//
// Those specs are upstream WildDuck files written for mocha, and they had never been executed
// here - the fork has since been patched in place with security fixes (inbound line-length bounds
// in the parser, STARTTLS command-injection hardening, post-BYE dispatch), and nothing was
// checking that the patches left the protocol handling intact.
//
// The vendored files are deliberately NOT edited: keeping them byte-identical to upstream is what
// makes the fork's patch list (see lib/imapproxy/imap-core/README.md) reviewable. Instead this
// adapter installs the handful of mocha globals they expect, then requires them.
//
// Only the hermetic specs are wired up. protocol-test.js and search-test.js drive a live server
// through test-server.js, which needs MongoDB and a WildDuck API; see the README for that gap.

const nodeTest = require('node:test');

// mocha calls hook and test bodies with a context exposing timeout()/slow()/retries(). Node's
// runner has no equivalent, and the specs only ever use them to widen a timeout, so they are
// accepted and ignored (the runner is invoked with --test-timeout instead).
const mochaContext = {
    timeout() {},
    slow() {},
    retries() {},
    skip() {}
};

// mocha passes `done` as the first argument; node:test passes (t, done) and only supplies `done`
// when the function declares two parameters. Bridge the two shapes.
const adapt = fn => {
    if (typeof fn !== 'function') {
        return fn;
    }

    if (fn.length === 0) {
        return function () {
            return fn.call(mochaContext);
        };
    }

    return function (t, done) {
        return fn.call(mochaContext, done);
    };
};

const wrap = nodeFn =>
    function (name, fn) {
        return typeof name === 'function' ? nodeFn(adapt(name)) : nodeFn(name, adapt(fn));
    };

global.describe = wrap(nodeTest.describe);
global.describe.skip = wrap(nodeTest.describe.skip);
global.it = wrap(nodeTest.it);
global.it.skip = wrap(nodeTest.it.skip);
global.before = wrap(nodeTest.before);
global.after = wrap(nodeTest.after);
global.beforeEach = wrap(nodeTest.beforeEach);
global.afterEach = wrap(nodeTest.afterEach);

require('../lib/imapproxy/imap-core/test/imap-parser-test.js');
require('../lib/imapproxy/imap-core/test/imap-compiler-test.js');
require('../lib/imapproxy/imap-core/test/imap-compile-stream-test.js');
require('../lib/imapproxy/imap-core/test/imap-indexer-test.js');
require('../lib/imapproxy/imap-core/test/tools-test.js');
