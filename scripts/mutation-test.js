#!/usr/bin/env node
/* eslint no-console: 0 */
'use strict';

// Mutation testing for the pure decision modules, the ones whose rules are easy to get subtly
// wrong and whose tests are meant to pin every rule: the learned IDLE interval, the IDLE settings,
// the tracking flags and the lock wrapper.
//
// Each mutant is one source file with one small change (a flipped comparison, a swapped boolean
// operator, an off by one constant, a dropped negation, min for max). The mutant is written into a
// private copy of the repository and the suites for that file run against it. A mutant no test
// catches ("survives") marks behavior the suites do not pin: either a missing assertion, or an
// equivalent mutant that can not change any output, which has to be judged by hand.
//
// Usage: npm run test:mutation -- [--workers 4] [--max 200] [--file lib/email-client/imap/adaptive-idle.js]
// Needs the test Redis, as the unit tier does. Survivors are written to survivors.json in a new
// directory under the system temp directory, whose path the run prints; the repository itself is
// never modified. Not part of `npm test`: a full run takes minutes.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
const opt = (name, def) => {
    const i = args.indexOf('--' + name);
    return i >= 0 ? args[i + 1] : def;
};

// The suites that cover each source file; a mutant runs only the ones for its file
const TESTS_BY_FILE = {
    'lib/email-client/imap/adaptive-idle.js': ['test/adaptive-idle-test.js', 'test/adaptive-idle-store-test.js', 'test/adaptive-idle-simulation-test.js'],
    'lib/email-client/imap/adaptive-idle-store.js': ['test/adaptive-idle-store-test.js', 'test/adaptive-idle-simulation-test.js'],
    'lib/email-client/imap/idle-settings.js': ['test/imap-idle-settings-test.js', 'test/adaptive-idle-test.js', 'test/adaptive-idle-simulation-test.js'],
    'lib/utils/tracking-settings.js': ['test/tracking-settings-test.js', 'test/queue-message-entry-test.js'],
    'lib/lock-run.js': ['test/lock-run-test.js']
};
const FILES = opt('file', '') ? [opt('file')] : Object.keys(TESTS_BY_FILE);
const WORKERS = Number(opt('workers', Math.max(2, Math.min(6, os.cpus().length - 2))));
const MAX = Number(opt('max', 0));

// What a workspace needs for the unit suites to load: the code, the tests and the configuration
const WORKSPACE_ENTRIES = ['lib', 'test', 'config', 'data', 'workers', 'translations', 'server.js', 'package.json'];

// operator replacements, applied to code (comments are skipped)
const OPERATORS = [
    [/[=]==/g, '!=='],
    [/!==/g, '==='],
    [/ <= /g, ' < '],
    [/ < /g, ' <= '],
    [/ >= /g, ' > '],
    [/ > /g, ' >= '],
    [/ && /g, ' || '],
    [/ \|\| /g, ' && '],
    [/ \?\? /g, ' || '],
    [/ \+ 1\b/g, ' + 2'],
    [/ - 1\b/g, ' - 2'],
    [/\+\+/g, '--'],
    [/\btrue\b/g, 'false'],
    [/\bfalse\b/g, 'true'],
    [/Math\.min\(/g, 'Math.max('],
    [/Math\.max\(/g, 'Math.min('],
    [/\(!(?!=)/g, '('],
    [/ !(?=[\w.(])/g, ' ']
];

// Lines that carry no runtime behavior
const SKIP_LINE = /^\s*(\*|\/\*|\/\/|'use strict'|const \w+ = require\(|module\.exports)/;

function mutantsOf(file) {
    const lines = fs.readFileSync(path.join(ROOT, file), 'utf8').split('\n');
    const mutants = [];
    let inBlockComment = false;
    lines.forEach((line, index) => {
        if (inBlockComment) {
            inBlockComment = !line.includes('*/');
            return;
        }
        if (/^\s*\/\*/.test(line) && !line.includes('*/')) {
            inBlockComment = true;
            return;
        }
        const code = line.replace(/\/\/.*$/, '');
        if (SKIP_LINE.test(line) || !code.trim()) {
            return;
        }
        for (const [pattern, replacement] of OPERATORS) {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(code))) {
                const mutatedLine = line.slice(0, match.index) + replacement + line.slice(match.index + match[0].length);
                if (mutatedLine !== line) {
                    mutants.push({ file, line: index + 1, from: line.trim(), to: mutatedLine.trim(), mutatedLine });
                }
            }
        }
    });
    return mutants;
}

function makeWorkspace(n) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `emailengine-mutant-${n}-`));
    for (const entry of WORKSPACE_ENTRIES) {
        if (fs.existsSync(path.join(ROOT, entry))) {
            fs.cpSync(path.join(ROOT, entry), path.join(dir, entry), { recursive: true });
        }
    }
    fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'));
    return dir;
}

function runTests(dir, tests, onFailure) {
    return new Promise(resolve => {
        execFile(
            process.execPath,
            // a mutant that makes a test hang fails at the per-test timeout, and one that blocks the
            // event loop is stopped by the process timeout; both count as killed
            ['--test', '--test-force-exit', '--test-concurrency=1', '--test-timeout=20000', ...tests],
            {
                cwd: dir,
                env: Object.assign({}, process.env, { NODE_ENV: 'test' }),
                timeout: 3 * 60 * 1000,
                maxBuffer: 64 * 1024 * 1024
            },
            (err, stdout, stderr) => {
                if (err && onFailure) {
                    onFailure(`${stdout}${stderr}`);
                }
                resolve(!err);
            }
        );
    });
}

async function main() {
    let mutants = FILES.flatMap(mutantsOf);
    if (MAX && mutants.length > MAX) {
        // an even sample over all files
        const step = mutants.length / MAX;
        mutants = Array.from({ length: MAX }, (_, i) => mutants[Math.floor(i * step)]);
    }
    const allTests = [...new Set(FILES.flatMap(file => TESTS_BY_FILE[file] || []))];
    console.log(`${mutants.length} mutants, ${WORKERS} workers, tests: ${allTests.length} files`);

    const workspaces = Array.from({ length: WORKERS }, (_, i) => makeWorkspace(i));
    try {
        // the unmutated code must pass first, otherwise every mutant would look killed
        if (!(await runTests(workspaces[0], allTests, output => console.error(output.split('\n').slice(-40).join('\n'))))) {
            console.error('the suites fail on the unmutated code');
            process.exitCode = 1;
            return;
        }
        let next = 0;
        let killed = 0;
        const survivors = [];
        const started = Date.now();
        await Promise.all(
            workspaces.map(async dir => {
                while (next < mutants.length) {
                    const mutant = mutants[next++];
                    const target = path.join(dir, mutant.file);
                    const original = fs.readFileSync(target, 'utf8');
                    const lines = original.split('\n');
                    lines[mutant.line - 1] = mutant.mutatedLine;
                    fs.writeFileSync(target, lines.join('\n'));
                    const passed = await runTests(dir, TESTS_BY_FILE[mutant.file]);
                    fs.writeFileSync(target, original);
                    if (passed) {
                        survivors.push(mutant);
                        console.log(`SURVIVED ${mutant.file}:${mutant.line}\n    - ${mutant.from}\n    + ${mutant.to}`);
                    } else {
                        killed++;
                    }
                    const done = killed + survivors.length;
                    if (done % 20 === 0) {
                        console.log(`  ${done}/${mutants.length} done, ${survivors.length} survived, ${Math.round((Date.now() - started) / 1000)}s`);
                    }
                }
            })
        );

        console.log(`\nkilled ${killed}, survived ${survivors.length}, mutation score ${((100 * killed) / mutants.length).toFixed(1)}%`);
        // a directory of its own: a fixed name in a shared temp directory could be planted
        const report = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'emailengine-mutation-')), 'survivors.json');
        survivors.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
        fs.writeFileSync(
            report,
            JSON.stringify(
                survivors.map(({ mutatedLine: _mutatedLine, ...m }) => m),
                null,
                2
            )
        );
        console.log(`survivors written to ${report}`);
    } finally {
        for (const dir of workspaces) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    }
}

main().catch(err => {
    console.error(err);
    process.exitCode = 1;
});
