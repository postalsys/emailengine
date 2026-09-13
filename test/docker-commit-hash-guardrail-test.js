'use strict';

// Guardrail for how the Docker image learns which commit it was built from.
//
// The Dockerfile used to do `COPY .git/refs/heads/master .git/refs/heads/master`, which tied the build
// to one branch name. Any checkout without a local master ref failed before the first build step with
// "failed to compute cache key: /.git/refs/heads/master: not found" - that is every pull_request
// build, since actions/checkout leaves the merge ref detached, and any clone of a single branch. It
// passed on pushes to master, so the only job that builds on pull_request (docker_scan) had been
// failing since it was added, unnoticed because every other PR was a release-please branch that the
// job skips. The ref file is not even reliably a file: a fresh clone packs refs away.
//
// The commit now arrives as the EE_COMMIT_HASH build arg, and the two things worth pinning about that
// are both invisible in a diff:
//
//  - The arg has to be REQUIRED by the build. update-info.sh writes `"commit": ""` rather than failing
//    when it is missing, which is right for its non-Docker callers and wrong here, so the Dockerfile
//    asserts it. Without that assertion a forgotten build-arg ships an image that cannot say what it
//    is, and no test of the workflow text would catch a build run by hand.
//  - The arg has to stay BELOW `npm ci`. An ARG's value is part of the cache key of every RUN after
//    it, verified against BuildKit: declaring it above the install layer makes that layer miss on
//    every commit, because every commit changes the value. Grouping it with the other ARGs at the top
//    of the stage is the obvious tidy-up and would quietly cost a full `npm ci` on every build.

const test = require('node:test');
const assert = require('node:assert').strict;

const { readDockerfile, copiedSources } = require('./helpers/dockerfile');

const BUILD_ARG = 'EE_COMMIT_HASH';

const dockerfile = readDockerfile();
const lines = dockerfile.split('\n');

// Index of the first line matching a pattern, or -1.
function lineIndex(pattern) {
    return lines.findIndex(line => pattern.test(line));
}

test('Docker build commit hash wiring', async t => {
    await t.test('nothing is copied out of .git', () => {
        const fromGit = [...copiedSources(dockerfile)].filter(source => source === '.git' || source.startsWith('.git/')).sort();

        assert.deepStrictEqual(
            fromGit,
            [],
            `the Dockerfile copies these out of .git, which only exists for the branch that happens to be ` +
                `checked out (and not even then, once refs are packed). Pass the commit as the ${BUILD_ARG} build arg instead.`
        );
    });

    await t.test(`declares ${BUILD_ARG}`, () => {
        assert.ok(
            lineIndex(new RegExp(`^ARG\\s+${BUILD_ARG}\\s*$`)) !== -1,
            `the Dockerfile must declare "ARG ${BUILD_ARG}" for the build arg to reach update-info.sh`
        );
    });

    await t.test('the build fails when no commit is supplied', () => {
        // `: "${VAR:?message}"` is shell for "expand, or abort with this message".
        assert.match(
            dockerfile,
            new RegExp(`\\$\\{${BUILD_ARG}:\\?`),
            `the Dockerfile must require ${BUILD_ARG} with a \${${BUILD_ARG}:?...} check. update-info.sh writes an ` +
                `empty commit rather than failing, so without this a build that forgets the arg silently ships an ` +
                `image that cannot report its commit.`
        );
    });

    await t.test(`${BUILD_ARG} is declared after the dependency install, so it cannot bust that layer`, () => {
        const argAt = lineIndex(new RegExp(`^ARG\\s+${BUILD_ARG}\\s*$`));
        const installAt = lineIndex(/^RUN\s+npm\s+ci\b/);

        assert.ok(installAt !== -1, 'could not find the `RUN npm ci` line in the Dockerfile; this check is no longer looking at anything');
        assert.ok(
            argAt > installAt,
            `ARG ${BUILD_ARG} is declared on line ${argAt + 1}, above the "npm ci" on line ${installAt + 1}. An ARG's value ` +
                `is part of the cache key of every RUN below it, so the install layer would be rebuilt on every commit. ` +
                `Keep the ARG below the install.`
        );
    });
});
