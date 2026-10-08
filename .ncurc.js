module.exports = {
    upgrade: true,
    // Node 20 is a hard runtime floor, not a preference. The DigitalOcean one-click images run
    // EmailEngine on Node 20 and ship an upgrade script for EmailEngine but none for Node, so those
    // installs keep self-updating on a runtime that never moves; raising the floor breaks them on
    // their next upgrade. Node 20 being EOL upstream, and CI and the pkg targets being on Node 24,
    // do not lift this. Treat "needs Node >20" as a permanent reject.
    //
    // Packages capped inside their current major: the next major is ESM-only (this codebase is
    // CommonJS and is bundled into a binary with pkg), needs a Node newer than the floor above, or
    // is a major we are deliberately soaking. Using 'minor' instead of a blanket reject so these
    // still receive security/patch updates within the safe major instead of being frozen at one
    // exact version. Verified against Node 20 (Docker) 2026-06-17.
    //
    // `pino` is capped harder than the rest, at 'patch', because the break arrived in a MINOR and a
    // major cap would not have stopped it. See its entry below.
    target: name =>
        ['pino', '@playwright/test'].includes(name)
            ? 'patch'
            : ['nanoid', 'gettext-parser', 'xgettext-template', 'chai', 'undici', 'marked', '@sentry/node-core', 'he'].includes(name)
              ? 'minor'
              : 'latest',
    //   pino              - held on 10.3.x. 10.4.0 took PR #2294, which makes lib/caller.js prefer
    //                       util.getCallSites() over the Error.prepareStackTrace dance. Inside a pkg
    //                       binary that API aborts the PROCESS, not the call: V8 fails the CHECK in
    //                       Script::GetPositionInfo() for a script that has no position info in the
    //                       snapshot, and the binary dies on startup with SIGTRAP (exit 133) before
    //                       main() does anything. `emailengine --version` is enough to trigger it.
    //                       Reproduced on node24-macos-arm64 and caught by the linux-x64 binary build
    //                       job, which exists for exactly this. Nothing in EmailEngine calls the API:
    //                       pino reaches it whenever a logger is constructed. Lift only once a pino
    //                       release guards the getCallSites path, or pkg ships position info for
    //                       snapshotted scripts, and only with a binary built and run to prove it.
    //   @playwright/test  - held on 1.63.x (dev only, the e2e tier). Under 1.64.0 the busy-state spec
    //                       (test/e2e/pages-ui-busy-state.spec.js) hangs: it answers a form's navigation
    //                       POST with route.fulfill({ status: 204 }) so the page stays put, and after that
    //                       click 1.64 never resolves a locator assertion on the same page (toBeDisabled
    //                       times out with "Received: undefined" while the page snapshot shows the button).
    //                       Same spec passes in 3.8 s on 1.63.0; nothing in the 1.64 release notes covers
    //                       it. Lift once a 1.64.x or later passes that spec unchanged.
    //   nanoid            - 4.x dropped the CommonJS require export (ESM-only)
    //   gettext-parser    - 8.x is ESM-only
    //   xgettext-template - 6.x is ESM-only (translation build tool)
    //   chai              - 5.x is ESM-only (only used by the vendored imap-core tests)
    //   undici            - 8.x requires Node >=22.19 and crashes at require() on Node 20. Permanent while the
    //                       Node 20 floor above stands.
    //   marked            - 16.x dropped the CommonJS build (ESM-only, needs require(esm)/Node >=20.19); 15.x is the
    //                       last require()-compatible line. 15.0.12 verified on Node 20-24 and in a yao/pkg node24 build.
    //                       Permanent while the Node 20 floor above stands.
    //   he                - 2.x is ESM-only (exports only src/he.mjs) and requires Node >=22; require('he') throws
    //                       ERR_REQUIRE_ESM on Node 20 before 20.19. 1.2.0 is the last CommonJS release. mailparser,
    //                       which reaches EmailEngine through the same require, rejects 2.x for the same reason.
    //   @sentry/node-core - held on the 10.x line for the reasons @sentry/node (which it replaced, through its
    //                       `light` entry) was held there: @sentry/node 11.x requires Node >=20.19 (the DigitalOcean
    //                       images are not guaranteed to be on a 20.x that new), and it depends on
    //                       @sentry/bundler-plugins, which pulls the 16 MB Sentry CLI (package `sentry`, licensed
    //                       FSL-1.1-Apache-2.0, not an OSI license) into the runtime tree and the pkg bundle. The
    //                       node-core line is versioned in step with @sentry/node, so lift this only once an 11.x
    //                       of node-core exists and has been checked against both points.
    //
    // ical.js was capped at 1.x here as "2.x is ESM-only", which was never true: every 2.x ships a CommonJS
    // build behind exports.require. Moved to 2.x on 2026-09-28; it is also what resolves a DTSTART against
    // the VTIMEZONE embedded in the same invite (1.x read such a value in the server's own zone).
    //
    // bullmq was capped at 5.x until 2026-08-17, when both stated reasons had expired. Now on 6.x, which
    // moves cron-parser off the deprecated 4.9.0 onto 5.x - but not off luxon, which cron-parser depends
    // on in both majors.
    //
    // ioredis was capped at 5.x for the same span, held there BY the bullmq cap (bullmq 5 carried ioredis
    // as a direct dependency; 6.x demoted it to an optional peer, which dissolved the coupling). Now on
    // 6.x, whose one breaking change is that it speaks RESP3 by default - taken as-is, since RESP3 was
    // verified against everything here that could plausibly differ (see the commit that made the move).
    //
    // joi used to be capped here because hapi-swagger peer-required 17.x. That dependency is gone
    // (the OpenAPI document is generated by lib/openapi/ now), so joi may move majors again. A major
    // bump still needs a look at the generated document: test/openapi-golden-test.js fails if joi's
    // describe() output changes shape.
    reject: [
        // @asamuzakjp/css-color >=4.1.2 pulls in @csstools/* v4 which are pure ESM and break pkg bundling
        // (transitive via @postalsys/email-text-tools -> jsdom -> cssstyle; also pinned in package.json "overrides").
        '@asamuzakjp/css-color'
    ]
};
