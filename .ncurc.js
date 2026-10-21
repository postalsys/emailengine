'use strict';

module.exports = {
    upgrade: true,
    // Node 20 is a hard runtime floor, not a preference (engines.node says >=20.19.0, the oldest 20.x the
    // dependency tree itself accepts; server.js only warns below it). The DigitalOcean one-click images run
    // EmailEngine on Node 20 and ship an upgrade script for EmailEngine but none for Node, so those
    // installs keep self-updating on a runtime that never moves; raising the floor breaks them on
    // their next upgrade. Node 20 being EOL upstream, and CI and the pkg targets being on Node 24,
    // do not lift this. Treat "needs Node >20" as a permanent reject.
    //
    // Packages capped inside their current major: the next major is ESM-only (this codebase is
    // CommonJS and is bundled into a binary with pkg), needs a Node newer than the floor above, or
    // is a major we are deliberately soaking. Using 'minor' instead of a blanket reject so these
    // still receive security/patch updates within the safe major instead of being frozen at one
    // exact version. Last verified against Node 20 (Docker) 2026-06-17; re-check whenever an entry
    // below is reconsidered.
    //
    // Two different constraints drive these caps, and they lift on different terms. "Needs a newer
    // Node" is the floor above. "ESM-only" is pkg: the binary bundles a CommonJS module graph and cannot
    // load ES modules whatever Node version runs it, so an ESM-only runtime dependency stays out even
    // if the floor ever moves (see "Pure JavaScript only" in CLAUDE.md).
    //
    // `pino` is capped harder than the rest, at 'patch', because the break arrived in a MINOR and a
    // major cap would not have stopped it. See its entry below.
    target: name =>
        ['pino', '@playwright/test'].includes(name)
            ? 'patch'
            : ['gettext-parser', 'xgettext-template', 'undici', 'marked', '@sentry/node-core', 'he', 'iconv-lite'].includes(name)
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
    //   gettext-parser    - 8.x is ESM-only
    //   xgettext-template - 6.x and later are ESM-only and need Node >=22. It only runs as a CLI in the
    //                       translation build, so ESM alone would not keep it out (build tools are exempt
    //                       from the CommonJS rule); the Node requirement does, since the tooling has to
    //                       run on the Node 20 floor too.
    //   undici            - 8.x requires Node >=22.19 and crashes at require() on Node 20. Permanent while the
    //                       Node 20 floor above stands.
    //   marked            - 16.x dropped the CommonJS build (ESM-only, needs require(esm)/Node >=20.19); 15.x is the
    //                       last require()-compatible line. 15.0.12 verified on Node 20-24 and in a yao/pkg node24 build.
    //                       Permanent: an ESM-only release cannot be bundled by pkg, whatever the Node floor.
    //   iconv-lite        - 1.0 (alpha since 2026-10) requires Node >=22 and moves to ES modules, relying on
    //                       require(esm). Held on 0.x; libmime, imapflow and mailparser carry the same cap.
    //                       The ES module move keeps it out of the pkg bundle even past the Node floor.
    //   he                - 2.x is ESM-only (exports only src/he.mjs) and requires Node >=22; require('he') throws
    //                       ERR_REQUIRE_ESM on Node 20 before 20.19. 1.2.0 is the last CommonJS release. mailparser,
    //                       which reaches EmailEngine through the same require, rejects 2.x for the same reason.
    //                       Permanent for the same pkg reason as marked, not because of the Node floor.
    //   @sentry/node-core - held on the 10.x line for the reasons @sentry/node (which it replaced, through its
    //                       `light` entry) was held there: @sentry/node 11.x requires Node >=20.19 (engines now says the
    //                       same, but the startup check only warns below it, so a DigitalOcean image on an older 20.x
    //                       still runs; the error-reporting path must not be what fails there), and it depends on
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
        // Not a direct dependency, so nothing here moves it: the "overrides" entry in package.json
        // lifts cheerio from the 1.0.0 that juice 11 (via @postalsys/email-text-tools) pins exactly,
        // which drags in a second copy of undici (6.x) next to ours. cheerio 1.2.0 shares our undici
        // 7 and keeps a CommonJS build; juice 12 would fix this itself but is ESM-only and needs
        // Node 22. Re-check the override when juice or email-text-tools changes its cheerio range.
    ]
};
