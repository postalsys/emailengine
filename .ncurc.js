'use strict';

module.exports = {
    upgrade: true,
    // The Node.js floor is lib/node-version.js: server.js refuses to start below MIN_NODE (22.19.0, what
    // undici 8 needs) and engines.node declares the range the bundled jsdom does. Until 2026-11 the floor
    // was Node 20, held there by the DigitalOcean one-click images (they upgrade EmailEngine but not the
    // Node.js under it), and several entries below existed only for that; they were lifted with the
    // floor. A package that needs a Node.js newer than MIN_NODE still needs the floor raised first.
    //
    // Packages capped inside their current major: the next major is ESM-only (this codebase is
    // CommonJS and is bundled into a binary with pkg), needs a Node newer than the floor above, or
    // is a major we are deliberately soaking. Using 'minor' instead of a blanket reject so these
    // still receive security/patch updates within the safe major instead of being frozen at one
    // exact version. Re-check whenever an entry below is reconsidered.
    //
    // "ESM-only" is pkg's constraint, not Node's: the binary bundles a CommonJS module graph and cannot
    // load ES modules whatever Node version runs it, so an ESM-only runtime dependency stays out
    // regardless of the floor (see "Pure JavaScript only" in CLAUDE.md).
    //
    // `pino` is capped harder than the rest, at 'patch', because the break arrived in a MINOR and a
    // major cap would not have stopped it. See its entry below.
    target: name =>
        ['pino', '@playwright/test'].includes(name)
            ? 'patch'
            : ['gettext-parser', 'marked', 'he', 'iconv-lite', '@hapi/boom'].includes(name)
              ? 'minor'
              : 'latest'
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
    //   gettext-parser    - 8.x and later are ESM-only (10.0.0 is type:module with no require condition). It is a
    //                       devDependency only (gettext-extract.js and test/gettext-pot-order-test.js), so pkg is not
    //                       the constraint: the unit tier runs under `npm run test:cjs` (require(esm) disabled), where
    //                       an ESM-only gettext-parser fails to load.
    //   marked            - 16.x dropped the CommonJS build (ESM-only, needs require(esm)); 15.x is the last
    //                       require()-compatible line, verified in a yao/pkg node24 build.
    //                       Permanent: an ESM-only release cannot be bundled by pkg, whatever the Node floor.
    //   iconv-lite        - 1.0 (alpha since 2026-10) moves to ES modules, relying on require(esm). Held on 0.x;
    //                       libmime, imapflow and mailparser carry the same cap. The ES module move keeps it out of
    //                       the pkg bundle.
    //   @hapi/boom        - 11.0.0-rc.0 (dist-tag next, 2026-08) is type:module with only an ESM export (boom PR #309,
    //                       "convert module to ESM") and engines node>=22. Without this cap `npm run update` would move
    //                       to it the day 11.0.0 reaches latest, and the pkg binary would fail while dev and tests pass on
    //                       require(esm). The hapi org did the same to bourne, formula, pinpoint and tlds in 2026 and has
    //                       ESM-only rcs of hoek 12 and topo 7, so a hapi 22 will likely follow: add every direct
    //                       @hapi/* dependency here the day it publishes an ESM-only major. hapi 21 itself still depends
    //                       on boom ^10, hoek ^11 and topo ^6.
    //   he                - 2.x is ESM-only (exports only src/he.mjs). 1.2.0 is the last CommonJS release. mailparser,
    //                       which reaches EmailEngine through the same require, rejects 2.x for the same reason.
    //                       Permanent for the same pkg reason as marked.
    //
    // Sentry: EmailEngine builds its client from @sentry/core (lib/sentry.js, with its own context-lines, context and
    // modules integrations in lib/sentry-integrations.js) and must not depend on @sentry/node or @sentry/node-core.
    // @sentry/node 11.x depends on @sentry/bundler-plugins, which pulls the 16 MB Sentry CLI (package `sentry`,
    // licensed FSL-1.1-Apache-2.0, not an OSI license) and the native oxc-parser into the runtime tree and the pkg
    // bundle, and @sentry/node-core, the light SDK used until 2026-11, ended at 10.x. @sentry/core depends only on
    // @sentry/conventions; check that it still does on every major.
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
};
