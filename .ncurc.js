module.exports = {
    upgrade: true,
    // Packages capped inside their current major: the next major is ESM-only (this codebase is
    // CommonJS and is bundled into a binary with pkg) or it breaks a peer dependency. Using 'minor'
    // instead of a blanket reject so these still receive security/patch updates within the safe
    // major instead of being frozen at one exact version. Verified against Node 20 (Docker) 2026-06-17.
    target: name => (['joi', 'nanoid', 'ical.js', 'gettext-parser', 'xgettext-template', 'chai', 'undici'].includes(name) ? 'minor' : 'latest'),
    //   joi               - hapi-swagger (repo archived 2026-02-04) peer-requires joi 17.x; permanent ceiling
    //   nanoid            - 4.x dropped the CommonJS require export (ESM-only)
    //   ical.js           - 2.x is ESM-only
    //   gettext-parser    - 8.x is ESM-only
    //   xgettext-template - 6.x is ESM-only (translation build tool)
    //   chai              - 5.x is ESM-only (only used by the vendored imap-core tests)
    //   undici            - 8.x requires Node >=22.19 and crashes at require() on Node 20; EmailEngine supports Node 20+
    reject: [
        // 8.16+ pulls apache-arrow (ESM) into the pkg bundle; 9.x drops it but is a major bump for
        // the deprecated, default-off Document Store. Even the 8.19 minor is unsafe to bundle.
        '@elastic/elasticsearch',

        // CommonJS build removed in marked 16.0.0; 15.0.12 is the last require()-compatible release
        // (16+ needs Node >=20.19 for require(esm)). Used only for marked.parse() of the EULA in workers/api.js.
        'marked',

        // v4.x adds vulnerable jquery + bootstrap runtime dependencies; v3.3.7 has none. Used only
        // for the generated software-license listing, never executed at runtime.
        'startbootstrap-sb-admin-2',

        // @asamuzakjp/css-color >=4.1.2 pulls in @csstools/* v4 which are pure ESM and break pkg bundling
        // (transitive via @postalsys/email-text-tools -> jsdom -> cssstyle; also pinned in package.json "overrides").
        '@asamuzakjp/css-color'
    ]
};
