# imap-core (vendored fork)

This directory is a **vendored fork**, not a dependency. It is not listed in `package.json`, so
`npm update` never touches it and `npm audit` never sees it.

## Provenance

Upstream: the `imap-core` module of [WildDuck](https://github.com/nodemailer/wildduck)
(`lib/imap-core` in that repository).

Imported into EmailEngine in `dd0d6e34` ("Added IMAP proxy server", 2022-08-23) and patched in
place since. It provides the IMAP protocol server that `lib/imapproxy/imap-server.js` builds on:
the command parser/compiler, the connection and command state machines, and the message indexer.

The WildDuck-specific parts of upstream (MongoDB-backed mailbox storage, the `test/prepare.sh`
fixture loader that talks to a WildDuck REST API) came along with the import and are not used
here.

## Local patches

Everything below is EmailEngine-only and has no upstream equivalent. Re-syncing with upstream
means re-applying these.

| Commit | Date | Change |
| --- | --- | --- |
| `4453330a` | 2026-06-01 | Prevent IMAP proxy worker crashes and connection leaks (#596) |
| `3661dddb` | 2026-06-05 | Harden STARTTLS against command injection: reject pipelined data buffered before the TLS upgrade |
| `9fb8a5e3` | 2026-06-05 | Bound inbound line length in the parser, so an unterminated line cannot grow without limit |
| `627c6d47` | 2026-06-05 | Re-arm a generous idle timeout for proxied connections |
| `e97950e7` | 2026-06-05 | Close leaks and a worker crash found in the connection hardening review |
| `d51e92d2` | 2026-06-06 | Prevent post-BYE command dispatch during teardown |
| `31f6a590` | 2026-07-26 | Fix the dead teardown guard in the notification listener |
| see git log | 2026-09-02 | Drop the built-in self-signed key/certificate pair from `tls-options.js`; a listener with TLS and no certificate is refused at startup instead of served with a key that ships in every copy |

Earlier local changes (`09085d12`, `0a389560`, `7e2e94f3`, `04c2aa90`, `1d6df05e`, `612d9f96`,
`13edec58`, `2e0bf1ce`, `b9a3e06c`, `b58a827e`, `1813f089`) are maintenance: dependency swaps
(`punycode` to `punycode.js`, `wild-config` to `@zone-eu/wild-config`), the `fast` IMAP indexing
option, OAuth `useAuthServer` support, formatting and lint-glob fixes.

`git log -- lib/imapproxy/imap-core/` is the authoritative list; this table is a summary.

## Tests

The `test/` directory is upstream's mocha suite. It is written for mocha, which is not a
dependency here, and had never been executed after the import.

The hermetic specs now run as part of the normal unit tier through
`test/imap-core-vendored-test.js`, which installs the mocha globals the specs expect and requires
them. **Do not edit the files under `test/` to make them run** - keeping them byte-identical to
upstream is what makes the patch list above reviewable. Adapt them from the EmailEngine side
instead.

Wired up and running:

- `imap-parser-test.js`
- `imap-compiler-test.js`
- `imap-compile-stream-test.js`
- `imap-indexer-test.js` (upstream has its `#rebuild` block commented out)
- `tools-test.js`

Not wired up, because they drive a live server via `test-server.js` and need MongoDB plus a
WildDuck REST API that does not exist in this repository:

- `protocol-test.js`
- `search-test.js`

That is a real coverage gap: `protocol-test.js` is the suite that exercises the connection and
command state machines, which is where most of the local patches above landed. The connection
handling that EmailEngine actually ships is covered instead by `test/dovecot/` (live IMAP against
Dovecot) and the IMAP proxy's own integration tests.
