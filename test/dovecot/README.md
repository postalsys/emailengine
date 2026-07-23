# Live Dovecot tests (IMAP4rev2 / BINARY)

Runs EmailEngine against a real IMAP4rev2 server - Dovecot 2.4+ in Docker -
instead of protocol mocks, mirroring the ImapFlow rev2 live suite. This tier
exists to catch compatibility problems with modern IMAP extensions early:
Dovecot enables IMAP4rev2, UTF8=ACCEPT, ESEARCH, MOVE and BINARY out of the
box, which the mock-based tests cannot faithfully emulate.

Covered: the ENABLE IMAP4rev2 negotiation (asserted on the wire through the
account protocol log), folder listing without LSUB, special-use mailbox
detection, a full message lifecycle (upload, fetch with byte-exact text and
attachment content assertions, ESEARCH-shaped search, flag updates, MOVE with
COPYUID, delete), and the same lifecycle with the account-level
`disableIMAP4rev2` opt-out keeping the connection on IMAP4rev1.

Note on BINARY: EmailEngine does not currently opt into ImapFlow's FETCH
BINARY (`download()` is called without `binary: true`), so content travels
BODY-encoded even on rev2 sessions. The suite asserts the server advertises
BINARY and that all content survives byte for byte - the surface a BINARY
adoption would touch - so the fetch path stays covered if that changes.
ImapFlow's own rev2 live suite tests the FETCH BINARY wire format directly.

## Running

```
npm run test:dovecot
```

Requires Docker and a local Redis (the test database from `config/test.toml`
is flushed, same as the integration tier). The script pulls
`dovecot/dovecot:2.4.4`, starts a container with the drop-in config from
`dovecot-test.conf`, boots an EmailEngine test server (`NODE_ENV=test`), runs
`dovecot-live-test.js` with the Node.js test runner, and always removes the
container and stops the server afterwards. The script refuses to start if the
API port is already taken - typically a leftover test server that would
silently serve old code (see the port guard comment in the script).

This tier is intentionally not part of `npm test` (the test runner globs only
match `test/*-test.js` and `test/integration/*-test.js`), so plain test runs
stay Docker-free. CI runs it in a dedicated `dovecot` job on `ubuntu-24.04`
(amd64 with Docker preinstalled), forcing `EENGINE_DOVECOT_PLATFORM=linux/amd64`.

## Environment overrides

- `EENGINE_DOVECOT_IMAGE` - image to run (default `dovecot/dovecot:2.4.4`;
  any 2.4.2+ tag supports IMAP4rev2)
- `EENGINE_DOVECOT_PLATFORM` - e.g. `linux/amd64`; defaults to the host
  platform. Forcing `linux/amd64` on Apple Silicon does not work - Rosetta
  cannot start Dovecot's privilege-separated login processes; local runs on
  Apple Silicon use the host-native arm64 image instead
- `EENGINE_DOVECOT_PORT` - host port to publish (default 31143)

## Test account model

The container uses Dovecot's static passdb (`USER_PASSWORD=pass`): any
username authenticates with the password `pass` and gets its own empty mail
home, so every test connects as a brand-new user and needs no cleanup between
runs. Special-use mailboxes (Sent/Drafts/Junk/Trash) are auto-created and
subscribed via `dovecot-test.conf`. Accounts enable the protocol log
(`logs: true`) so the tests can assert the actual client/server exchange via
`/admin/accounts/{account}/logs.txt`.
