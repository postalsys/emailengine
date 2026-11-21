---
description: Device Bound Session Credentials for admin sessions: bindings, refresh semantics, and the deliberate behaviors that must not be reverted.
paths:
  - "lib/dbsc/**"
  - "lib/ui-routes/dbsc-routes.js"
  - "test/dbsc-*.js"
  - "test/e2e/pages-dbsc.spec.js"
---

## Device-bound admin sessions (DBSC)

`lib/dbsc/` binds an admin session to a key the browser keeps in the device's security hardware ([Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/)), behind the `dbscEnabled` setting (default off, privileged, Beta on the Security page, quiet like MCP: `fix:` commits, no README). `protocol.js` is the wire format, `jwt.js` verifies proofs with Node's own crypto, `store.js` keeps bindings and single-use challenges in Redis, `index.js` holds the offer (`onPreResponse` on rendered admin pages), the two routes' logic (`POST /admin/dbsc/start`, `/admin/dbsc/refresh`, registered by `lib/ui-routes/dbsc-routes.js`) and the enforcement (`onPostAuth`). A bound session's requests, the message browser's `sess_` API calls included, need the short-lived iron-sealed `eeb` cookie that only the key can renew; an unbound session (any browser without support) works as before.

What is deliberate and easy to "fix" back into a hole:

- **Nothing deletes a binding**, not a refusal and not a logout. The session cookie says nothing about being bound, so a removed binding would let a copy of the same cookie pass as an unbound session, and let its holder bind a key of their own. Logout (`endDeviceBinding()`) marks it `ended` instead (`SET XX KEEPTTL`), which refuses the session cookie everywhere once the last bound cookie runs out, and only the TTL removes it. Found by the security review before the feature shipped.
- **A session is bound once** (`SET NX`): a second registration answers 409, or whoever holds the cookie could replace the key.
- **Refresh answers by what the browser does with the status.** It ignores a 3xx, so the route reads the session in `try` mode and tells an ended, unknown or switched-off session `{"continue": false}`; every 4xx other than 403 ends the session in the browser, which is how repeated bad proofs are stopped (`MAX_REFRESH_FAILURES`, then 401). It is in `TOTP_EXEMPT_PATHS` for the same reason.
- **Challenges are single use.** Chrome signs proactive refreshes over the challenge it cached; that is answered with a fresh one in a 403 and Chrome retries, one extra round trip.
- **Chrome only binds on a trusted https origin**: not on http, not on localhost, not with a certificate error, and not in Playwright's unsigned Chrome for Testing on macOS (no platform key store). Verified against Chrome 156 on 2026-11-05; `test/e2e/pages-dbsc.spec.js` runs only with a signed Chrome and a public https URL (`EE_E2E_DBSC_CHROME`, `EE_E2E_DBSC_URL`, e.g. a cloudflared tunnel to port 7099) and skips otherwise. `test/dbsc-test.js` covers the protocol on a real hapi server, and `test/dbsc-jwt-test.js` carries two proofs Chrome actually sent.
- The sign-out message after a refusal is a flash, and flashes are keyed by the `crumb` cookie, so a bare copied session cookie is told nothing while the session's own browser is told why.
