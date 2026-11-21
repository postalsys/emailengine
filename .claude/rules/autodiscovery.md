---
description: IMAP/SMTP autodiscovery: the resolver race, the Exchange POX/SOAP requirements, when credentials may be sent, and the hosted form skipping the server settings step.
paths:
  - "lib/autodetect-imap-settings.js"
  - "lib/egress-fetch.js"
  - "lib/egress-filter.js"
  - "lib/webhook-egress.js"
  - "lib/ui-routes/account-routes.js"
  - "lib/ui-routes/account-setup.js"
  - "lib/api-routes/account-routes.js"
  - "views/accounts/register/**"
  - "test/autodetect-*.js"
---

## Email autodiscovery

`lib/autodetect-imap-settings.js` resolves IMAP/SMTP settings for an address. The MX-based resolver is tried first and, failing that, five resolvers race under a five second budget each (SRV, `.well-known`, `autoconfig.<domain>`, the Mozilla ISPDB, and Exchange autodiscovery); the first to answer wins.

The Exchange branch has three requirements that are not guesses, and getting any of them wrong looks like a working request that returns nothing:

- **`Content-Type: text/xml`.** Exchange answers `application/xml` with 415 before it parses the body.
- **`EMailAddress` before `AcceptableResponseSchema`** in the legacy ("POX") request. The schema declares a sequence, and the other order returns `<ErrorCode>600</ErrorCode>` ("Invalid Request").
- **Every place the sequence names, not just `autodiscover.<domain>`.** The https POST to the SRV target (or to `autodiscover.<domain>`) is one of several documented locations, and a provider can publish only one of the others: the root domain `https://<domain>/autodiscover/autodiscover.xml`, and whatever the unauthenticated plain-http GET to `http://autodiscover.<domain>/autodiscover/autodiscover.xml` redirects to. IONOS/1&1 publishes only the last of those - `autodiscover.<domain>` is a CNAME to a redirector listening on port 80 only - so for every domain on that provider the one request EmailEngine made could not connect. The candidates are raced rather than walked in order, because this branch shares the five second budget. A POX answer carrying `<Action>redirectUrl</Action>` is followed too, bounded by `MAX_AUTODISCOVER_REDIRECTS`, and **anonymously**: the origin comes out of the body of a server that answered 200 without asking for anything, so letting it collect the password would make the host the address domain points at the one that decides where the password goes. `<RedirectAddr>` names a different address and is not followed at all.

- **Both endpoints, not just the legacy one.** `autodiscover.xml` (POX) and `autodiscover.svc` (SOAP `GetUserSettings`) are populated from different Exchange configuration. Hosted Exchange commonly answers POX with nothing but the `WEB` protocol while the IMAP and SMTP endpoints, the ones its webmail shows on its own "POP and IMAP settings" page, come back only from SOAP as `ExternalImap4Connections` / `ExternalSmtpConnections`. Verified against OVH (both Email Pro and Hosted Exchange run Exchange 2019 behind `pro*`/`ex*.mail.ovh.net`).

All three were wrong from the module's first commit in 2021 until 2026-09-08, so this path had never resolved a real Exchange server.

**Credentials.** Hosted Exchange refuses both endpoints anonymously with a 401 offering Basic. `autodetectImapSettings(email, gt, credentials)` therefore takes an optional `{ user, pass }`, and `runAutodiscovery()` asks anonymously first, only offering the password once the server has asked for it, then puts the authenticated POX and SOAP requests in flight together (either can be the one carrying IMAP settings, and the budget is shared with four other resolvers). POX wins a tie because it is the only one of the two that names the login to use. Two callers pass credentials, because they are the ones holding a password: the hosted setup form, and `POST /v1/autoconfig` for an integrator running its own setup UI. `GET /v1/autoconfig` takes the address in a query string, where a password must never go, so it stays anonymous and an Exchange domain still resolves to nothing there. The POST is grouped with `POST /v1/verifyAccount` under `provisioning` rather than with the GET under `diagnostics`, since it relays a supplied credential.

The password reaches a host named by DNS records under the address domain's own control, which is the same trust the discovered IMAP host already gets. What must not happen is that host handing the password on, so three rules hold it in place. The retry is sent only after a 401 whose `WWW-Authenticate` actually offers Basic, and never to a host that answered some other way: a 404 from a wildcard-DNS parking host, a CDN answering an unknown path with 200, and a server offering only NTLM all answered without asking for a password, and an anonymous 200 carrying no settings ends the lookup rather than escalating. It goes to the origin that issued the challenge, read off `res.url`, rather than replaying the redirect chain, which would strip the header on a cross-origin hop and arrive unauthenticated. And that origin has to be https, because a redirect is allowed to lead to http and Basic there is a cleartext password. `fetchWithVettedRedirects` drops `Authorization`/`Cookie` when a redirect leaves the origin, the way fetch() does.

**Skipping the server settings step.** A setup link minted with `skipServerSettings` (`POST /v1/authentication/form`, carried inside the signed blob) lets the hosted form go from the address and password straight to the calling application. It is the default there, so a caller that wants the step shown regardless has to send `skipServerSettings: false`; the flag is only ever written into the blob when it is on (`filterEmptyObjectValues()` drops a false one), which is what leaves links minted before the default flipped, and the admin UI's own `POST /admin/accounts/new` links, on the settings form as before. `POST /accounts/new/imap` renders `views/accounts/register/validating.hbs` instead of the settings form when `hasCompleteServerSettings()` holds - the same answer that arms the settings page's auto-verify, asked of the `connectionFields` schema rather than of a hand-kept list, so "complete" means "the create endpoint would accept this"; that page checks the connection through the existing `/accounts/new/imap/test` and submits the same field set the settings form would have. It is best effort in both directions: nothing discovered means the settings form as before, and a failed check hands the visitor that form through `POST /accounts/new/imap/settings`. The form's action is the settings form until the check passes, so a browser without JavaScript and an interrupted check both land there rather than creating an account from settings nobody verified.

**An empty answer is not an answer.** `resolver()` resolves on the first branch to come back, so a resolver that parsed a response describing no server at all used to beat a slower one that had the real settings. A result naming neither an IMAP nor an SMTP host now counts as a loss for every branch, which is also what makes the hosted form say autodiscovery failed instead of rendering a form with empty server fields.

Do not reach for a provider-specific rule here. Keying off the `_autodiscover._tcp` SRV target (for OVH it is the mail server itself, `:993` implicit TLS and `:587` STARTTLS) works, but SOAP autodiscovery covers the same accounts through a documented protocol and covers every other Exchange with it.
