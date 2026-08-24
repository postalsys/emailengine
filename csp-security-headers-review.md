# Security headers and CSP: current state, blockers, and a path to enforcement

Investigation against `master` at 2.79.2 (aea45350). Nothing was changed. Findings come from
reading the code plus a live header capture from a throwaway e2e instance
(`NODE_ENV=e2e node server.js`, db 14, since torn down).

## Bottom line

The expensive half of a CSP migration is already done and nobody seems to have noticed. There
are **zero inline event handler attributes** (`onclick=`, `onchange=`, ...) anywhere in the 158
view templates, **zero `<style>` blocks**, one `javascript:` URL, and **every subresource is
same-origin** - no CDN, no remote font, no analytics tag. That is the part of a CSP retrofit that
usually takes months.

What remains is a short, well-defined list:

| Blocker | Scope | Directive it forces |
|---|---|---|
| 37 inline `<script>` blocks | 32 view files, ~3,280 lines | `script-src 'unsafe-inline'` |
| `Handlebars.compile()` in the browser | 2 pages | `script-src 'unsafe-eval'` |
| `new Function()` in the filter-preview worker | 3 pages | `script-src 'unsafe-eval'` |
| Ace loads its syntax workers from Blob URLs | 3 pages | `worker-src blob:` |
| 63 `style=` attributes | 31 view files | `style-src-attr 'unsafe-inline'` |
| Rendered email HTML (inline styles, `data:` images, remote images) | `/admin/accounts/{id}/browse` | `style-src-attr 'unsafe-inline'`, `img-src data: https:` |
| bull-board (third party) pulls Google Fonts, ships inline styles | `/admin/bull-board/*` | external `style-src`/`font-src` |
| Operator-injected branding HTML | public hosted pages | whatever the operator put there |

Only the last three are architectural. The first five are mechanical work with a known end state.

The immediate, zero-risk win is separate from CSP: **no security headers are sent at all today**,
and roughly half of the useful set has no compatibility cost whatsoever. Ship those first.

---

## 1. Current state (measured)

Live capture against a running instance. Every response, on every surface:

```
HTTP/1.1 200 OK
cache-control: no-cache
set-cookie: crumb=...; Secure; HttpOnly; SameSite=Strict; Path=/
content-type: text/html; charset=utf-8
```

No `Content-Security-Policy`, no `X-Content-Type-Options`, no `X-Frame-Options`, no
`Referrer-Policy`, no `Strict-Transport-Security`, no `Permissions-Policy`, no
`Cross-Origin-*`. Confirmed on `/`, `/admin`, `/admin/login`, `/v1/settings`, `/swagger.json`,
`/static/js/ui.js`, `/robots.txt`, `/licenses.html`, `/unsubscribe`, `/mcp`, `/v1/changes`.

The only security headers in the repo are the ones `DOCKER_DEPLOYMENT.md:139-141` and `:178-180`
suggest that operators add at their nginx/Caddy reverse proxy. Which means: a deployment that is
not behind the documented proxy gets nothing, and every deployment that is gets a policy
EmailEngine does not control and cannot keep in step with its own markup.

What is already good, and should be preserved rather than rediscovered:

- CORS is **off by default** (`workers/api.js:231-232`); it only turns on via `EENGINE_CORS_ORIGIN`
  / `[cors] origin`. A preflight from an unlisted origin gets no `Access-Control-Allow-Origin`.
- CSRF crumb is server-wide with an explicit skip list (`workers/api.js:2847-2865`): `api`,
  `scope:metrics`, `static`, `external` tags. Cookie is `Secure; HttpOnly; SameSite=Strict`.
- Session cookie is `SameSite=Lax`, `HttpOnly`, and `Secure` whenever `serviceUrl` is https
  (`workers/api.js:1238-1246`) - that flag is already the right signal to reuse for HSTS.
- Attachments carry `Content-Disposition: attachment` on all three providers
  (`lib/email-client/imap/mailbox.js:2530`, `gmail-client.js:1276`, `outlook-client.js:1586`).
- No CDN, no external subresource anywhere in `views/` or `static/css/`. The `https://` strings in
  templates are all `href` link targets, never `src`. The air-gap goal holds.

## 2. Where a header would be stamped

Two hooks already exist and are exactly the right shape:

- **Headers**: `server.ext('onPreResponse', preResponse)` at `workers/api.js:3184`. A second
  `onPreResponse` extension registered *after* this one would see the final response object,
  including the case where `preResponse` replaces a Boom error with a rendered `error` view
  (`workers/api.js:3175-3180`) - stamping inside `preResponse` itself would miss that branch,
  because the headers would go onto the response object it is about to discard. Because the ext is
  server-wide it also covers Inert static files and the bull-board plugin routes, which is what
  makes per-path policies possible in one place.
- **Nonce**: `server.views({ ..., async context(request) {...} })` at `workers/api.js:2867`. This
  is a single global view context applied to every layout and every page. Generating a nonce in an
  `onRequest` ext, parking it on `request.app`, and returning it from `context()` makes
  `{{cspNonce}}` available in all 158 templates for free.

There is no third HTML renderer to worry about: everything server-rendered goes through
`h.view()`. The one exception is bull-board, whose HTML comes from its own EJS template inside
`node_modules` and can never receive a nonce.

## 3. What blocks a strict CSP

### 3.1 Inline scripts (the bulk, but the easy part)

37 inline `<script>` blocks across 32 files, ~3,280 lines. Largest offenders:

```
views/accounts/account.hbs                  544 lines
views/tokens/new.hbs                        454
views/partials/oauth_form.hbs               416
views/accounts/register/imap-server.hbs     313
views/partials/filter_editor_js.hbs         249
views/config/ai.hbs                         145
views/templates/template.hbs                125
views/config/document-store/chat.hbs        112
```

**A nonce solves all of them at once.** Adding `nonce="{{cspNonce}}"` to 37 opening tags (plus the
12 `<script src>` tags in the 5 layouts) is a mechanical, reviewable diff. Extracting 3,280 lines
into separate files is *not* required and should not be attempted as a precondition.

One caveat that a nonce does not fix, and that is worth handling in the same pass. Eleven of these
inline blocks interpolate server data:

```
views/accounts/browse.hbs:37-38      account: '{{account}}', accessToken: '{{sessionToken}}',
views/config/oauth/app.hbs:369       const appId = "{{app.id}}";
views/reference/redirect.hbs:18      const map = {{{redirectMap}}};
views/config/network.hbs:183         {{{addressListTemplate}}}
views/accounts/account.hbs:1345      <script id="test-send-template" ...>{{{testSendTemplate}}}</script>
views/accounts/register/imap-server.hbs (7 gettext strings in template literals)
```

Handlebars' default escaping covers `& < > " ' \` =`, so `</script>` cannot be emitted and none of
these is XSS today. But it does **not** escape backslash, and account IDs are unconstrained -
`accountIdSchema` (`lib/schemas.js:44`) is `Joi.string().max(256)` with no character class. An
account ID ending in `\` swallows the closing quote at `browse.hbs:37` and desyncs the JS
tokenizer for the rest of the block. Not exploitable as written (the attacker cannot emit a quote
to re-open a string), but it is a correctness hazard sitting one schema change away from being a
real one, and a nonce would explicitly bless it.

The fix is already in the codebase and just needs promoting: `jsonForScript()` at
`lib/api-reference/index.js:133` does `JSON.stringify` plus `<`, U+2028, U+2029 escaping.
`views/reference/redirect.hbs` already uses it correctly and documents why. Move it to
`lib/tools.js` and convert the other interpolations to `<script type="application/json">` data
islands read with `JSON.parse(el.textContent)`. `views/partials/filter_editor_js.hbs:56` already
uses exactly this pattern (`JSON.parse(document.getElementById('scriptEnvJson').value)`), so
there is an in-repo precedent to point at.

`{{{testSendTemplate}}}` and `{{{addressListTemplate}}}` are static files read at startup
(`lib/ui-routes/route-helpers.js:47-50`), not user data, so they are safe - but see 3.2.

### 3.2 `unsafe-eval`: two independent sources

**Browser-side Handlebars compilation.** `static/vendor/handlebars/handlebars.min-v4.7.9.js` is
the full compiler, and `Function.apply(this, [...])` in the code generator is the Function
constructor. Two call sites:

- `views/config/network.hbs:224` - compiles `views/partials/address_list.hbs` (33 lines)
- `views/accounts/account.hbs:1376` - compiles `views/partials/test_send.hbs` (156 lines)

Fix: precompile both partials at build time (`handlebars.precompile`, wired into
`copy-static-files.sh`) and ship `handlebars.runtime.min.js` instead of the full build. Smaller
bundle, no `unsafe-eval`. Alternatively rewrite two small templates as DOM building and drop the
browser Handlebars dependency entirely - 189 lines of template between them.

**The filter-preview evaluator.** `static/js/evaluation-worker.js:21` runs user-authored webhook
`fn`/`map` scripts via `new Function('payload', 'logger', 'fetch', 'env', source)`. Loaded from
`views/partials/filter_editor_js.hbs:58`, which is included by `views/config/ai.hbs`,
`views/config/document-store/pre-processing/index.hbs`, and
`views/partials/webhooks_editor_functions.hbs`.

Serving the worker script with its own CSP header does **not** help: a dedicated worker inherits
the owning document's policy list, so `script-src 'self'` on the page kills `new Function` inside
the worker too. The clean fix is a **sandbox route**: a dedicated same-origin document (say
`GET /admin/sandbox/evaluate`) served with its own
`Content-Security-Policy: sandbox allow-scripts; script-src 'self' 'unsafe-eval'`, loaded in an
`<iframe src=...>`, with the worker created inside it and results posted back over
`postMessage`. A framed document loaded from a real URL takes its CSP from its own response
rather than inheriting the parent's, so this confines `unsafe-eval` to one opaque-origin document
that holds no session. `srcdoc`/`blob:`/`about:blank` iframes will *not* work here - those inherit.

This is worth doing on its own merits regardless of CSP: it is the browser-side twin of the
`vm`-isolation question already recorded for the server-side SubScript evaluator.

### 3.3 Ace and `blob:` workers

`static/js/ace/ace.js` ships `loadWorkerFromBlob:!0`, so `useWorker: true` editors construct
their syntax workers from `URL.createObjectURL(new Blob([...]))`. That needs `worker-src blob:`
(and, in browsers that fall back, `child-src blob:`), which is a meaningful weakening.

Three pages use `useWorker: true`: `views/config/ai.hbs:319`, `views/config/webhooks.hbs:300`,
`views/config/branding.hbs:91` and `:99`. Everything else already passes `useWorker: false`.

Fix, two lines, no behavior change:

```js
ace.config.set('loadWorkerFromBlob', false);
ace.config.set('workerPath', '/static/js/ace');
```

The worker files are already served same-origin at `/static/js/ace/worker-*.js`, so this just
stops the pointless Blob round-trip and lets `worker-src 'self'` hold.

One related detail: `static/js/reference.js:1063-1067` injects `<script src>` for Ace lazily. Under
`script-src 'self' 'nonce-...'` that is fine (`'self'` covers it), but if the policy ever moves to
`'strict-dynamic'` - which drops `'self'` - the injected element needs `element.nonce = ...`
propagated. Worth a comment at the call site now so a future tightening does not silently break
the Try-it panels.

### 3.4 Inline styles

63 `style=` attributes across 31 files, no `<style>` blocks at all. The heaviest file is
`views/account/security.hbs` with 13. Converting these to Tailwind utility classes or the existing
`views/partials/ui/` component set is small, boring work.

The real `style-src` problem is not in the templates. It is section 3.5.

### 3.5 The message browser: rendering email HTML in the admin origin

`static/js/ee-client.js:1733` interpolates the server-sanitized message body straight into a
template string that is assigned with `viewer.innerHTML = html` at line 1759. The body arrives from
`GET /v1/account/{id}/message/{id}?webSafeHtml=true`.

Server-side sanitization is real: `@postalsys/email-text-tools` runs DOMPurify twice
(`mime-html.js:185` and `:220`), forbids `<style>` in the second pass, and juices CSS into
attributes. So there is no script in the output. But the output shape forces three things:

1. **Inline `style=` attributes on nearly every element** - that is what juice *does*. Requires
   `style-src-attr 'unsafe-inline'` on the admin origin.
2. **A `<style>` block** for plain-text-only messages: `PLAINTEXT_STYLE_BLOCK` in
   `lib/web-safe-html.js:66-99` is prepended after sanitization. Requires `style-src-elem
   'unsafe-inline'` or a hash.
3. **Images.** `cid:` attachments are inlined as `data:` URIs (`applyWebSafeHtmlOptions` sets
   `embedAttachedImages`, `lib/web-safe-html.js:452`), so `img-src data:`. Remote `<img src="https://...">`
   in the message body is passed through untouched, so a strict `img-src 'self' data:` would block
   every remote image in every email.

That last one is a **product decision, not a security tradeoff to be resolved silently**. Blocking
remote images is what every serious mail client does by default (it defeats open-tracking pixels),
and it would be a privacy improvement. But it changes how mail renders in the admin UI and needs to
be a deliberate, documented choice with a per-message "load remote images" control, not a side
effect of a header rollout.

The architecturally correct answer to all three is the same as 3.2: **move the message body into a
sandboxed same-origin iframe** served from its own route with its own permissive-but-contained
policy (`sandbox allow-popups; default-src 'none'; style-src 'unsafe-inline'; img-src data: https:`).
That buys three things at once: `/admin` keeps a strict `style-src`, a DOMPurify bypass stops being
same-origin script execution against a live admin session, and the remote-image policy becomes one
header on one route instead of a global compromise. It is the single highest-value structural change
on this list.

### 3.6 bull-board (third party, cannot be nonced)

`node_modules/@bull-board/ui/dist/index.ejs` carries:

- `<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans...">` - a live external
  stylesheet that also pulls font files from `fonts.gstatic.com`. This is a standing air-gap
  violation independent of CSP, and it is upstream's markup in both 8.6.1 and 9.0.0.
- An inline `<style>` block and several inline `style=` attributes in the loading skeleton.
- `<script id="__UI_CONFIG__" type="application/json">` - harmless, CSP does not govern
  non-executable script types.

Because the HTML is rendered inside the plugin, no nonce can reach it. `/admin/bull-board/*` needs
its own relaxed policy: `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src
'self' https://fonts.gstatic.com; script-src 'self'`. Its own JS bundles are same-origin and it uses
a plain CSS build (not CSS-in-JS), so `script-src 'self'` holds.

If the air-gap goal is to be taken seriously, the alternative is patching the template at install
time or vendoring the fonts - but that is a separate piece of work and should not gate the CSP.

### 3.7 Operator-injected branding HTML

`views/layout/public.hbs:34-36` and `:48-52` render the `templateHtmlHead` and `templateHeader`
settings as raw HTML (`{{{...}}}`) into every hosted page. `lib/schemas.js:523-528` documents the
intended use explicitly:

```
templateHtmlHead: 'Custom HTML to inject into the <head> section of hosted pages (e.g., for analytics)'
  .example('<link rel="stylesheet" href="https://example.com/brand.css">')
```

Analytics tags and remote stylesheets are precisely what a strict CSP exists to stop. Any policy on
the public pages will break existing deployments that use this feature as documented.

Options, in order of preference:

1. Ship a **more permissive default policy on the public surface** than on `/admin` (they are
   different threat models: the public pages hold no admin session), and let operators tighten it.
2. Add a settings field for extra CSP sources that gets merged into the public-page policy, so an
   operator who adds `https://plausible.example` to their head block can allow it in one place.
3. Nonce the operator block. Rejected: the operator writes the markup, not the template, so they
   would have to hand-place `{{cspNonce}}` and the failure mode is a silently broken analytics tag.

Note that the branding **preview** route (`POST /admin/config/branding/preview`,
`lib/ui-routes/admin-config-routes.js:911-926`) renders the same untrusted-ish HTML through the
`public` layout while an admin session is live. It targets a named popup window
(`views/config/branding.hbs:106`), so `form-action 'self'` is satisfied, but it deserves the public
policy rather than the admin one.

## 4. Recommended rollout

### Phase 0 - ship now, no compatibility cost

None of these can break a page. They are pure header additions with no markup dependency.

```
X-Content-Type-Options: nosniff                    (everywhere)
Referrer-Policy: strict-origin-when-cross-origin   (everywhere)
X-Permitted-Cross-Domain-Policies: none            (everywhere)
Cross-Origin-Opener-Policy: same-origin            (/admin, /)
X-Frame-Options: DENY                              (/admin/*, /v1/*)
Referrer-Policy: no-referrer                       (/redirect only)
```

`nosniff` is the missing half of the attachment story from section 1: `Content-Disposition:
attachment` is already set, but the `Content-Type` on
`GET /v1/account/{id}/attachment/{id}` comes straight from the MIME part and is entirely
attacker-controlled (`lib/email-client/imap/mailbox.js:2544`). Disposition alone is enough on modern
browsers; `nosniff` closes the gap on the rest and costs nothing.

`no-referrer` on `/redirect` (`workers/api.js`, the click tracker) stops the signed tracking URL,
which encodes the account and message ID, from being handed to the destination site in the `Referer`
header of the redirected request.

Also in phase 0, a CSP that genuinely cannot break anything, on responses that are never documents:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox
```

Applied to `api`-tagged routes, `/swagger.json`, attachment downloads, and message-source
downloads. `sandbox` with no tokens neutralizes any of those responses that a browser is tricked
into treating as a document.

**HSTS**, deliberately separated because it is the one header here that can take a host offline:

```
Strict-Transport-Security: max-age=15552000
```

Send only when the request arrived over TLS or `serviceUrl` is https - reuse the exact check at
`workers/api.js:1238-1246` that already drives `secureCookie`. Do **not** default
`includeSubDomains` (it applies to every sibling host in the domain, several of which the operator
may not control) and never default `preload` (effectively irreversible). Both should be opt-in
settings with the consequence spelled out in the UI.

### Phase 1 - nonce plumbing plus report-only CSP on the admin surface

1. Nonce in `onRequest` -> `request.app.cspNonce` -> the global view context at `workers/api.js:2867`.
2. `nonce="{{cspNonce}}"` on all 37 inline blocks and the 12 layout `<script src>` tags.
3. Register a second `onPreResponse` after `preResponse` that stamps a per-path policy.
4. Start report-only:

```
Content-Security-Policy-Report-Only:
  default-src 'none';
  script-src 'nonce-{N}' 'self' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self';
  worker-src 'self' blob:;
  frame-src 'self';
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'none';
  object-src 'none'
```

`connect-src 'self'` covers the `EventSource('/admin/changes')` at `static/js/app.js:359`.
`img-src data:` is needed by our own CSS too - `static/css/flyonui.css` carries 109
`url("data:image/svg+xml...")` icon masks.

### Phase 2 - drop `unsafe-eval`

Precompile the two Handlebars partials and switch to `handlebars.runtime`; move the filter
evaluator into the sandbox iframe route; set `loadWorkerFromBlob: false` and drop `blob:` from
`worker-src`.

### Phase 3 - drop `style-src 'unsafe-inline'`

Convert the 63 `style=` attributes; move the message body into the sandboxed iframe route. This is
the phase that decides the remote-image question.

### Phase 4 - enforce

Flip report-only to enforcing on `/admin`. Give `/admin/bull-board/*` and the public hosted pages
their own documented, looser policies. Expose an `EENGINE_CSP` escape hatch (`enforce` /
`report-only` / `off`) so an operator with a broken custom branding block can degrade rather than
lose their instance, and so the reverse-proxy guidance in `DOCKER_DEPLOYMENT.md` can be updated to
say "do not duplicate this at the proxy".

## 5. Traps worth writing down before anyone starts

- **`Permissions-Policy` will break passkey login** if written the usual copy-pasted deny-all way.
  WebAuthn needs `publickey-credentials-get=(self)` and `publickey-credentials-create=(self)`
  (`static/js/login-passkey.js:41`, `static/js/passkey-register.js:74`), and the copy buttons need
  `clipboard-write=(self)` (`static/js/ui.js:325`). Per the project's own auth design note, passkey
  is a standalone sufficient factor, so breaking it locks people out rather than degrading them.
- **`frame-ancestors 'none'` is safe on `/admin` but not obviously safe on the public pages.** The
  hosted authentication form is a page operators redirect their users to, and some of them will be
  framing it. Deny on `/admin` and `/v1`; make the public surface configurable, defaulting to `'self'`.
- **`COEP: require-corp` would break bull-board's Google Fonts.** COOP alone is fine; do not reach
  for COEP without resolving 3.6 first.
- **Header stamping must run after `preResponse`, not inside it.** `preResponse` builds a *new*
  response for Boom errors (`workers/api.js:3175-3180`); headers set on the old one are discarded,
  so error pages would silently ship with no policy - which is exactly where an injected payload
  would like to land.
- **A nonce is not a fix for the interpolated inline scripts.** It makes them trusted. Do the
  `jsonForScript()` data-island conversion in the same pass, or the CSP will be asserting a safety
  property that is not there.

## 6. How to validate

The Playwright suite in `test/e2e/` is the right harness and already visits about 40 admin pages
(`pages-admin.spec.js`), plus `hosted-form.spec.js`, `reference.spec.js`, `unsubscribe.spec.js`,
`pages-bull-board.spec.js`. `test/e2e/helpers/bootstrap.js:26-33` already collects console errors
per test with the convention that every spec asserts zero.

Extend that same helper to listen for `securitypolicyviolation` on the page and assert zero
violations. With report-only shipped in phase 1, every page the suite already visits becomes a CSP
regression test for free, and the assertion pattern matches what the suite already does for console
errors. That is the mechanism that keeps a policy from rotting the first time somebody adds an
inline script.

I did try to run this empirically during the investigation - injecting the phase-1 policy as
report-only via Playwright route interception and collecting violations per page. It could not be
run: `node_modules` in this working copy is a production-only install with no `node_modules/.bin`
and no `@playwright/test`, and installing dev dependencies would have modified the tree. Worth doing
as the first concrete step, since it converts every estimate in section 3 into a measured list.

## 7. Suggested order of work

1. Phase 0 headers. Small, self-contained, no markup dependency. `fix:` prefix.
2. The empirical report-only probe under `test/e2e/`, to replace section 3's estimates with counts.
3. Nonce plumbing plus the `jsonForScript()` data-island conversion, shipped together.
4. Sandbox iframe route. Serves 3.2 and 3.5 with one mechanism, and is worth doing on security
   grounds even if the CSP work stopped right after.
5. Handlebars precompile, Ace worker path, `style=` sweep. Independent, parallelizable, dull.
6. Public-surface policy and the branding-block escape hatch. Needs a product call on how much to
   break for operators using `templateHtmlHead` as documented.
7. Enforce, and update `DOCKER_DEPLOYMENT.md` so the proxy guidance stops duplicating what the app
   now sends.

Steps 1 and 2 are worth doing regardless of whether the rest ever happens.
