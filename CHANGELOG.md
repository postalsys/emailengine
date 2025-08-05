# Changelog

## [2.54.2](https://github.com/postalsys/emailengine/compare/v2.54.1...v2.54.2) (2025-08-05)


### Bug Fixes

* dark mode support for message browser ([59d3c31](https://github.com/postalsys/emailengine/commit/59d3c31d58ea46d31b9908188b599c2169da87f7))
* **delegated:** Fixed mailbox listing for delegated OAuth2 accounts ([9fc74fd](https://github.com/postalsys/emailengine/commit/9fc74fd41e00a92eb121a85efa134947497de608))
* limit session token usage for the message browser ([41ead92](https://github.com/postalsys/emailengine/commit/41ead924917930f828f996b43c6a16a73c8c7bb9))
* message browser uses theme based confirm instead of sync javascript confirm ([9409d2c](https://github.com/postalsys/emailengine/commit/9409d2c7e4a93fd9ab16876baf52294968511840))
* **verify:** Slightly faster account data verification ([3e27d5e](https://github.com/postalsys/emailengine/commit/3e27d5e75f4a59e97aca7a3eff8a041c3d540935))

## [2.54.1](https://github.com/postalsys/emailengine/compare/v2.54.0...v2.54.1) (2025-08-03)


### Bug Fixes

* **oauth2:** Fixed issues with OAuth2 periodic renewals (subscriptions etc) ([046bd55](https://github.com/postalsys/emailengine/commit/046bd5585f24d8184a4cca7484afbb3fda93fbf4))

## [2.54.0](https://github.com/postalsys/emailengine/compare/v2.53.3...v2.54.0) (2025-08-01)


### Features

* **ui:** Added message browser to account view ([a1e27d8](https://github.com/postalsys/emailengine/commit/a1e27d8004631d62849ba7f08451eec0cc731cca))


### Bug Fixes

* move from OAS v2 to OAS v3 ([49e7018](https://github.com/postalsys/emailengine/commit/49e7018d8003397bce7383c7aac6b39c1ff1e3d0))
* normalize OAuth2 subscription keys ([a400e73](https://github.com/postalsys/emailengine/commit/a400e7397d509ef6bba1a47d7dd8535b019862c4))
* Show the token description on the delete token confirmation modal ([495af4f](https://github.com/postalsys/emailengine/commit/495af4fb860e705b983674a5e8d708a09ef9de20))

## [2.53.3](https://github.com/postalsys/emailengine/compare/v2.53.2...v2.53.3) (2025-07-17)


### Bug Fixes

* **delegated-oauth:** Handle delegated MS Graph account properly if created using delegated=true ([4cece01](https://github.com/postalsys/emailengine/commit/4cece016eac3033aae14422a31444c93c8375423))
* **MS-Graph:** Fixed IMAP and SMTP hosts for Government Cloud accounts ([e78a9cb](https://github.com/postalsys/emailengine/commit/e78a9cb6c480c740c2c3abb9b50a8c7c7f6e7ee7))
* **no-active-handler:** Fixed response code 200 for No Active Handler response ([067a37b](https://github.com/postalsys/emailengine/commit/067a37b4326d4ab0f4d2ae188220a0716921c0f0))
* **search:** Prefer WITHIN extension and YOUNGER/OLDER for SINCE/BEFORE searches ([34d5889](https://github.com/postalsys/emailengine/commit/34d5889b84812537ca592089f58abde5d4005223))

## [2.53.2](https://github.com/postalsys/emailengine/compare/v2.53.1...v2.53.2) (2025-07-09)


### Bug Fixes

* **language:** Added language selection with ?locale=et query argument ([b911ec3](https://github.com/postalsys/emailengine/commit/b911ec31e93c75be281d7f79f18b9dcbab2ba1cb))
* **no active handler:** Return 503 error, not 200 ([d1e0702](https://github.com/postalsys/emailengine/commit/d1e070292df2000005cca2f000094fc21e5d43df))
* **smtp:** Improved Message-ID rewriting detection for AWS SES ([fbe7ff3](https://github.com/postalsys/emailengine/commit/fbe7ff3b99b4142cc263d15dcea47733f343a2ce))
* Special envelope handling for LarkSuite accounts ([f448d39](https://github.com/postalsys/emailengine/commit/f448d39ecb958f926c05a28d7ad3ca110f16c17a))

## [2.53.1](https://github.com/postalsys/emailengine/compare/v2.53.0...v2.53.1) (2025-07-04)


### Bug Fixes

* **multi-operations:** Added new search term 'emailIds', if set it will use the predefined email IDs instead of executing the search ([aac3aab](https://github.com/postalsys/emailengine/commit/aac3aab65e1eea3b51ea302b5634f3e2b1a30063))
* removed dotenv debug log line ([9c5fc1b](https://github.com/postalsys/emailengine/commit/9c5fc1b4b3cb1c38c7604eec75f5427bf0f8482b))
* **webhooks:** Include a HMAC signature in webhook headers ([7516188](https://github.com/postalsys/emailengine/commit/75161881c9100c2d5a2bec22790aa3311a2de87f))

## [2.53.0](https://github.com/postalsys/emailengine/compare/v2.52.6...v2.53.0) (2025-06-30)


### Features

* Use persistent SMTP connections instead of logging separately for every email sent by the same account ([866e24f](https://github.com/postalsys/emailengine/commit/866e24fd06760ab92752629b259577fcf620b781))


### Bug Fixes

* Bumped deps to fix formwat=flowed parsing issue ([efffe4e](https://github.com/postalsys/emailengine/commit/efffe4e7be778667a1119343e71e86817e1dc71e))

## [2.52.6](https://github.com/postalsys/emailengine/compare/v2.52.5...v2.52.6) (2025-06-23)


### Bug Fixes

* Reverted ICOn handling for windows app ([7abba87](https://github.com/postalsys/emailengine/commit/7abba87b749ed36ccd663dabfc26fa7a2d2b320d))
* **submit:** Added configuration ENV option EENGINE_SUBMIT_DELAY / --submitDelay=duration argument to allow rate limiting message sending (this is global, not account specific) ([531caad](https://github.com/postalsys/emailengine/commit/531caadb00d8b7d8710668509845d9452c9c924d))
* **translations:** Allow changing active language with ?lang=lang_code query argument ([1f2a0e6](https://github.com/postalsys/emailengine/commit/1f2a0e6070a9dfa5989e6055648fb1d0f4d8c095))

## [2.52.5](https://github.com/postalsys/emailengine/compare/v2.52.4...v2.52.5) (2025-05-20)


### Bug Fixes

* **virtual-list:** Fixed authentication requirement for the public re-subscribe page ([956fdfa](https://github.com/postalsys/emailengine/commit/956fdfaaa0946004939e9774a42306b50b51d7aa))

## [2.52.4](https://github.com/postalsys/emailengine/compare/v2.52.3...v2.52.4) (2025-05-13)


### Bug Fixes

* **encryption:** Cache keys in memory to avoid using scrypt every time a secret is accessed ([cbfcde5](https://github.com/postalsys/emailengine/commit/cbfcde507cbb920ac888e0c23f13437c0b4017f4))
* **message/rfc822:** Fixed message/rfc822 attachment handling when sending emails ([af2bf30](https://github.com/postalsys/emailengine/commit/af2bf308a7634c01c065f06c75503597b6c42690))
* **UI:** prevent trying to format a non-existing timestamp value ([d97bb92](https://github.com/postalsys/emailengine/commit/d97bb923de611c5bd45b0ef7df1ddbbec0b184b1))
* **webhooks:** Include envelope property in messageSent for Gmail API and MS Graph API submissions ([6b1a3fa](https://github.com/postalsys/emailengine/commit/6b1a3fa98b6370af5ba006ee486d400737fd9845))

## [2.52.3](https://github.com/postalsys/emailengine/compare/v2.52.2...v2.52.3) (2025-05-01)


### Bug Fixes

* **gmail-api:** Fixed special use label handling when updating messages ([9e06ed7](https://github.com/postalsys/emailengine/commit/9e06ed79c3c1e4db0995df64f84c587e02645a7e))

## [2.52.2](https://github.com/postalsys/emailengine/compare/v2.52.1...v2.52.2) (2025-04-30)


### Bug Fixes

* Allow adding shared MS accounts directly via the /v1/accounts endpoint ([c77e61e](https://github.com/postalsys/emailengine/commit/c77e61ea16d67c84b1a7b1b0d49f60f577a73839))
* Dutch translations ([#526](https://github.com/postalsys/emailengine/issues/526)) ([ebbd783](https://github.com/postalsys/emailengine/commit/ebbd783d5787f056b1d25a22f15932b18dd6deff))
* **schema:** Updated settings schema descriptions. Added imapClient... setting keys to configure RFC2971 IMAP ID extension ([bc38322](https://github.com/postalsys/emailengine/commit/bc383225a522c4c7b1912f260f9a902a6e4be4b1))

## [2.52.1](https://github.com/postalsys/emailengine/compare/v2.52.0...v2.52.1) (2025-04-18)


### Bug Fixes

* **messageBounce:** Check messages in the Junk folder as well for bounces ([0def3e3](https://github.com/postalsys/emailengine/commit/0def3e3635376118ea9379369f018b52f0f8d66e))
* **workmail:** better detection of bounce emails with AWS WorkMail ([1a8e750](https://github.com/postalsys/emailengine/commit/1a8e7503447f1a6db4b67fa9771374274c9f2e3b))

## [2.52.0](https://github.com/postalsys/emailengine/compare/v2.51.3...v2.52.0) (2025-04-10)


### Features

* **sending:** Support 'Idempotency-Key' header for /submit message requests and 'X-EE-Idempotency-Key' SMTP header to avoid sending duplicate emails ([1423135](https://github.com/postalsys/emailengine/commit/1423135b7049449bfb4be68cc03baa7f1b6a1a62))


### Bug Fixes

* **gmail-api:** Show a failure message if OAuth2 configured scopes are insufficient ([f72b5f3](https://github.com/postalsys/emailengine/commit/f72b5f3f72d03f1750d36f5adffa525d1b90c1d9))
* **markAsSeen:** fix markAsSeen option for Gmail API and MS Graph API ([7e2dcdc](https://github.com/postalsys/emailengine/commit/7e2dcdcbd4a9726855f5ec216fac0d4212ca2e5f))
* **ms-graph-api:** Fix fetching message/rfc822 attachments ([c55bcbd](https://github.com/postalsys/emailengine/commit/c55bcbdcd1dc88c2ed3b4442fb8c074e31c9256c))

## [2.51.3](https://github.com/postalsys/emailengine/compare/v2.51.2...v2.51.3) (2025-03-26)


### Bug Fixes

* **gmail-watch:** Allow setting subscription name for Gmail PubSub ([529f698](https://github.com/postalsys/emailengine/commit/529f698837a90f4f813832026fcafcc1e62762e9))
* **gmail-watch:** Log and show information watch renewal failures ([7a59ce9](https://github.com/postalsys/emailengine/commit/7a59ce9a97a2e9d5c44e20598a1f3d2c7a1f3ae8))
* **websafe:** Process web safe HTML before injecting base64 attachments to speed the process up ([b04d0fe](https://github.com/postalsys/emailengine/commit/b04d0fed1852677a6787438d1d0f73f2d9cc4f4d))

## [2.51.2](https://github.com/postalsys/emailengine/compare/v2.51.1...v2.51.2) (2025-03-25)


### Bug Fixes

* **google-oauth:** Allow to specify the PubSub Topic Name instead of using the autogenerated value ([41f362b](https://github.com/postalsys/emailengine/commit/41f362b96aa250591e190a565a24683b313fc93e))
* **imap-proxy:** Fixed regression bug in IMAP proxy interface ([612d9f9](https://github.com/postalsys/emailengine/commit/612d9f963402a952bfaee41eeda09acd6e6225aa))

## [2.51.1](https://github.com/postalsys/emailengine/compare/v2.51.0...v2.51.1) (2025-03-17)


### Bug Fixes

* **connection-counter:** Only decrease connection counter if a connection was actually removed ([d402888](https://github.com/postalsys/emailengine/commit/d4028884ad4261eaf0c09faedab8bb395a92abde))

## [2.51.0](https://github.com/postalsys/emailengine/compare/v2.50.10...v2.51.0) (2025-03-07)


### Features

* Attachments in new message webhooks ([#514](https://github.com/postalsys/emailengine/issues/514)) ([81d0d8f](https://github.com/postalsys/emailengine/commit/81d0d8f48a7bcc5a9ac1a9c5b00e7556fad2edb0))


### Bug Fixes

* schema updates for message update ([4d293a1](https://github.com/postalsys/emailengine/commit/4d293a1954b9d7968c95a758175882a640292328))
* **webhook-routing:** Do not throw 500 when viewing a failing webhook routing page ([a8acde2](https://github.com/postalsys/emailengine/commit/a8acde26cedda4831b0996805adc7bcacc4c807e))

## [2.50.10](https://github.com/postalsys/emailengine/compare/v2.50.9...v2.50.10) (2025-02-24)


### Bug Fixes

* maintenance release ([bed7e16](https://github.com/postalsys/emailengine/commit/bed7e16ff3377fcca6e5a47fc69a987aed511514))

## [2.50.9](https://github.com/postalsys/emailengine/compare/v2.50.8...v2.50.9) (2025-02-23)


### Bug Fixes

* **docker:** reverted docker release action ([c205aae](https://github.com/postalsys/emailengine/commit/c205aae5953a63e2fab1cf52e534468d3dedddeb))

## [2.50.8](https://github.com/postalsys/emailengine/compare/v2.50.7...v2.50.8) (2025-02-22)


### Bug Fixes

* **inline-html:** Fixed reply and forward inline emails if only text was set ([2efaa77](https://github.com/postalsys/emailengine/commit/2efaa77c122b099a2607e045c10cb6ab05900e78))

## [2.50.7](https://github.com/postalsys/emailengine/compare/v2.50.6...v2.50.7) (2025-02-11)


### Bug Fixes

* **api:** Added new method to list Gmail signatures for an account ([c7e379a](https://github.com/postalsys/emailengine/commit/c7e379aad46843419dad0ce2fd30f269a241c484))
* **notificationBaseUrl:** Allow using a path component in the base URL ([d2af058](https://github.com/postalsys/emailengine/commit/d2af058cc987636481093466e4ffe7574782533b))
* **submit:** Added new message reference action 'reply-all' ([b0bd69f](https://github.com/postalsys/emailengine/commit/b0bd69f8ac5abc9b63110cc8eaf63f2ba41b8b64))

## [2.50.6](https://github.com/postalsys/emailengine/compare/v2.50.5...v2.50.6) (2025-02-10)


### Bug Fixes

* **dockerfile:** Unpin Node version ([4feb420](https://github.com/postalsys/emailengine/commit/4feb420009a7af613343690007d787063e20e1a0))
* **docker:** Pin Node version in Dockerfile ([decb751](https://github.com/postalsys/emailengine/commit/decb7510ef9e9b107277c8d687ab8e3af94b3975))
* **docker:** Publish tags to Github Registry as well ([24db762](https://github.com/postalsys/emailengine/commit/24db762b72a3bf45679e4c0263c35a24f9bb261f))

## [2.50.5](https://github.com/postalsys/emailengine/compare/v2.50.4...v2.50.5) (2025-02-04)


### Bug Fixes

* **api:** Improved message-move API endpoint for Gmail API accounts. There is now a new payload option 'source' that specifies the folder the message is moved from ([861bc23](https://github.com/postalsys/emailengine/commit/861bc2369229346815863859dfe2d5281748e865))
* **gmail-api:** clear label cache after modifying labels ([ca60f89](https://github.com/postalsys/emailengine/commit/ca60f89e8eddc736da5fd4fab33029fc4947c3fc))
* **oauth:** Return 'id' not 'message' for message upload requests against Gmail API and MS Graph API ([d1bd122](https://github.com/postalsys/emailengine/commit/d1bd1226f6297224efed6775bc8d72b656b8faa0))
* **worker-close:** If worker dies then do not try to update accounts statuses to prevent race conditions ([d532365](https://github.com/postalsys/emailengine/commit/d532365b321efef63d3c68965631b61381533c45))

## [2.50.4](https://github.com/postalsys/emailengine/compare/v2.50.3...v2.50.4) (2025-01-29)


### Bug Fixes

* **deps:** Bumped ImapFlow to improve handling of unstable IMAP connections ([3dfa5fa](https://github.com/postalsys/emailengine/commit/3dfa5fa7f0dfcb99f3319dd4bbbb1d4cdb14c5b6))
* **ms-graph:** Added new setting notificationBaseUrl to set a different webhook URLs for MS Graph notificationUrl and lifecycleNotificationUrl than serviceUrl ([0963041](https://github.com/postalsys/emailengine/commit/09630414cd80b37cb9c223b3acd140dffac64d12))
* **translations:** Added Polish translations; Merge pull request [#497](https://github.com/postalsys/emailengine/issues/497) from jakubmieszczanin/master ([b0b29e5](https://github.com/postalsys/emailengine/commit/b0b29e5e716724d2e143afd7120c0677bfbe6fec))

## [2.50.3](https://github.com/postalsys/emailengine/compare/v2.50.2...v2.50.3) (2025-01-26)


### Bug Fixes

* **redis:** Tolerate Redis reconnections better ([5d3627c](https://github.com/postalsys/emailengine/commit/5d3627c62662428e3a9e9316f54ff4cd8062fcce))

## [2.50.2](https://github.com/postalsys/emailengine/compare/v2.50.1...v2.50.2) (2025-01-23)


### Bug Fixes

* **filename:** Fixed filename handling for message responses from servers without parameter continuation support ([1463506](https://github.com/postalsys/emailengine/commit/14635065b2d5a9c12190aa3f5b2a5177948f0d01))
* **oauth-smtp:** Fixed authentication username for shared outlook SMTP accounts ([c4ca913](https://github.com/postalsys/emailengine/commit/c4ca913f14321cc8c852158c8d9cdecf0eb58061))

## [2.50.1](https://github.com/postalsys/emailengine/compare/v2.50.0...v2.50.1) (2025-01-19)


### Bug Fixes

* **web:** Fixed preview function for public website templates in the admin UI ([6f3567b](https://github.com/postalsys/emailengine/commit/6f3567be5abd796f3397014a37021809a6645112))

## [2.50.0](https://github.com/postalsys/emailengine/compare/v2.49.7...v2.50.0) (2025-01-13)


### Features

* **oauth2-apps:** Added search field to the OAuth2 application listing page to search OAuth2 applications ([69144fe](https://github.com/postalsys/emailengine/commit/69144fe01fdfba3d5448419a7ef46abba5c1aa4c))


### Bug Fixes

* **ms-graph-api:** Fixed plaintext content handling when retrieving emails from MS Graph API ([0166a0a](https://github.com/postalsys/emailengine/commit/0166a0a8121feab6900da49d2d544899f2f23fd7))

## [2.49.7](https://github.com/postalsys/emailengine/compare/v2.49.6...v2.49.7) (2025-01-09)


### Bug Fixes

* **imap-auth:** Bumped ImapFlow dependency to fix issue with AUTHENTICATE LOGIN on some IMAP servers ([c1a5fba](https://github.com/postalsys/emailengine/commit/c1a5fbaedd7c1d3ade881ee48db8cc9e238a042b))

## [2.49.6](https://github.com/postalsys/emailengine/compare/v2.49.5...v2.49.6) (2025-01-08)


### Bug Fixes

* **deps:** Bumped ImapFlow to handle invalid BODYSTRUCTURE from BlueMind ([1174a29](https://github.com/postalsys/emailengine/commit/1174a29aea60f5f2fc24c35eb565f0e2e1633e86))
* **http-requests:** Use undici RetryAgent for HTTP request network errors and 429 rate limiting, removed custom 429 handler ([bafcd1c](https://github.com/postalsys/emailengine/commit/bafcd1c1551a2c00809b07d31e2ba67b1c9d19df))
* **message-upload:** Fix message upload if uploading to a child folder of Inbox using MS Graph API ([2c14b5e](https://github.com/postalsys/emailengine/commit/2c14b5eb80ff1fe60e03504bd6550e06698210ee))
* **ms-graph-api:** Upload message as a JSON structure instead of EML with MS Graph API in order to set meta info like flags ([c7fde6f](https://github.com/postalsys/emailengine/commit/c7fde6fedb127773cfbf4cff1937cad1a91148cd))
* **ui:** Replaced 2024 with 2025 in static HTML pages ([99e805b](https://github.com/postalsys/emailengine/commit/99e805b5ce1e373b60bbaa2b9f0fa138f8f8d27b))

## [2.49.5](https://github.com/postalsys/emailengine/compare/v2.49.4...v2.49.5) (2024-12-30)


### Bug Fixes

* **Auth-server:** Ensure correct oauth2 username and history ID for accounts added with auth server ([aa68c0d](https://github.com/postalsys/emailengine/commit/aa68c0d7519565d0ce7915a4397148199fc664d2))
* **oauth-flow:** Fixed page title on the redirect page after OAuth2 code has been received ([b2c0c5a](https://github.com/postalsys/emailengine/commit/b2c0c5a28da3550eeb8754b5efec18254b6d8ff5))
* **templates:** Allow setting brand name to replace 'EmailEngine' in the HTML title ([bf85c06](https://github.com/postalsys/emailengine/commit/bf85c06aaf92d2f3d54dbfde5771a2df3a71b9b9))

## [2.49.4](https://github.com/postalsys/emailengine/compare/v2.49.3...v2.49.4) (2024-12-13)


### Bug Fixes

* **cors:** Removed custom OPTIONS preflight handler in favor of default Hapi CORS handler ([6427728](https://github.com/postalsys/emailengine/commit/6427728bcc56249bb4acb4adcc817bd9c2221f2f))
* **oauth2:** Fixed field encryption for OAuth2 apps ([a0c3eaa](https://github.com/postalsys/emailengine/commit/a0c3eaacc117257e3b1303f161650c0b16ff051f))

## [2.49.3](https://github.com/postalsys/emailengine/compare/v2.49.2...v2.49.3) (2024-12-09)


### Bug Fixes

* **gmail-api:** Fixed attachment forwarding when using Gmail API ([6aef655](https://github.com/postalsys/emailengine/commit/6aef65556d501a3df7dde845ae9470bf575ebb56))
* **gmail-api:** Fixed threading for replied messages when using Gmail API ([2b4d5bb](https://github.com/postalsys/emailengine/commit/2b4d5bbbebf66ecf44a4dcefa789e7813b043d1e))

## [2.49.2](https://github.com/postalsys/emailengine/compare/v2.49.1...v2.49.2) (2024-12-03)


### Bug Fixes

* **deps:** Downgraded elasticsearch dependency to avoid including ESM dependencies ([78d6aed](https://github.com/postalsys/emailengine/commit/78d6aed2a0baba61fd381785d1cc63e9b1654871))

## [2.49.1](https://github.com/postalsys/emailengine/compare/v2.49.0...v2.49.1) (2024-12-03)


### Bug Fixes

* **delivery-test:** Fixed gateway usage with delivery tests ([ec94223](https://github.com/postalsys/emailengine/commit/ec9422397fe392f815c8c3c0f8337f4a5cef55cd))
* **deps:** Bumped email-text-tools to fix failing preProcessHtml and webSafeHtml ([4de02ae](https://github.com/postalsys/emailengine/commit/4de02aeb98a1f481cabcc309f6b58bfa5820affe))
* Prevent throwing an exception if serviceUrl is not set ([e947a0b](https://github.com/postalsys/emailengine/commit/e947a0bf6f15cacbd2426dd81df03f9acba6a340))

## [2.49.0](https://github.com/postalsys/emailengine/compare/v2.48.7...v2.49.0) (2024-11-10)


### Features

* **delegated-accounts:** Allow using credentials from another existing account for a shared MS365 mailbox account ([fc17b02](https://github.com/postalsys/emailengine/commit/fc17b029c06c4053342fd10834b221828af1e387))
* **delegated-accounts:** Allow using delegated MS Graph API accounts; pull request [#475](https://github.com/postalsys/emailengine/issues/475) from postalsys/shared-ms-api ([f0627e9](https://github.com/postalsys/emailengine/commit/f0627e9cf382c72acfe0e2134dd8fb1e0e5a1239))


### Bug Fixes

* **gateway:** Fixed gateway based sending for API accounts ([86c2c02](https://github.com/postalsys/emailengine/commit/86c2c02cc8f73d7967dd9fd37c3fb0fee9abefba))

## [2.48.7](https://github.com/postalsys/emailengine/compare/v2.48.6...v2.48.7) (2024-11-07)


### Bug Fixes

* **gateway:** Fixed gateway testing ([6c29c87](https://github.com/postalsys/emailengine/commit/6c29c870bf065bc846b7244516489e9943779247))
* **imap-auth:** Always use username and password as string, not atom for LOGIN command ([1064d1f](https://github.com/postalsys/emailengine/commit/1064d1fdb0040ca812ecca151b129dd34c4ab081))
* **imap-auth:** Prefer AUTH=LOGIN and AUTH=PLAIN to LOGIN for better compatibility of special characters ([7e09d2d](https://github.com/postalsys/emailengine/commit/7e09d2de20c328394057f90c89e8af2ccdcc4339))

## [2.48.6](https://github.com/postalsys/emailengine/compare/v2.48.5...v2.48.6) (2024-11-01)


### Bug Fixes

* **admin:** Fixed pagination URL for oauth2 listing ([4140e34](https://github.com/postalsys/emailengine/commit/4140e3458d640e5f1ecdb4a270363be3e506dd00))
* **outlook-api:** Falls back to username as account email if failed to retrieve account email address ([57f3d82](https://github.com/postalsys/emailengine/commit/57f3d827ce68f33971ffb53dfc02421885d6b960))
* **stats:** Correctly detect account state for Gmail/MS Graph API accounts ([a5af1de](https://github.com/postalsys/emailengine/commit/a5af1de3e9145570756fc081c686d6c329914a7b))

## [2.48.5](https://github.com/postalsys/emailengine/compare/v2.48.4...v2.48.5) (2024-10-31)


### Bug Fixes

* **hosted-authentication:** If a user tries to add an hotmail/outlook account with a password, show a warning about MS disabling password based auth ([dd0407e](https://github.com/postalsys/emailengine/commit/dd0407e858bbbdd7244259733ee5d37de6296901))
* **outlook-api:** Detect if message is from Inbox when processing messageNew webhook ([2a72aa0](https://github.com/postalsys/emailengine/commit/2a72aa098340f4cbd12b08a71a858960ffb52ece))
* **outlook-api:** If mail property is not provided in user profile, then use userPrincipalName instead ([2e2224c](https://github.com/postalsys/emailengine/commit/2e2224cb8ded44286af9148ebe8a75234ae422db))
* **redis:** Do not use Redis connectionName to avoid calling CLIENT command ([aafc732](https://github.com/postalsys/emailengine/commit/aafc7328992baa6ce26292a9f67007b3989fd0b0))

## [2.48.4](https://github.com/postalsys/emailengine/compare/v2.48.3...v2.48.4) (2024-10-25)


### Bug Fixes

* **account-state:** Only swiths to disconnected if the account was previously connected ([4f56fe3](https://github.com/postalsys/emailengine/commit/4f56fe365af98b338b51710b9911abf8021e0afe))
* **outlook-api:** Fixed missing redis object ([c248e49](https://github.com/postalsys/emailengine/commit/c248e49443b5bdbf85f36707a32965a264f8d8b4))

## [2.48.3](https://github.com/postalsys/emailengine/compare/v2.48.2...v2.48.3) (2024-10-25)


### Bug Fixes

* **change-events:** Trigger a 'disconnected' event when an account is deleted and the connection is closed ([bf56440](https://github.com/postalsys/emailengine/commit/bf56440d429b19ef1960a8b4527502a43bcc89a1))
* **oauth-api:** Do not try to convert null to string when making an OAuth2 API request ([5231327](https://github.com/postalsys/emailengine/commit/523132714a91c2b625095ea62bb1ec2d6e2c5ba8))
* **outlook-api:** Ensure seemsLikeNew value for new message webhooks ([16e12c0](https://github.com/postalsys/emailengine/commit/16e12c000e57b993344fb329f037cb46a9f7b2b1))
* **outlook-search:** Allow using $search instead of $filter by setting the useOutlookSearch query argument ([3a0d75e](https://github.com/postalsys/emailengine/commit/3a0d75e45043b0a5beb32e6465ebbf7cc2676c85))
* **redis:** Do not set connection name to prevent calling CLIENT.SETNAME command ([166a947](https://github.com/postalsys/emailengine/commit/166a94708301a758be7b479f6f42b25df8d1faa5))

## [2.48.2](https://github.com/postalsys/emailengine/compare/v2.48.1...v2.48.2) (2024-10-23)


### Bug Fixes

* **metrics:** Ensure that unassigned accounts are included in the 'disconnectedä state count ([d502425](https://github.com/postalsys/emailengine/commit/d5024256f3f715a0b9ad849d911684cb059ad742))
* **metrics:** Include thread counts in Prometheus output ([04e978e](https://github.com/postalsys/emailengine/commit/04e978e9ef8962cef05619dea508a4b8e9a4c191))
* **oauth2:** Allow to specify to show only Google Workspace accounts on OAuth2 login screen ([a3b2412](https://github.com/postalsys/emailengine/commit/a3b2412342a79b2f012c328bae8839e36a6a07d4))
* **submit:** Added additional and optional reference field 'messageId'. If set then this value is validated against the Message-ID header of the referenced email ([8d76345](https://github.com/postalsys/emailengine/commit/8d76345fa51827cb81e1849ffbfee3f1cecdb2e3))

## [2.48.1](https://github.com/postalsys/emailengine/compare/v2.48.0...v2.48.1) (2024-10-18)


### Bug Fixes

* **certs:** Show a proper error response for failed ACME validation requests ([71dfeba](https://github.com/postalsys/emailengine/commit/71dfeba07c9fd22c2b26003e6f4f44b1062ddbfc))
* **oauth-api:** Use a default cloud value for outlook OAuth2 apps if AzureCloud is not specified ([1affc1d](https://github.com/postalsys/emailengine/commit/1affc1d8dd29ca96d18cd91af810c6abd7820058))
* **oauth2:** Double check if OAuth2 account is actually already used before throwing AccountAlreadyExists error ([3f967a9](https://github.com/postalsys/emailengine/commit/3f967a93e6ade6d0f25429521cd551eb6f48de53))

## [2.48.0](https://github.com/postalsys/emailengine/compare/v2.47.0...v2.48.0) (2024-10-14)


### Features

* **imap:** Added new IMAP indexing option: 'fast' ([1d6df05](https://github.com/postalsys/emailengine/commit/1d6df05e5a95b45eabda368bee8f93471fc21377))


### Bug Fixes

* **outlook:** Fixed Outlook OAuth2 connection ([920aa20](https://github.com/postalsys/emailengine/commit/920aa20fc2847cc419592a181d127a7c796df940))

## [2.47.0](https://github.com/postalsys/emailengine/compare/v2.46.5...v2.47.0) (2024-10-07)


### Features

* **bullmq:** Replaced Bull Arena with Bull Board ([e6762b9](https://github.com/postalsys/emailengine/commit/e6762b9c4c23a8fbb63f19bd10dd6c8676b94f43))


### Bug Fixes

* **oauth:** Added 'useAuthServer' support for API based email accounts ([04c2aa9](https://github.com/postalsys/emailengine/commit/04c2aa905de8793f6150f69cc47e0ac26bf1e9d1))
* **swagger:** Use embedded Swagger UI instead of Iframe ([ce9fd6a](https://github.com/postalsys/emailengine/commit/ce9fd6a02685f76eed060b9eef2551a91874e732))
* **templates:** Allow to inject HTML code to the &lt;head&gt; tag of the public pages like authentication form or 404 error page ([bd97a7c](https://github.com/postalsys/emailengine/commit/bd97a7c06430407a2e6be9aea33136eec1e6626b))

## [2.46.5](https://github.com/postalsys/emailengine/compare/v2.46.4...v2.46.5) (2024-09-25)

### Bug Fixes

-   **release:** Use node v20 for prepackaged binaries ([ed2a161](https://github.com/postalsys/emailengine/commit/ed2a16165c6b7b57171d3d638ee5894831910687))

## [2.46.4](https://github.com/postalsys/emailengine/compare/v2.46.3...v2.46.4) (2024-09-23)

### Bug Fixes

-   **search:** Fixed resolving special use paths like \All ([3fb0c9c](https://github.com/postalsys/emailengine/commit/3fb0c9c34a864558172ba2660259432af8ed9260))
-   **security:** Generate Fluid-Attacks SAST Scan Results ([5780708](https://github.com/postalsys/emailengine/commit/5780708fc6c94240c9d34b8aa685348153e0fbf7))
-   **security:** Replaced node-gettext with @postalsys/gettext ([a13378a](https://github.com/postalsys/emailengine/commit/a13378a32bfdaed8afb9eb0dba045669e9004f45))

## [2.46.3](https://github.com/postalsys/emailengine/compare/v2.46.2...v2.46.3) (2024-09-10)

### Bug Fixes

-   **security:** Allow limiting IP addresses that are allowed to access /admin paths ([7b64009](https://github.com/postalsys/emailengine/commit/7b6400963eb6ce781074e39c63a2e3281f3b916d))

## [2.46.2](https://github.com/postalsys/emailengine/compare/v2.46.1...v2.46.2) (2024-09-07)

### Bug Fixes

-   **oauth2-api:** Set default value for Outlook OAuth2 cloud property when creating a new OAuth2 app via API ([d4e1993](https://github.com/postalsys/emailengine/commit/d4e199382c5759762afd2ffa832acbf9ea1a0318))
-   Upgraded dependencies ([abb9edf](https://github.com/postalsys/emailengine/commit/abb9edf05c79e7fdc3a5149b901e46d3bac3fd2f))

## [2.46.1](https://github.com/postalsys/emailengine/compare/v2.46.0...v2.46.1) (2024-09-04)

### Bug Fixes

-   **click-open-tracking:** Allow to configure clicks and opens tracking separately with trackOpens and trackClicks options ([1cc55bc](https://github.com/postalsys/emailengine/commit/1cc55bcfa7bf9f83b459d3690e510854bb2157d7))

## [2.46.0](https://github.com/postalsys/emailengine/compare/v2.45.1...v2.46.0) (2024-08-29)

### Features

-   **azure:** Added support for different Azure cloud environments ([#440](https://github.com/postalsys/emailengine/issues/440)) ([93a7010](https://github.com/postalsys/emailengine/commit/93a7010223558036d2b2d09c7008e888a48cc071))

### Bug Fixes

-   **autoconf-validation:** If autoconfig does not respond with full settings, do not auto-attempt configuration check ([cdc5765](https://github.com/postalsys/emailengine/commit/cdc57650479941e230fc99d53709cfdc0ed7ebb1))
-   **autoconfig:** Added configuration information for ATT email accounts ([729de83](https://github.com/postalsys/emailengine/commit/729de83e0e2bb9728ca33d01eff2345d8795938e))
-   **imap:** Disable IMAP syncing if authentication fails too many times ([def4404](https://github.com/postalsys/emailengine/commit/def4404e62ce76838f9e6dc37c1cbefc2f5cf8d0))
-   **link-tracking:** Fixed unsubscribe links when click tracking is enabled ([34cdc38](https://github.com/postalsys/emailengine/commit/34cdc38ae801c7b04264c900c8fb2b35970f398c))

## [2.45.1](https://github.com/postalsys/emailengine/compare/v2.45.0...v2.45.1) (2024-08-23)

### Bug Fixes

-   Fixed a bug with invalid logger object ([e44de90](https://github.com/postalsys/emailengine/commit/e44de9041a041caa16499d83806543fbd2af8d0c))

## [2.45.0](https://github.com/postalsys/emailengine/compare/v2.44.1...v2.45.0) (2024-08-22)

### Features

-   Require minimally Node v18 (previously v16) ([dc8282e](https://github.com/postalsys/emailengine/commit/dc8282e09033d0554301c9c824e8cb74c79bdb19))
-   **templates:** Removed MJML support ([b976e53](https://github.com/postalsys/emailengine/commit/b976e53ff2e9eeb6591b16ac983e87f85ff70c76))

### Bug Fixes

-   **deps:** Bumped dependencies to fix web safe HTML ([7b20aff](https://github.com/postalsys/emailengine/commit/7b20affbeaa41377ac22accbbc39f2dddfc10961))
-   Use no-referrer policy for all \_blank links ([eef5757](https://github.com/postalsys/emailengine/commit/eef5757579667e9950aefce11d4cd5e68e1c2421))

## [2.44.1](https://github.com/postalsys/emailengine/compare/v2.44.0...v2.44.1) (2024-08-15)

### Bug Fixes

-   **oauth2:** Fixed Gmail API OAuth2 schema ([205f34e](https://github.com/postalsys/emailengine/commit/205f34e1c89eaf003d027aa0664023af0029c53e))

## [2.44.0](https://github.com/postalsys/emailengine/compare/v2.43.3...v2.44.0) (2024-08-15)

### Features

-   **ms-graph-api:** MS Graph API support ([#431](https://github.com/postalsys/emailengine/issues/431)) ([5e10dd3](https://github.com/postalsys/emailengine/commit/5e10dd3528c8c5ca6898f2ed0800f0d168fb8b33))

### Bug Fixes

-   **app-password:** Add T-Online to providers needing an app password ([#430](https://github.com/postalsys/emailengine/issues/430)) ([823939b](https://github.com/postalsys/emailengine/commit/823939b1d5e6934876537597ea52b52b4f12ab59))
-   **oauth-tokens:** Fix renewal check for access tokens ([f687aa1](https://github.com/postalsys/emailengine/commit/f687aa11752a2981a1237cc84cca1d26f24d1f49))
-   **outlook-oauth:** Show 'supported account types' as a selectable list instead of a text field input ([fe62e5b](https://github.com/postalsys/emailengine/commit/fe62e5b293307d42c6e8e1c200911d4eff4e26de))

## [2.43.3](https://github.com/postalsys/emailengine/compare/v2.43.2...v2.43.3) (2024-08-01)

### Bug Fixes

-   **cors:** Added missing OPTIONS handler for CORS ([205480d](https://github.com/postalsys/emailengine/commit/205480d4c150f35aa14edaa918b7635774eface3))

## [2.43.2](https://github.com/postalsys/emailengine/compare/v2.43.1...v2.43.2) (2024-07-29)

### Bug Fixes

-   **reconnect:** Allow reconnecting paused accounts ([b8e212f](https://github.com/postalsys/emailengine/commit/b8e212f512ad007d3fa3c2678d8dfdbf8155c0ca))

## [2.43.1](https://github.com/postalsys/emailengine/compare/v2.43.0...v2.43.1) (2024-07-21)

### Bug Fixes

-   **api-docs:** Updated information about total/pages/nextPageCursor ([cd12547](https://github.com/postalsys/emailengine/commit/cd12547096da14b2407156745bb86326134db177))
-   **cli:** Added command 'export' to retrieve raw account data with credentials ([9932801](https://github.com/postalsys/emailengine/commit/99328017918cf978ceadc4cc87f64e9b924d4ee6))
-   **gmail-api:** Fixed webhook notifications for authenticationSuccess and authenticationError ([2c3d63a](https://github.com/postalsys/emailengine/commit/2c3d63a5f62ee3fdfe3245c1e5128e908a679e82))
-   **gmail-api:** Log API requests to user log ([f00f864](https://github.com/postalsys/emailengine/commit/f00f86439af8484c7d55aa3b0e386e09f209dce0))
-   **oauth2:** Fixed broken extra scopes handling ([9185359](https://github.com/postalsys/emailengine/commit/91853599c238c79a326886107e8f62b23dd26973))

## [2.43.0](https://github.com/postalsys/emailengine/compare/v2.42.0...v2.43.0) (2024-07-08)

### Features

-   **gmail-api:** Gmail API Support ([#421](https://github.com/postalsys/emailengine/issues/421)) ([91b3cad](https://github.com/postalsys/emailengine/commit/91b3cad4537e8b5e2c2b9faad54f87c5d6997d15))

### Bug Fixes

-   **api:** Added support for paging cursors ([d3f7685](https://github.com/postalsys/emailengine/commit/d3f76857a1d139aa15646fe96dd0ef5d8a791fbe))
-   **api:** Do not allow to proxy connections for accounts with API scopes ([9498fa9](https://github.com/postalsys/emailengine/commit/9498fa9efbf0c6f341239e77514de9903e6195ee))
-   Fix exception when Document Store is disabled but there are embeddings stored ([6d18a48](https://github.com/postalsys/emailengine/commit/6d18a48e146a2aceb7fcf94dad21ce6959188bc4))
-   **font-loading:** Use a locally cached font instead of loading from Google FOnts ([4e53929](https://github.com/postalsys/emailengine/commit/4e539296d4f8bac3d4772fdcf1941611d1289846))
-   **model-labels:** Model label improvements to have named models instead ([dc75dbc](https://github.com/postalsys/emailengine/commit/dc75dbc9693d48d7693df71961443607640f55fb))
-   **paging:** Fixed paging links for OAuth2 apps ([d698082](https://github.com/postalsys/emailengine/commit/d6980826a8136d9f8ae612c4be98a8665619accd))
-   **templates:** Allow running template API requests with account tokens ([dd2da5b](https://github.com/postalsys/emailengine/commit/dd2da5bceecca53b579c12fb83c97dbf59f77c55))

## [2.42.0](https://github.com/postalsys/emailengine/compare/v2.41.4...v2.42.0) (2024-05-30)

### Features

-   **gmail-api:** Alpha version of Gmail API support ([f7fd60a](https://github.com/postalsys/emailengine/commit/f7fd60ac3f27f5bdc18c9cc16242dbc1d3a65a93))

### Bug Fixes

-   **ts:** Fixed API schema to pass TypeScript SDK generation ([29493ac](https://github.com/postalsys/emailengine/commit/29493ac88e31b79b771e8e43fc8de758b607977f))

## [2.41.4](https://github.com/postalsys/emailengine/compare/v2.41.3...v2.41.4) (2024-05-15)

### Bug Fixes

-   **env:** Fixed EENGINE_MAX_PAYLOAD_TIMEOUT handling ([feaa0d2](https://github.com/postalsys/emailengine/commit/feaa0d261e4d0de06665600b78af58ed110a89dc))

## [2.41.3](https://github.com/postalsys/emailengine/compare/v2.41.2...v2.41.3) (2024-05-08)

### Bug Fixes

-   **empty-listing:** Treat empty LIST or LSUB response as an error condition ([53e3bc9](https://github.com/postalsys/emailengine/commit/53e3bc926952e7d50ad489b8f779eb49c82afc43))
-   **imapflow:** Bumped ImapFlow to prevent IDLE deadlocks ([869db0a](https://github.com/postalsys/emailengine/commit/869db0ae05a7e10f95e23830eb8e96d4c9ff82af))
-   **lua:** Fixed lua script to calculate total number of matching accounts for a query ([a4284c5](https://github.com/postalsys/emailengine/commit/a4284c53cfc7b157454938fb2cd43c34fa4c25ea))
-   **render:** Updated Render deployment blueprint ([031a457](https://github.com/postalsys/emailengine/commit/031a457f030c938b66c4d95354994548d8ae856f))

## [2.41.2](https://github.com/postalsys/emailengine/compare/v2.41.1...v2.41.2) (2024-04-19)

### Bug Fixes

-   **sync:** send webhooks for old messages during first sync ([5d05986](https://github.com/postalsys/emailengine/commit/5d05986ad2363d8a1a13aea2c965bfc8a11f5b8c))

## [2.41.1](https://github.com/postalsys/emailengine/compare/v2.41.0...v2.41.1) (2024-04-12)

### Bug Fixes

-   **deps:** Bumped dependencies to clean up dependency tree (forgot before previous release) ([6d8ab9a](https://github.com/postalsys/emailengine/commit/6d8ab9af30b69072949d95e5bf5346194743e315))

## [2.41.0](https://github.com/postalsys/emailengine/compare/v2.40.9...v2.41.0) (2024-04-11)

### Features

-   **custom-account-headers:** Allows setting account specific custom webhook headers ([f4c4c8b](https://github.com/postalsys/emailengine/commit/f4c4c8b943d6287dcb537c7781307466de8b73f9))

### Bug Fixes

-   **account-form:** Added support for 'path' in the authentication form ([198ba41](https://github.com/postalsys/emailengine/commit/198ba4162435882b52c7498d3df0ba83b8a4ce4f))
-   **accountPath:** Use an array by default as the path type ([3faa977](https://github.com/postalsys/emailengine/commit/3faa977168070c7e9dcbc3af7794118e0ef7842b))
-   **web-ui:** Do not clear up IMAP settings when enabling/disabling IMAP in the web UI ([037091b](https://github.com/postalsys/emailengine/commit/037091b2731b65dab386eec9cc7474aa2fddd97f))

## [2.40.9](https://github.com/postalsys/emailengine/compare/v2.40.8...v2.40.9) (2024-04-03)

### Bug Fixes

-   **oauth2:** Show access token validity period on account details page ([6cee85f](https://github.com/postalsys/emailengine/commit/6cee85fb6bc87cb647e3fe7fe4379b42a2feb2fe))
-   **oauth2:** Show OAuth2 error on account page if token renewal failed due to invalid grant ([70f7bc8](https://github.com/postalsys/emailengine/commit/70f7bc8c35d17da38d8cb654564411b8940c7ea0))
-   **ui-tweak:** Automatically reconnect an account if log settings are updated via UI ([4d4be15](https://github.com/postalsys/emailengine/commit/4d4be15e8d8562cc05af4ae8a19c308a20218dc4))

## [2.40.8](https://github.com/postalsys/emailengine/compare/v2.40.7...v2.40.8) (2024-03-24)

### Bug Fixes

-   **reconnect:** Force close previous connection if reconnect was requested ([ec0baf1](https://github.com/postalsys/emailengine/commit/ec0baf101f4219891b087f33c8b12cdabb04656c))
-   **smtp:** Do not override From: header in an email from SMTP interface ([69f6c32](https://github.com/postalsys/emailengine/commit/69f6c325278e79e8950e5c4e7efb299e06b0cbd0))

## [2.40.7](https://github.com/postalsys/emailengine/compare/v2.40.6...v2.40.7) (2024-03-20)

### Bug Fixes

-   **gmail-smtp:** Fix failing SMTP connections for Gmail ([c3dd63a](https://github.com/postalsys/emailengine/commit/c3dd63a9df27798dac899932cec309d0b867beeb))

## [2.40.6](https://github.com/postalsys/emailengine/compare/v2.40.5...v2.40.6) (2024-03-20)

### Bug Fixes

-   **account-listing:** Show accounts as initializing if account has not yet been processed after startup ([0e70898](https://github.com/postalsys/emailengine/commit/0e7089899513bfe9c0557a2f6eb24a1ebab8bfe0))
-   **connection:** Do not wait for subconnections when setting up the connection ([d8daff8](https://github.com/postalsys/emailengine/commit/d8daff8f1d7e00eeee71aa0b84276f24371e9456))
-   **oauth2-error:** If OAuth2 app is failing then show an indication about it on the account page ([dd44cd5](https://github.com/postalsys/emailengine/commit/dd44cd5e30ec66cf5340df2c355946f3ebd4b19a))

## [2.40.5](https://github.com/postalsys/emailengine/compare/v2.40.4...v2.40.5) (2024-03-16)

### Bug Fixes

-   **reconnection:** Tweaked reconnection logic on errors ([95067c5](https://github.com/postalsys/emailengine/commit/95067c51cd64d91e1ef86073a8a042982fac24b9))

## [2.40.4](https://github.com/postalsys/emailengine/compare/v2.40.3...v2.40.4) (2024-03-14)

### Bug Fixes

-   **connections:** Added additional logging to detect broken reconnections ([bfe6229](https://github.com/postalsys/emailengine/commit/bfe6229cb135528021e1495640eae2595dd13bd2))

## [2.40.3](https://github.com/postalsys/emailengine/compare/v2.40.2...v2.40.3) (2024-03-08)

### Bug Fixes

-   **fetch:** allow to configure max fetch batch size with an ENV value ([de45851](https://github.com/postalsys/emailengine/commit/de45851c0a629d245a5dd1f7873283e9fd0d7cf3))
-   **fetch:** Allow to set the fetch batch size limit with a cli argument ([f5daf91](https://github.com/postalsys/emailengine/commit/f5daf91e8d46687e40f8844d6cdf68f2fe85e8f6))
-   **fetch:** If fetch fails while syncing, then set a warning flag and try again ([ffcb559](https://github.com/postalsys/emailengine/commit/ffcb559eed622a8d34a92cb1920690190687aca3))
-   **fetch:** use batches when fetching message entries for indexing ([1e83e64](https://github.com/postalsys/emailengine/commit/1e83e644ded8cd9d4a229ce0d1ac46679f8b0250))

## [2.40.2](https://github.com/postalsys/emailengine/compare/v2.40.1...v2.40.2) (2024-03-04)

### Bug Fixes

-   **mime:** Use custom MIME boundary pattern for generated emails ([0e2a110](https://github.com/postalsys/emailengine/commit/0e2a110c6c9731486238428cb053606e889a49e7))
-   **webhooks:** include network routing information in messageSent, messageDeliveryError and messageFailed webhooks ([16bd82d](https://github.com/postalsys/emailengine/commit/16bd82d81d2643f4e721e05f1b943c191619874c))

## [2.40.1](https://github.com/postalsys/emailengine/compare/v2.40.0...v2.40.1) (2024-02-26)

### Bug Fixes

-   **network:** Fixed failing network scan for detecting local IP addresses ([048358d](https://github.com/postalsys/emailengine/commit/048358da34da2d6835c5872d08e5058fd2e138d1))

## [2.40.0](https://github.com/postalsys/emailengine/compare/v2.39.11...v2.40.0) (2024-02-23)

### Features

-   **connections:** If EmailEngine is syncing an account then use a secondary IMAP connection to serve API requests ([965b63c](https://github.com/postalsys/emailengine/commit/965b63c4747c93dd2151749002a0fa91f9996ea4))
-   **path:** Account path argument can take either a path string, or an array of strings to monitor multiple folders instead of just one ([a7c6abc](https://github.com/postalsys/emailengine/commit/a7c6abc146a8631a1b63d62180274b1a372cf598))
-   **submit:** Allow to set proxy url and local address when submitting emails for delivery ([af1d253](https://github.com/postalsys/emailengine/commit/af1d253dc2c194d7af12aa15b711a4fbeb246fe4))

### Bug Fixes

-   **config:** Properly parse time values from EENGINE_MAX_PAYLOAD_TIMEOUT config option ([c3f5ac7](https://github.com/postalsys/emailengine/commit/c3f5ac79e45f7c79281105ef993f2e37a9f1ce53))

## [2.39.11](https://github.com/postalsys/emailengine/compare/v2.39.10...v2.39.11) (2024-02-18)

### Bug Fixes

-   **llm:** LLM processing did not work ([28973d4](https://github.com/postalsys/emailengine/commit/28973d40080e710fb439ed84ff55503c418a3786))

## [2.39.10](https://github.com/postalsys/emailengine/compare/v2.39.9...v2.39.10) (2024-02-12)

### Bug Fixes

-   **message-upload:** improvements regarding empty From header ([45df0fd](https://github.com/postalsys/emailengine/commit/45df0fd830c0dd3690bf367fe344572826c6d96e))

## [2.39.9](https://github.com/postalsys/emailengine/compare/v2.39.8...v2.39.9) (2024-02-03)

### Bug Fixes

-   **build:** fixed broken build ([ae43242](https://github.com/postalsys/emailengine/commit/ae43242ebdc8ee95750cf6c91c7aaebc4ac1ca55))

## [2.39.8](https://github.com/postalsys/emailengine/compare/v2.39.7...v2.39.8) (2024-02-02)

### Bug Fixes

-   **deps:** bumped deps to clear vulnerability notifications ([fbe71ff](https://github.com/postalsys/emailengine/commit/fbe71ffc73338beaced229310afc3f6530547c06))
-   **deps:** bumped imapflow ([c79d160](https://github.com/postalsys/emailengine/commit/c79d1608663133615e518dc1408545648b5a9f06))
-   **document-store:** Added deprecation notice ([1ed38d8](https://github.com/postalsys/emailengine/commit/1ed38d8b22ee57f4e32006df427fadcc60acacaf))
-   **outh2-apps:** Allow to clear display title and description ([f04b115](https://github.com/postalsys/emailengine/commit/f04b115c6b1af8e251b9f20d8bf1547b980c144b))
-   **submit-timeout:** Allow to configure HTTP POST timeout for submit and message upload API endpoints (previous default 10s) ([89f0f01](https://github.com/postalsys/emailengine/commit/89f0f013fe3c0d0028e7832d3d54a62d363251b3))
-   **translations:** Added Japanese translation file for gettext (hosted authentication form) ([4bc743a](https://github.com/postalsys/emailengine/commit/4bc743a5000818fb806793f959495850fc16e2f2))
-   **translations:** Moved all field validation error translations into a separate project (joi-messages) ([5cb0c61](https://github.com/postalsys/emailengine/commit/5cb0c6136f997752d29b155c0bbfc2b6913b0d84))

## [2.39.7](https://github.com/postalsys/emailengine/compare/v2.39.6...v2.39.7) (2024-01-15)

### Bug Fixes

-   **cookies:** do not validate cookies to prevent 'invalid cookie value' error for 3rd party cookies ([a869640](https://github.com/postalsys/emailengine/commit/a8696406c50bfc39495148f3d11679342001fff3))
-   **submit:** allow empty string as address name ([4d6b276](https://github.com/postalsys/emailengine/commit/4d6b276eebe8a603dbc0a2d6f2de86708d08bb14))
-   **webhooks:** fixed text.html field for messageNew if notifyWebSafeHtml is true ([47e64a8](https://github.com/postalsys/emailengine/commit/47e64a8ef0bd4e7a2f6c75b563b7cfffe175379c))

## [2.39.6](https://github.com/postalsys/emailengine/compare/v2.39.5...v2.39.6) (2024-01-03)

### Bug Fixes

-   **redis-locks:** Bumped ioredfour to fix issue with Redis servers where WITH is disabled ([b53007a](https://github.com/postalsys/emailengine/commit/b53007a450a5cc39389edcfaa9601a3f57232ad1))

## [2.39.5](https://github.com/postalsys/emailengine/compare/v2.39.4...v2.39.5) (2024-01-03)

### Bug Fixes

-   **api:** Added quota information to account info response ([6341400](https://github.com/postalsys/emailengine/commit/63414007a1437e0b642e6402d92bd0f00c898232))
-   **api:** enforce numbers as integers in the validation schema ([84298c8](https://github.com/postalsys/emailengine/commit/84298c8a060c9ff6200060a78056e5536aeb8c66))
-   **documentstore:** prevent throwing an error when fetching an empty email ([c3dc0b6](https://github.com/postalsys/emailengine/commit/c3dc0b6bc43b8dee2c2936d228315985155a1797))
-   **settings:** Ensure setting service url and timezone if not set ([27faad9](https://github.com/postalsys/emailengine/commit/27faad98ce7861f8fc6b03ade906d357f79eb697))

## [2.39.4](https://github.com/postalsys/emailengine/compare/v2.39.3...v2.39.4) (2023-12-15)

### Bug Fixes

-   **redis:** Show a warning on the dashboard if Amazon ElastiCache is used as the database ([814e724](https://github.com/postalsys/emailengine/commit/814e724a0b8613c2a53366507033547d9fba9b8f))
-   **redis:** Show warning when using Redis Cluster ([17b599e](https://github.com/postalsys/emailengine/commit/17b599eafcb3beed5a539abf868ef499e848e9db))

## [2.39.3](https://github.com/postalsys/emailengine/compare/v2.39.2...v2.39.3) (2023-12-12)

### Bug Fixes

-   **llm:** Do not try to process an email without message contents ([9e4cbdc](https://github.com/postalsys/emailengine/commit/9e4cbdc692f4b666345442460d15c1250f2b7095))
-   **oauth2-outlook:** Enforce account selection when authenticating OAuth2 connections for MS365 ([1c6b56a](https://github.com/postalsys/emailengine/commit/1c6b56a67f0820e78098abfb526f7d71e0023021))
-   **redis:** Fixed Redis stats collections when using Upstash Redis ([9730123](https://github.com/postalsys/emailengine/commit/97301239aa1db2c4cd04b3dcac2cdf6b69598681))

## [2.39.2](https://github.com/postalsys/emailengine/compare/v2.39.1...v2.39.2) (2023-11-29)

### Bug Fixes

-   **llm:** Allow to load available models from the OpenAI models API endpoint ([00fffda](https://github.com/postalsys/emailengine/commit/00fffda98b6728cff23c46b529d94dbed09d2ae3))
-   **metrics:** added Redis Latency metric ([aba2dab](https://github.com/postalsys/emailengine/commit/aba2dab0001d6036fa503910315ee08f04a64f50))
-   **redis-latency:** show latency for Redis commands in the dashboard ([65fa362](https://github.com/postalsys/emailengine/commit/65fa362c4253c9ba22aac894bc6e0b68a81a727a))

## [2.39.1](https://github.com/postalsys/emailengine/compare/v2.39.0...v2.39.1) (2023-11-24)

### Bug Fixes

-   **error-messages:** Form validation errors did not show limit number properly ([d939955](https://github.com/postalsys/emailengine/commit/d9399550236b483b024f611577426d56fbc400aa))
-   **imap:** Allow to define IMAP TCP socket timeout with the EENGINE_IMAP_SOCKET_TIMEOUT env value ([4d29d20](https://github.com/postalsys/emailengine/commit/4d29d20b363b6fee04fa0a35f395a9084ca7cf6c))
-   **smtp-verify:** Fixed accessToken usage for verifying SMTP account settings ([0cd38f2](https://github.com/postalsys/emailengine/commit/0cd38f26f1bbf1521a8b5fd7e861ce97e88bdc16))

## [2.39.0](https://github.com/postalsys/emailengine/compare/v2.38.1...v2.39.0) (2023-11-06)

### Features

-   **api:** Allow to override EENGINE_TIMEOUT value for a single API request ([9a3aec3](https://github.com/postalsys/emailengine/commit/9a3aec3f50c2a6bc277021053704493cfdb6a983))
-   **tls:** Allow to set TLS settings for API server ([67f5aa3](https://github.com/postalsys/emailengine/commit/67f5aa3c63f9a54356976d7ab8332fb1e401c7bc))

### Bug Fixes

-   **authentication-form:** Prevent re-using the same authentication form url ([b13d9b9](https://github.com/postalsys/emailengine/commit/b13d9b9851c30bcde52ec96d604700791d99dc95))
-   **cors:** Do not override default CORS headers ([e5a2f50](https://github.com/postalsys/emailengine/commit/e5a2f50547dd00fb2659ca8aa02e5f8a5f5cfdea))
-   **file-ui:** Do not use a 'file' input element, instead use a button that triggers file select dialog to select files ([14a9fe3](https://github.com/postalsys/emailengine/commit/14a9fe30d482678d5912b36a48986754bd232eac))
-   **ui:** small tweaks ([8cb6034](https://github.com/postalsys/emailengine/commit/8cb60346068f1015d67a155ddb0e7b5145803310))

## [2.38.1](https://github.com/postalsys/emailengine/compare/v2.38.0...v2.38.1) (2023-10-27)

### Bug Fixes

-   **docker:** fixed docker autobuild ([ae0f3ab](https://github.com/postalsys/emailengine/commit/ae0f3abb384034208d967a4c1a6680ec243d1126))

## [2.38.0](https://github.com/postalsys/emailengine/compare/v2.37.7...v2.38.0) (2023-10-26)

### Features

-   **oauth:** Allow to disable base OAuth2 scopes like SMTP.Send ([ef89d83](https://github.com/postalsys/emailengine/commit/ef89d83643b9a7c6d03aba04e75afcbcf0b611e9))
-   **openai:** Allow to set custom models using the API (not in UI) ([858f48b](https://github.com/postalsys/emailengine/commit/858f48b8a69c850e8d491fc6d585243ae1c183ac))
-   **openai:** Allow to specify custom API url for OpenAI API requests ([047647d](https://github.com/postalsys/emailengine/commit/047647df95c17f5cfbc11647eedd560e3659931e))
-   **tls:** Allow to ignore IMAP/SMTP TLS certificate errors by default using the ignoreMailCertErrors setting ([cba8ffe](https://github.com/postalsys/emailengine/commit/cba8ffeca489321e3c9736039a325c8acfb05de2))

### Bug Fixes

-   **special-use-flags:** Added support for user-specified Archive special use tag ([a107f23](https://github.com/postalsys/emailengine/commit/a107f233d9f25800c08dd3e371b7cd6c95fe1a1b))
-   **throttling:** Retry throttled FETCH commands a few times before giving up ([c3d259a](https://github.com/postalsys/emailengine/commit/c3d259a0bc94cd3b84ffd6e77b77d1bc098ff64c))

## [2.37.7](https://github.com/postalsys/emailengine/compare/v2.37.6...v2.37.7) (2023-10-20)

### Bug Fixes

-   **chat:** use topic instead of question for the filtering embedding ([3acebc3](https://github.com/postalsys/emailengine/commit/3acebc37dd5e5c0d25dab386354f1ec1bf78d244))
-   **initialization:** Start all IMAP worker threads before assigning accounts ([9b4c3fc](https://github.com/postalsys/emailengine/commit/9b4c3fc48b00a3bcfeade592cc36b8144038dad8))
-   **stats:** added missing counters for messageNew/messageDeleted ([3f9f4cd](https://github.com/postalsys/emailengine/commit/3f9f4cda6aa1896f7c30b786ab7909ea274fcb69))

## [2.37.6](https://github.com/postalsys/emailengine/compare/v2.37.5...v2.37.6) (2023-10-17)

### Bug Fixes

-   **about:** Added a dedicated page for license and legal information ([077b38f](https://github.com/postalsys/emailengine/commit/077b38f4edfe711109fab809327adcaa55204b40))
-   **accountCounters:** added counters object that contains cumulative counter of all account specific triggered events ([67613a3](https://github.com/postalsys/emailengine/commit/67613a3bb5e69dc06304a6a5441b997e52e7b5f1))
-   **documentstore:** do not report missing email as an error ([58130c7](https://github.com/postalsys/emailengine/commit/58130c786b21fcb75ce48e557c5b8f19edbb7581))
-   **license:** added a section to the license about source code usage ([a923d3b](https://github.com/postalsys/emailengine/commit/a923d3bba28bf3831aa79face17c75ad65ace002))

## [2.37.5](https://github.com/postalsys/emailengine/compare/v2.37.4...v2.37.5) (2023-10-11)

### Bug Fixes

-   **chat:** Fixed chat feature support for older Redis versions ([86538ba](https://github.com/postalsys/emailengine/commit/86538baff7037598788e38b68495f4d3958d52bc))
-   **default_conf:** Ensure default config values for notifyText, notifyTextSize, and enableApiProxy ([b7b4d9c](https://github.com/postalsys/emailengine/commit/b7b4d9c150ffabd533e5015b2e4aee4f26160b30))
-   **license:** allow selecting license key from a file instead of copying ([d813e35](https://github.com/postalsys/emailengine/commit/d813e356a20879c7e9c69db9f8e21e5648be2a6d))

## [2.37.4](https://github.com/postalsys/emailengine/compare/v2.37.3...v2.37.4) (2023-10-05)

### Bug Fixes

-   **docker:** fixed docker tags, added missing v prefix to version tags ([481bf5c](https://github.com/postalsys/emailengine/commit/481bf5c6e80b6cb48a32f460dd65ee887bc79847))

## [2.37.3](https://github.com/postalsys/emailengine/compare/v2.37.2...v2.37.3) (2023-10-05)

### Bug Fixes

-   **docker:** fixed docker tagged release process ([f23cde0](https://github.com/postalsys/emailengine/commit/f23cde0e851fc3e43893383d65929dc3f03b2991))

## [2.37.2](https://github.com/postalsys/emailengine/compare/v2.37.1...v2.37.2) (2023-10-03)

### Bug Fixes

-   **chat:** Bumped dependency to better parse output from OpenAI API ([0250da8](https://github.com/postalsys/emailengine/commit/0250da8c37b1ced730dc9e42a611e1d6bdc0a582))

## [2.37.1](https://github.com/postalsys/emailengine/compare/v2.37.0...v2.37.1) (2023-10-02)

### Bug Fixes

-   **chat:** Added 'try it' button to 'chat with emails' config page ([0f23c39](https://github.com/postalsys/emailengine/commit/0f23c390887b6d554b2ed90a437c30f2c6530aac))
-   **chat:** Improved 'chat with emails' response quality by sorting and filtering embeddings vectors ([de429d6](https://github.com/postalsys/emailengine/commit/de429d6f8f1cffdbce0e48dce4f716cdf83f93bf))

## [2.37.0](https://github.com/postalsys/emailengine/compare/v2.36.1...v2.37.0) (2023-09-29)

### Features

-   **secrets:** removed deprecated vault support ([8ab9d60](https://github.com/postalsys/emailengine/commit/8ab9d60df58b5d258dcf459a1928f285b02eea62))

### Bug Fixes

-   **chat:** Use separate settings page for 'chat with emails' feature ([c66e3ba](https://github.com/postalsys/emailengine/commit/c66e3ba8234390ccc5cf800cee29f8e4ab0b56d2))
-   **deploy:** Build packages with Node 20 ([a394cf2](https://github.com/postalsys/emailengine/commit/a394cf2d487ba95a1906b964a630d524cf57f16c))
-   **package-lock:** Do not delete package lock. Use 'npm ci' to install dependencies ([752be23](https://github.com/postalsys/emailengine/commit/752be230bf510c68c1551e0f852b47a7d1f1dedb))

## [2.36.1](https://github.com/postalsys/emailengine/compare/v2.36.0...v2.36.1) (2023-09-20)

### Bug Fixes

-   **deploy:** keep package-lock.json ([ec311e3](https://github.com/postalsys/emailengine/commit/ec311e34834266d6a1db382dc044a13828a1eca4))

## [2.36.0](https://github.com/postalsys/emailengine/compare/v2.35.0...v2.36.0) (2023-09-20)

### Features

-   **ai:** Allow using embeddings generation without prompting ([b59e702](https://github.com/postalsys/emailengine/commit/b59e702b31a869e810178518b9549871b7988b19))

### Bug Fixes

-   **ai:** Added support for gpt-3.5-turbo-instruct ([bf75c5a](https://github.com/postalsys/emailengine/commit/bf75c5ab4077ffe5e0b4a92e009d4ee6500c50b8))
-   **ai:** Do not store generated embeddings in the document store ([9638480](https://github.com/postalsys/emailengine/commit/9638480662581ed09bf7fa0ebecbb64461224413))
-   **deploy:** Added tests runner ([b382569](https://github.com/postalsys/emailengine/commit/b382569604b74f312ab7fadafdcba65d76f0c1ec))
-   **deploy:** Automated release management ([8e2bd88](https://github.com/postalsys/emailengine/commit/8e2bd88d305a8502102986528b346c96f35f4c06))
