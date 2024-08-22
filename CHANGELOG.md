# Changelog

## [2.45.0](https://github.com/postalsys/emailengine/compare/v2.44.1...v2.45.0) (2024-08-22)


### Features

* Require minimally Node v18 (previously v16) ([dc8282e](https://github.com/postalsys/emailengine/commit/dc8282e09033d0554301c9c824e8cb74c79bdb19))
* **templates:** Removed MJML support ([b976e53](https://github.com/postalsys/emailengine/commit/b976e53ff2e9eeb6591b16ac983e87f85ff70c76))


### Bug Fixes

* **deps:** Bumped dependencies to fix web safe HTML ([7b20aff](https://github.com/postalsys/emailengine/commit/7b20affbeaa41377ac22accbbc39f2dddfc10961))
* Use no-referrer policy for all _blank links ([eef5757](https://github.com/postalsys/emailengine/commit/eef5757579667e9950aefce11d4cd5e68e1c2421))

## [2.44.1](https://github.com/postalsys/emailengine/compare/v2.44.0...v2.44.1) (2024-08-15)


### Bug Fixes

* **oauth2:** Fixed Gmail API OAuth2 schema ([205f34e](https://github.com/postalsys/emailengine/commit/205f34e1c89eaf003d027aa0664023af0029c53e))

## [2.44.0](https://github.com/postalsys/emailengine/compare/v2.43.3...v2.44.0) (2024-08-15)


### Features

* **ms-graph-api:** MS Graph API support ([#431](https://github.com/postalsys/emailengine/issues/431)) ([5e10dd3](https://github.com/postalsys/emailengine/commit/5e10dd3528c8c5ca6898f2ed0800f0d168fb8b33))


### Bug Fixes

* **app-password:** Add T-Online to providers needing an app password ([#430](https://github.com/postalsys/emailengine/issues/430)) ([823939b](https://github.com/postalsys/emailengine/commit/823939b1d5e6934876537597ea52b52b4f12ab59))
* **oauth-tokens:** Fix renewal check for access tokens ([f687aa1](https://github.com/postalsys/emailengine/commit/f687aa11752a2981a1237cc84cca1d26f24d1f49))
* **outlook-oauth:** Show 'supported account types' as a selectable list instead of a text field input ([fe62e5b](https://github.com/postalsys/emailengine/commit/fe62e5b293307d42c6e8e1c200911d4eff4e26de))

## [2.43.3](https://github.com/postalsys/emailengine/compare/v2.43.2...v2.43.3) (2024-08-01)


### Bug Fixes

* **cors:** Added missing OPTIONS handler for CORS ([205480d](https://github.com/postalsys/emailengine/commit/205480d4c150f35aa14edaa918b7635774eface3))

## [2.43.2](https://github.com/postalsys/emailengine/compare/v2.43.1...v2.43.2) (2024-07-29)


### Bug Fixes

* **reconnect:** Allow reconnecting paused accounts ([b8e212f](https://github.com/postalsys/emailengine/commit/b8e212f512ad007d3fa3c2678d8dfdbf8155c0ca))

## [2.43.1](https://github.com/postalsys/emailengine/compare/v2.43.0...v2.43.1) (2024-07-21)


### Bug Fixes

* **api-docs:** Updated information about total/pages/nextPageCursor ([cd12547](https://github.com/postalsys/emailengine/commit/cd12547096da14b2407156745bb86326134db177))
* **cli:** Added command 'export' to retrieve raw account data with credentials ([9932801](https://github.com/postalsys/emailengine/commit/99328017918cf978ceadc4cc87f64e9b924d4ee6))
* **gmail-api:** Fixed webhook notifications for authenticationSuccess and authenticationError ([2c3d63a](https://github.com/postalsys/emailengine/commit/2c3d63a5f62ee3fdfe3245c1e5128e908a679e82))
* **gmail-api:** Log API requests to user log ([f00f864](https://github.com/postalsys/emailengine/commit/f00f86439af8484c7d55aa3b0e386e09f209dce0))
* **oauth2:** Fixed broken extra scopes handling ([9185359](https://github.com/postalsys/emailengine/commit/91853599c238c79a326886107e8f62b23dd26973))

## [2.43.0](https://github.com/postalsys/emailengine/compare/v2.42.0...v2.43.0) (2024-07-08)


### Features

* **gmail-api:** Gmail API Support ([#421](https://github.com/postalsys/emailengine/issues/421)) ([91b3cad](https://github.com/postalsys/emailengine/commit/91b3cad4537e8b5e2c2b9faad54f87c5d6997d15))


### Bug Fixes

* **api:** Added support for paging cursors ([d3f7685](https://github.com/postalsys/emailengine/commit/d3f76857a1d139aa15646fe96dd0ef5d8a791fbe))
* **api:** Do not allow to proxy connections for accounts with API scopes ([9498fa9](https://github.com/postalsys/emailengine/commit/9498fa9efbf0c6f341239e77514de9903e6195ee))
* Fix exception when Document Store is disabled but there are embeddings stored ([6d18a48](https://github.com/postalsys/emailengine/commit/6d18a48e146a2aceb7fcf94dad21ce6959188bc4))
* **font-loading:** Use a locally cached font instead of loading from Google FOnts ([4e53929](https://github.com/postalsys/emailengine/commit/4e539296d4f8bac3d4772fdcf1941611d1289846))
* **model-labels:** Model label improvements to have named models instead ([dc75dbc](https://github.com/postalsys/emailengine/commit/dc75dbc9693d48d7693df71961443607640f55fb))
* **paging:** Fixed paging links for OAuth2 apps ([d698082](https://github.com/postalsys/emailengine/commit/d6980826a8136d9f8ae612c4be98a8665619accd))
* **templates:** Allow running template API requests with account tokens ([dd2da5b](https://github.com/postalsys/emailengine/commit/dd2da5bceecca53b579c12fb83c97dbf59f77c55))

## [2.42.0](https://github.com/postalsys/emailengine/compare/v2.41.4...v2.42.0) (2024-05-30)


### Features

* **gmail-api:** Alpha version of Gmail API support ([f7fd60a](https://github.com/postalsys/emailengine/commit/f7fd60ac3f27f5bdc18c9cc16242dbc1d3a65a93))


### Bug Fixes

* **ts:** Fixed API schema to pass TyepScript SDK generation ([29493ac](https://github.com/postalsys/emailengine/commit/29493ac88e31b79b771e8e43fc8de758b607977f))

## [2.41.4](https://github.com/postalsys/emailengine/compare/v2.41.3...v2.41.4) (2024-05-15)


### Bug Fixes

* **env:** Fixed EENGINE_MAX_PAYLOAD_TIMEOUT handling ([feaa0d2](https://github.com/postalsys/emailengine/commit/feaa0d261e4d0de06665600b78af58ed110a89dc))

## [2.41.3](https://github.com/postalsys/emailengine/compare/v2.41.2...v2.41.3) (2024-05-08)


### Bug Fixes

* **empty-listing:** Treat empty LIST or LSUB response as an error condition ([53e3bc9](https://github.com/postalsys/emailengine/commit/53e3bc926952e7d50ad489b8f779eb49c82afc43))
* **imapflow:** Bumped ImapFlow to prevent IDLE deadlocks ([869db0a](https://github.com/postalsys/emailengine/commit/869db0ae05a7e10f95e23830eb8e96d4c9ff82af))
* **lua:** Fixed lua script to calculate total number of matching accounts for a query ([a4284c5](https://github.com/postalsys/emailengine/commit/a4284c53cfc7b157454938fb2cd43c34fa4c25ea))
* **render:** Updated Render deployment blueprint ([031a457](https://github.com/postalsys/emailengine/commit/031a457f030c938b66c4d95354994548d8ae856f))

## [2.41.2](https://github.com/postalsys/emailengine/compare/v2.41.1...v2.41.2) (2024-04-19)


### Bug Fixes

* **sync:** send webhooks for old messages during first sync ([5d05986](https://github.com/postalsys/emailengine/commit/5d05986ad2363d8a1a13aea2c965bfc8a11f5b8c))

## [2.41.1](https://github.com/postalsys/emailengine/compare/v2.41.0...v2.41.1) (2024-04-12)


### Bug Fixes

* **deps:** Bumped dependencies to clean up dependency tree (forgot before previous release) ([6d8ab9a](https://github.com/postalsys/emailengine/commit/6d8ab9af30b69072949d95e5bf5346194743e315))

## [2.41.0](https://github.com/postalsys/emailengine/compare/v2.40.9...v2.41.0) (2024-04-11)


### Features

* **custom-account-headers:** Allos setting account specific custom webhook headers ([f4c4c8b](https://github.com/postalsys/emailengine/commit/f4c4c8b943d6287dcb537c7781307466de8b73f9))


### Bug Fixes

* **account-form:** Added support for 'path' in the authentication form ([198ba41](https://github.com/postalsys/emailengine/commit/198ba4162435882b52c7498d3df0ba83b8a4ce4f))
* **accountPath:** Use an array by default as the path type ([3faa977](https://github.com/postalsys/emailengine/commit/3faa977168070c7e9dcbc3af7794118e0ef7842b))
* **web-ui:** Do not clear up IMAP settings when enabling/disabling IMAP in the web UI ([037091b](https://github.com/postalsys/emailengine/commit/037091b2731b65dab386eec9cc7474aa2fddd97f))

## [2.40.9](https://github.com/postalsys/emailengine/compare/v2.40.8...v2.40.9) (2024-04-03)


### Bug Fixes

* **oauth2:** Show access token validity period on account details page ([6cee85f](https://github.com/postalsys/emailengine/commit/6cee85fb6bc87cb647e3fe7fe4379b42a2feb2fe))
* **oauth2:** Show OAuth2 error on account page if token renewal failed due to invalid grant ([70f7bc8](https://github.com/postalsys/emailengine/commit/70f7bc8c35d17da38d8cb654564411b8940c7ea0))
* **ui-tweak:** Automatically reconnect an account if log settings are updated via UI ([4d4be15](https://github.com/postalsys/emailengine/commit/4d4be15e8d8562cc05af4ae8a19c308a20218dc4))

## [2.40.8](https://github.com/postalsys/emailengine/compare/v2.40.7...v2.40.8) (2024-03-24)


### Bug Fixes

* **reconnect:** Force close previous connection if reconnect was requested ([ec0baf1](https://github.com/postalsys/emailengine/commit/ec0baf101f4219891b087f33c8b12cdabb04656c))
* **smtp:** Do not override From: header in an email from SMTP interface ([69f6c32](https://github.com/postalsys/emailengine/commit/69f6c325278e79e8950e5c4e7efb299e06b0cbd0))

## [2.40.7](https://github.com/postalsys/emailengine/compare/v2.40.6...v2.40.7) (2024-03-20)


### Bug Fixes

* **gmail-smtp:** Fix failing SMTP connections for Gmail ([c3dd63a](https://github.com/postalsys/emailengine/commit/c3dd63a9df27798dac899932cec309d0b867beeb))

## [2.40.6](https://github.com/postalsys/emailengine/compare/v2.40.5...v2.40.6) (2024-03-20)


### Bug Fixes

* **account-listing:** Show accounts as initializing if account has not yet been processed after startup ([0e70898](https://github.com/postalsys/emailengine/commit/0e7089899513bfe9c0557a2f6eb24a1ebab8bfe0))
* **connection:** Do not wait for subconnections when setting up the connection ([d8daff8](https://github.com/postalsys/emailengine/commit/d8daff8f1d7e00eeee71aa0b84276f24371e9456))
* **oauth2-error:** If OAuth2 app is failing then show an indication about it on the account page ([dd44cd5](https://github.com/postalsys/emailengine/commit/dd44cd5e30ec66cf5340df2c355946f3ebd4b19a))

## [2.40.5](https://github.com/postalsys/emailengine/compare/v2.40.4...v2.40.5) (2024-03-16)


### Bug Fixes

* **reconnection:** Tweaked reconnection logic on errors ([95067c5](https://github.com/postalsys/emailengine/commit/95067c51cd64d91e1ef86073a8a042982fac24b9))

## [2.40.4](https://github.com/postalsys/emailengine/compare/v2.40.3...v2.40.4) (2024-03-14)


### Bug Fixes

* **connections:** Added additional logging to detect broken reconnections ([bfe6229](https://github.com/postalsys/emailengine/commit/bfe6229cb135528021e1495640eae2595dd13bd2))

## [2.40.3](https://github.com/postalsys/emailengine/compare/v2.40.2...v2.40.3) (2024-03-08)


### Bug Fixes

* **fetch:** allow to configure max fetch batch size with an ENV value ([de45851](https://github.com/postalsys/emailengine/commit/de45851c0a629d245a5dd1f7873283e9fd0d7cf3))
* **fetch:** Allow to set the fetch batch size limit with a cli argument ([f5daf91](https://github.com/postalsys/emailengine/commit/f5daf91e8d46687e40f8844d6cdf68f2fe85e8f6))
* **fetch:** If fetch fails while syncing, then set a warning flag and try again ([ffcb559](https://github.com/postalsys/emailengine/commit/ffcb559eed622a8d34a92cb1920690190687aca3))
* **fetch:** use batches when fetching message entries for indexing ([1e83e64](https://github.com/postalsys/emailengine/commit/1e83e644ded8cd9d4a229ce0d1ac46679f8b0250))

## [2.40.2](https://github.com/postalsys/emailengine/compare/v2.40.1...v2.40.2) (2024-03-04)


### Bug Fixes

* **mime:** Use custom MIME boundary pattern for generated emails ([0e2a110](https://github.com/postalsys/emailengine/commit/0e2a110c6c9731486238428cb053606e889a49e7))
* **webhooks:** include network routing information in messageSent, messageDeliveryError and messageFailed webhooks ([16bd82d](https://github.com/postalsys/emailengine/commit/16bd82d81d2643f4e721e05f1b943c191619874c))

## [2.40.1](https://github.com/postalsys/emailengine/compare/v2.40.0...v2.40.1) (2024-02-26)


### Bug Fixes

* **network:** Fixed failing network scan for detecting local IP addresses ([048358d](https://github.com/postalsys/emailengine/commit/048358da34da2d6835c5872d08e5058fd2e138d1))

## [2.40.0](https://github.com/postalsys/emailengine/compare/v2.39.11...v2.40.0) (2024-02-23)


### Features

* **connections:** If EmailEngine is syncing an account then use a secondary IMAP connection to serve API requests ([965b63c](https://github.com/postalsys/emailengine/commit/965b63c4747c93dd2151749002a0fa91f9996ea4))
* **path:** Account path argument can take either a path string, or an array of strings to monitor multiple folders instead of just one ([a7c6abc](https://github.com/postalsys/emailengine/commit/a7c6abc146a8631a1b63d62180274b1a372cf598))
* **submit:** Allow to set proxy url and local address when submitting emails for delivery ([af1d253](https://github.com/postalsys/emailengine/commit/af1d253dc2c194d7af12aa15b711a4fbeb246fe4))


### Bug Fixes

* **config:** Properly parse time values from EENGINE_MAX_PAYLOAD_TIMEOUT config option ([c3f5ac7](https://github.com/postalsys/emailengine/commit/c3f5ac79e45f7c79281105ef993f2e37a9f1ce53))

## [2.39.11](https://github.com/postalsys/emailengine/compare/v2.39.10...v2.39.11) (2024-02-18)


### Bug Fixes

* **llm:** LLM processing did not work ([28973d4](https://github.com/postalsys/emailengine/commit/28973d40080e710fb439ed84ff55503c418a3786))

## [2.39.10](https://github.com/postalsys/emailengine/compare/v2.39.9...v2.39.10) (2024-02-12)


### Bug Fixes

* **message-upload:** improvements regarding empty From header ([45df0fd](https://github.com/postalsys/emailengine/commit/45df0fd830c0dd3690bf367fe344572826c6d96e))

## [2.39.9](https://github.com/postalsys/emailengine/compare/v2.39.8...v2.39.9) (2024-02-03)


### Bug Fixes

* **build:** fixed broken build ([ae43242](https://github.com/postalsys/emailengine/commit/ae43242ebdc8ee95750cf6c91c7aaebc4ac1ca55))

## [2.39.8](https://github.com/postalsys/emailengine/compare/v2.39.7...v2.39.8) (2024-02-02)


### Bug Fixes

* **deps:** bumped deps to clear vulnerability notifications ([fbe71ff](https://github.com/postalsys/emailengine/commit/fbe71ffc73338beaced229310afc3f6530547c06))
* **deps:** bumped imapflow ([c79d160](https://github.com/postalsys/emailengine/commit/c79d1608663133615e518dc1408545648b5a9f06))
* **document-store:** Added deprecation notice ([1ed38d8](https://github.com/postalsys/emailengine/commit/1ed38d8b22ee57f4e32006df427fadcc60acacaf))
* **outh2-apps:** Allow to clear display title and description ([f04b115](https://github.com/postalsys/emailengine/commit/f04b115c6b1af8e251b9f20d8bf1547b980c144b))
* **submit-timeout:** Allow to configure HTTP POST timeout for submit and message upload API endpoints (previous default 10s) ([89f0f01](https://github.com/postalsys/emailengine/commit/89f0f013fe3c0d0028e7832d3d54a62d363251b3))
* **translations:** Added Japanese translation file for gettext (hosted authentication form) ([4bc743a](https://github.com/postalsys/emailengine/commit/4bc743a5000818fb806793f959495850fc16e2f2))
* **translations:** Moved all field validation error translations into a separate project (joi-messages) ([5cb0c61](https://github.com/postalsys/emailengine/commit/5cb0c6136f997752d29b155c0bbfc2b6913b0d84))

## [2.39.7](https://github.com/postalsys/emailengine/compare/v2.39.6...v2.39.7) (2024-01-15)


### Bug Fixes

* **cookies:** do not validate cookies to prevent 'invalid cookie value' error for 3rd party cookies ([a869640](https://github.com/postalsys/emailengine/commit/a8696406c50bfc39495148f3d11679342001fff3))
* **submit:** allow empty string as address name ([4d6b276](https://github.com/postalsys/emailengine/commit/4d6b276eebe8a603dbc0a2d6f2de86708d08bb14))
* **webhooks:** fixed text.html field for messageNew if notifyWebSafeHtml is true ([47e64a8](https://github.com/postalsys/emailengine/commit/47e64a8ef0bd4e7a2f6c75b563b7cfffe175379c))

## [2.39.6](https://github.com/postalsys/emailengine/compare/v2.39.5...v2.39.6) (2024-01-03)


### Bug Fixes

* **redis-locks:** Bumped ioredfour to fix issue with Redis servers where WITH is disabled ([b53007a](https://github.com/postalsys/emailengine/commit/b53007a450a5cc39389edcfaa9601a3f57232ad1))

## [2.39.5](https://github.com/postalsys/emailengine/compare/v2.39.4...v2.39.5) (2024-01-03)


### Bug Fixes

* **api:** Added quota information to account info response ([6341400](https://github.com/postalsys/emailengine/commit/63414007a1437e0b642e6402d92bd0f00c898232))
* **api:** enforce numbers as integers in the validation schema ([84298c8](https://github.com/postalsys/emailengine/commit/84298c8a060c9ff6200060a78056e5536aeb8c66))
* **documentstore:** prevent throwing an error when fetching an empty email ([c3dc0b6](https://github.com/postalsys/emailengine/commit/c3dc0b6bc43b8dee2c2936d228315985155a1797))
* **settings:** Ensure setting service url and timezone if not set ([27faad9](https://github.com/postalsys/emailengine/commit/27faad98ce7861f8fc6b03ade906d357f79eb697))

## [2.39.4](https://github.com/postalsys/emailengine/compare/v2.39.3...v2.39.4) (2023-12-15)


### Bug Fixes

* **redis:** Show a warning on the dashboard if Amazon ElastiCache is used as the database ([814e724](https://github.com/postalsys/emailengine/commit/814e724a0b8613c2a53366507033547d9fba9b8f))
* **redis:** Show warning when using Redis Cluster ([17b599e](https://github.com/postalsys/emailengine/commit/17b599eafcb3beed5a539abf868ef499e848e9db))

## [2.39.3](https://github.com/postalsys/emailengine/compare/v2.39.2...v2.39.3) (2023-12-12)


### Bug Fixes

* **llm:** Do not try to process an email without message contents ([9e4cbdc](https://github.com/postalsys/emailengine/commit/9e4cbdc692f4b666345442460d15c1250f2b7095))
* **oauth2-outlook:** Enforce account selection when authenticating OAuth2 connections for MS365 ([1c6b56a](https://github.com/postalsys/emailengine/commit/1c6b56a67f0820e78098abfb526f7d71e0023021))
* **redis:** Fixed Redis stats collections when using Upstash Redis ([9730123](https://github.com/postalsys/emailengine/commit/97301239aa1db2c4cd04b3dcac2cdf6b69598681))

## [2.39.2](https://github.com/postalsys/emailengine/compare/v2.39.1...v2.39.2) (2023-11-29)


### Bug Fixes

* **llm:** Allow to load available models from the OpenAI models API endpoint ([00fffda](https://github.com/postalsys/emailengine/commit/00fffda98b6728cff23c46b529d94dbed09d2ae3))
* **metrics:** added Redis Latency metric ([aba2dab](https://github.com/postalsys/emailengine/commit/aba2dab0001d6036fa503910315ee08f04a64f50))
* **redis-latency:** show latency for Redis commands in the dashboard ([65fa362](https://github.com/postalsys/emailengine/commit/65fa362c4253c9ba22aac894bc6e0b68a81a727a))

## [2.39.1](https://github.com/postalsys/emailengine/compare/v2.39.0...v2.39.1) (2023-11-24)


### Bug Fixes

* **error-messages:** Form validation errors did not show limit number properly ([d939955](https://github.com/postalsys/emailengine/commit/d9399550236b483b024f611577426d56fbc400aa))
* **imap:** Allow to define IMAP TCP socket timeout with the EENGINE_IMAP_SOCKET_TIMEOUT env value ([4d29d20](https://github.com/postalsys/emailengine/commit/4d29d20b363b6fee04fa0a35f395a9084ca7cf6c))
* **smtp-verify:** Fied accessToken usage for verifying SMTP account settings ([0cd38f2](https://github.com/postalsys/emailengine/commit/0cd38f26f1bbf1521a8b5fd7e861ce97e88bdc16))

## [2.39.0](https://github.com/postalsys/emailengine/compare/v2.38.1...v2.39.0) (2023-11-06)


### Features

* **api:** Allow to override EENGINE_TIMEOUT value for a single API request ([9a3aec3](https://github.com/postalsys/emailengine/commit/9a3aec3f50c2a6bc277021053704493cfdb6a983))
* **tls:** Allow to set TLS settings for API server ([67f5aa3](https://github.com/postalsys/emailengine/commit/67f5aa3c63f9a54356976d7ab8332fb1e401c7bc))


### Bug Fixes

* **authentication-form:** Prevent re-using the same authentication form url ([b13d9b9](https://github.com/postalsys/emailengine/commit/b13d9b9851c30bcde52ec96d604700791d99dc95))
* **cors:** Do not override default CORS headers ([e5a2f50](https://github.com/postalsys/emailengine/commit/e5a2f50547dd00fb2659ca8aa02e5f8a5f5cfdea))
* **file-ui:** Do not use a 'file' input element, instead use a button that triggers file select dialog to select files ([14a9fe3](https://github.com/postalsys/emailengine/commit/14a9fe30d482678d5912b36a48986754bd232eac))
* **ui:** small tweaks ([8cb6034](https://github.com/postalsys/emailengine/commit/8cb60346068f1015d67a155ddb0e7b5145803310))

## [2.38.1](https://github.com/postalsys/emailengine/compare/v2.38.0...v2.38.1) (2023-10-27)


### Bug Fixes

* **docker:** fixed docker autobuild ([ae0f3ab](https://github.com/postalsys/emailengine/commit/ae0f3abb384034208d967a4c1a6680ec243d1126))

## [2.38.0](https://github.com/postalsys/emailengine/compare/v2.37.7...v2.38.0) (2023-10-26)


### Features

* **oauth:** Allow to disable base OAuth2 scopes like SMTP.Send ([ef89d83](https://github.com/postalsys/emailengine/commit/ef89d83643b9a7c6d03aba04e75afcbcf0b611e9))
* **openai:** Allow to set custom models using the API (not in UI) ([858f48b](https://github.com/postalsys/emailengine/commit/858f48b8a69c850e8d491fc6d585243ae1c183ac))
* **openai:** Allow to specify custom API url for OpenAI API requests ([047647d](https://github.com/postalsys/emailengine/commit/047647df95c17f5cfbc11647eedd560e3659931e))
* **tls:** Allow to ignore IMAP/SMTP TLS certificate errors by default using the ignoreMailCertErrors setting ([cba8ffe](https://github.com/postalsys/emailengine/commit/cba8ffeca489321e3c9736039a325c8acfb05de2))


### Bug Fixes

* **special-use-flags:** Added support for user-specified Archive special use tag ([a107f23](https://github.com/postalsys/emailengine/commit/a107f233d9f25800c08dd3e371b7cd6c95fe1a1b))
* **throttling:** Retry throttled FETCH commands a few times before giving up ([c3d259a](https://github.com/postalsys/emailengine/commit/c3d259a0bc94cd3b84ffd6e77b77d1bc098ff64c))

## [2.37.7](https://github.com/postalsys/emailengine/compare/v2.37.6...v2.37.7) (2023-10-20)


### Bug Fixes

* **chat:** use topic instead of question for the filtering embedding ([3acebc3](https://github.com/postalsys/emailengine/commit/3acebc37dd5e5c0d25dab386354f1ec1bf78d244))
* **initialization:** Start all IMAP worker threads before assigning accounts ([9b4c3fc](https://github.com/postalsys/emailengine/commit/9b4c3fc48b00a3bcfeade592cc36b8144038dad8))
* **stats:** added missing counters for messageNew/messageDeleted ([3f9f4cd](https://github.com/postalsys/emailengine/commit/3f9f4cda6aa1896f7c30b786ab7909ea274fcb69))

## [2.37.6](https://github.com/postalsys/emailengine/compare/v2.37.5...v2.37.6) (2023-10-17)


### Bug Fixes

* **about:** Added a dedicated page for license and legal information ([077b38f](https://github.com/postalsys/emailengine/commit/077b38f4edfe711109fab809327adcaa55204b40))
* **accountCounters:** added counters object that contains cumulative counter of all account specific triggered events ([67613a3](https://github.com/postalsys/emailengine/commit/67613a3bb5e69dc06304a6a5441b997e52e7b5f1))
* **documentstore:** do not report missing email as an error ([58130c7](https://github.com/postalsys/emailengine/commit/58130c786b21fcb75ce48e557c5b8f19edbb7581))
* **license:** added a section to the license about source code usage ([a923d3b](https://github.com/postalsys/emailengine/commit/a923d3bba28bf3831aa79face17c75ad65ace002))

## [2.37.5](https://github.com/postalsys/emailengine/compare/v2.37.4...v2.37.5) (2023-10-11)


### Bug Fixes

* **chat:** Fixed chat feature support for older Redis versions ([86538ba](https://github.com/postalsys/emailengine/commit/86538baff7037598788e38b68495f4d3958d52bc))
* **default_conf:** Ensure default config values for notifyText, notifyTextSize, and enableApiProxy ([b7b4d9c](https://github.com/postalsys/emailengine/commit/b7b4d9c150ffabd533e5015b2e4aee4f26160b30))
* **license:** allow selecting license key from a file instead of copying ([d813e35](https://github.com/postalsys/emailengine/commit/d813e356a20879c7e9c69db9f8e21e5648be2a6d))

## [2.37.4](https://github.com/postalsys/emailengine/compare/v2.37.3...v2.37.4) (2023-10-05)


### Bug Fixes

* **docker:** fixed docker tags, added missing v prefix to version tags ([481bf5c](https://github.com/postalsys/emailengine/commit/481bf5c6e80b6cb48a32f460dd65ee887bc79847))

## [2.37.3](https://github.com/postalsys/emailengine/compare/v2.37.2...v2.37.3) (2023-10-05)


### Bug Fixes

* **docker:** fixed docker tagged release process ([f23cde0](https://github.com/postalsys/emailengine/commit/f23cde0e851fc3e43893383d65929dc3f03b2991))

## [2.37.2](https://github.com/postalsys/emailengine/compare/v2.37.1...v2.37.2) (2023-10-03)


### Bug Fixes

* **chat:** Bumped dependency to better parse output from OpenAI API ([0250da8](https://github.com/postalsys/emailengine/commit/0250da8c37b1ced730dc9e42a611e1d6bdc0a582))

## [2.37.1](https://github.com/postalsys/emailengine/compare/v2.37.0...v2.37.1) (2023-10-02)


### Bug Fixes

* **chat:** Added 'try it' button to 'chat with emails' config page ([0f23c39](https://github.com/postalsys/emailengine/commit/0f23c390887b6d554b2ed90a437c30f2c6530aac))
* **chat:** Improved 'chat with emails' response quality by sorting and filtering embeddings vectors ([de429d6](https://github.com/postalsys/emailengine/commit/de429d6f8f1cffdbce0e48dce4f716cdf83f93bf))

## [2.37.0](https://github.com/postalsys/emailengine/compare/v2.36.1...v2.37.0) (2023-09-29)


### Features

* **secrets:** removed deprecated vault support ([8ab9d60](https://github.com/postalsys/emailengine/commit/8ab9d60df58b5d258dcf459a1928f285b02eea62))


### Bug Fixes

* **chat:** Use separate settings page for 'chat with emails' feature ([c66e3ba](https://github.com/postalsys/emailengine/commit/c66e3ba8234390ccc5cf800cee29f8e4ab0b56d2))
* **deploy:** Build packages with Node 20 ([a394cf2](https://github.com/postalsys/emailengine/commit/a394cf2d487ba95a1906b964a630d524cf57f16c))
* **package-lock:** Do not delete package lock. Use 'npm ci' to install dependencies ([752be23](https://github.com/postalsys/emailengine/commit/752be230bf510c68c1551e0f852b47a7d1f1dedb))

## [2.36.1](https://github.com/postalsys/emailengine/compare/v2.36.0...v2.36.1) (2023-09-20)


### Bug Fixes

* **deploy:** keep package-lock.json ([ec311e3](https://github.com/postalsys/emailengine/commit/ec311e34834266d6a1db382dc044a13828a1eca4))

## [2.36.0](https://github.com/postalsys/emailengine/compare/v2.35.0...v2.36.0) (2023-09-20)


### Features

* **ai:** Allow using embeddings generation without prompting ([b59e702](https://github.com/postalsys/emailengine/commit/b59e702b31a869e810178518b9549871b7988b19))


### Bug Fixes

* **ai:** Added support for gpt-3.5-turbo-instruct ([bf75c5a](https://github.com/postalsys/emailengine/commit/bf75c5ab4077ffe5e0b4a92e009d4ee6500c50b8))
* **ai:** Do not store generated embeddings in the document store ([9638480](https://github.com/postalsys/emailengine/commit/9638480662581ed09bf7fa0ebecbb64461224413))
* **deploy:** Added tests runner ([b382569](https://github.com/postalsys/emailengine/commit/b382569604b74f312ab7fadafdcba65d76f0c1ec))
* **deploy:** Automated release management ([8e2bd88](https://github.com/postalsys/emailengine/commit/8e2bd88d305a8502102986528b346c96f35f4c06))
