# Changelog

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
