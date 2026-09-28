'use strict';

require('dotenv').config({ quiet: true });

const test = require('node:test');
const assert = require('node:assert').strict;
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const Redis = require('ioredis');
const config = require('@zone-eu/wild-config');
const msgpack = require('../lib/msgpack');
const { Settings: CertSettings } = require('@postalsys/certs/lib/settings');

const { encrypt, decrypt } = require('../lib/encrypt');
const { ENCRYPTED_APP_KEYS } = require('../lib/consts');

const execFileAsync = promisify(execFile);

// Own key prefix: the CLI rewrites every record it finds, so a shared prefix would let this test
// re-encrypt the fixtures of any suite running in parallel.
const TEST_PREFIX = 'ee-encrypt-rotation-test';
const OLD_SECRET = 'rotation-test-old-secret';
const NEW_SECRET = 'rotation-test-new-secret';

// The certs library builds its own key from the namespace it is handed (`${REDIS_PREFIX}`), so ask
// it rather than assuming the separator.
const CERTS_KEY = CertSettings.create({ namespace: `${TEST_PREFIX}:` }).getKey('settings');

const cleartextFor = label => `cleartext-value-for-${label}`;

// `emailengine encrypt` re-encrypts stored credentials under a new instance secret. Anything it
// fails to visit stays readable only with the OLD secret, and the feature that owns it breaks after
// the rotation, with no self-healing path. Two real bugs of exactly this shape shipped: the OAuth2
// app `externalAccount` field was missing from its field list, and the SMTP gateway loop read an
// index set (`ia:gateways`) that nothing writes, so it reported `0/0` forever. So this drives the
// real CLI against one record of every type the tool claims to cover, rather than testing one list.
test('emailengine encrypt rotates every encrypted record type', async t => {
    const redis = new Redis(config.dbs.redis);

    t.after(async () => {
        const keys = await redis.keys(`${TEST_PREFIX}*`);
        if (keys.length) {
            await redis.del(keys);
        }
        await redis.quit();
    });

    // --- OAuth2 application: msgpack blob, fields listed in ENCRYPTED_APP_KEYS
    const appId = 'rotation-test-app';
    const appEntry = { id: appId, provider: 'gmailService', authMethod: 'externalAccount' };
    for (let key of ENCRYPTED_APP_KEYS) {
        appEntry[key] = encrypt(cleartextFor(`app.${key}`), OLD_SECRET);
    }
    await redis.sadd(`${TEST_PREFIX}:oapp:i`, appId);
    await redis.hsetBuffer(`${TEST_PREFIX}:oapp:c`, `${appId}:data`, msgpack.encode(appEntry));

    // --- Account: JSON blobs per protocol, secrets nested under `auth` and at the top level
    const accountId = 'rotation-test-account';
    await redis.sadd(`${TEST_PREFIX}:ia:accounts`, accountId);
    await redis.hmset(`${TEST_PREFIX}:iad:${accountId}`, {
        account: accountId,
        // the credential-bearing account fields, ENCRYPTED_ACCOUNT_FIELDS in lib/account.js
        webhooks: encrypt(cleartextFor('account.webhooks'), OLD_SECRET),
        webhooksCustomHeaders: encrypt(cleartextFor('account.webhooksCustomHeaders'), OLD_SECRET),
        proxy: encrypt(cleartextFor('account.proxy'), OLD_SECRET),
        imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'user@example.com', pass: encrypt(cleartextFor('imap.pass'), OLD_SECRET) } }),
        oauth2: JSON.stringify({
            auth: { user: 'user@example.com' },
            accessToken: encrypt(cleartextFor('oauth2.accessToken'), OLD_SECRET),
            refreshToken: encrypt(cleartextFor('oauth2.refreshToken'), OLD_SECRET)
        })
    });

    // --- Settings: every encryptedKeys entry is a JSON encoding, encrypted as a whole
    await redis.hset(`${TEST_PREFIX}:settings`, 'authServer', encrypt(JSON.stringify(cleartextFor('settings.authServer')), OLD_SECRET));

    // --- Webhook route: msgpack meta entry, target URL and header list encrypted inside it
    const routeId = 'rotation-test-route';
    await redis.sadd(`${TEST_PREFIX}:wh:i`, routeId);
    await redis.hsetBuffer(
        `${TEST_PREFIX}:wh:c`,
        `${routeId}:meta`,
        msgpack.encode({
            id: routeId,
            name: 'Route',
            targetUrl: encrypt(cleartextFor('route.targetUrl'), OLD_SECRET),
            customHeaders: encrypt(cleartextFor('route.customHeaders'), OLD_SECRET)
        })
    );
    // and one stored before encryption, with its header list as an array
    const legacyRouteId = 'rotation-test-legacy-route';
    const legacyHeaders = [{ key: 'Authorization', value: 'Bearer legacy' }];
    await redis.sadd(`${TEST_PREFIX}:wh:i`, legacyRouteId);
    await redis.hsetBuffer(
        `${TEST_PREFIX}:wh:c`,
        `${legacyRouteId}:meta`,
        msgpack.encode({ id: legacyRouteId, name: 'Legacy route', targetUrl: 'https://legacy.example.com/', customHeaders: legacyHeaders })
    );

    // --- SMTP gateway: plain hash field (index set is `gateways`, see lib/gateway.js)
    const gatewayId = 'rotation-test-gateway';
    await redis.sadd(`${TEST_PREFIX}:gateways`, gatewayId);
    await redis.hset(`${TEST_PREFIX}:gateway:${gatewayId}`, 'pass', encrypt(cleartextFor('gateway.pass'), OLD_SECRET));

    // --- TLS keys: the certs library's own hash, every field msgpack encoded
    const domain = 'mail.example.com';
    await redis.hsetBuffer(
        CERTS_KEY,
        `account:emailengine`,
        msgpack.encode({ privateKey: encrypt(cleartextFor('acme.privateKey'), OLD_SECRET), account: { id: 'acct-1' } })
    );
    await redis.hsetBuffer(CERTS_KEY, `domain:${domain}:privateKey`, msgpack.encode(encrypt(cleartextFor('domain.privateKey'), OLD_SECRET)));
    // A neighbouring entry that is NOT encrypted - the tool must leave it alone
    await redis.hsetBuffer(CERTS_KEY, `domain:${domain}:cert`, msgpack.encode({ cert: 'PLAIN CERT PEM' }));

    await execFileAsync(
        process.execPath,
        [path.join(__dirname, '..', 'encrypt.js'), `--dbs.redis=${config.dbs.redis}`, `--service.secret=${NEW_SECRET}`, `--decrypt=${OLD_SECRET}`],
        { env: Object.assign({}, process.env, { EENGINE_REDIS_PREFIX: TEST_PREFIX }) }
    );

    const rotatedTo = (stored, label) => {
        assert.strictEqual(decrypt(stored, NEW_SECRET), cleartextFor(label), `${label} should decrypt with the new secret`);
        assert.throws(() => decrypt(stored, OLD_SECRET), `${label} should no longer decrypt with the old secret`);
    };

    const rotatedApp = msgpack.decode(await redis.hgetBuffer(`${TEST_PREFIX}:oapp:c`, `${appId}:data`));
    for (let key of ENCRYPTED_APP_KEYS) {
        rotatedTo(rotatedApp[key], `app.${key}`);
    }

    const rotatedAccount = await redis.hgetall(`${TEST_PREFIX}:iad:${accountId}`);
    rotatedTo(JSON.parse(rotatedAccount.imap).auth.pass, 'imap.pass');
    rotatedTo(JSON.parse(rotatedAccount.oauth2).accessToken, 'oauth2.accessToken');
    rotatedTo(JSON.parse(rotatedAccount.oauth2).refreshToken, 'oauth2.refreshToken');
    rotatedTo(rotatedAccount.webhooks, 'account.webhooks');
    rotatedTo(rotatedAccount.webhooksCustomHeaders, 'account.webhooksCustomHeaders');
    rotatedTo(rotatedAccount.proxy, 'account.proxy');

    const rotatedAuthServer = await redis.hget(`${TEST_PREFIX}:settings`, 'authServer');
    assert.strictEqual(JSON.parse(decrypt(rotatedAuthServer, NEW_SECRET)), cleartextFor('settings.authServer'));
    assert.throws(() => decrypt(rotatedAuthServer, OLD_SECRET));

    const rotatedRoute = msgpack.decode(await redis.hgetBuffer(`${TEST_PREFIX}:wh:c`, `${routeId}:meta`));
    rotatedTo(rotatedRoute.targetUrl, 'route.targetUrl');
    rotatedTo(rotatedRoute.customHeaders, 'route.customHeaders');
    assert.strictEqual(rotatedRoute.name, 'Route', 'the rest of the route entry survives the re-encode');

    const legacyRoute = msgpack.decode(await redis.hgetBuffer(`${TEST_PREFIX}:wh:c`, `${legacyRouteId}:meta`));
    assert.strictEqual(decrypt(legacyRoute.targetUrl, NEW_SECRET), 'https://legacy.example.com/');
    assert.deepStrictEqual(JSON.parse(decrypt(legacyRoute.customHeaders, NEW_SECRET)), legacyHeaders, 'a cleartext header array is encrypted as JSON');

    rotatedTo(await redis.hget(`${TEST_PREFIX}:gateway:${gatewayId}`, 'pass'), 'gateway.pass');

    const rotatedAcme = msgpack.decode(await redis.hgetBuffer(CERTS_KEY, `account:emailengine`));
    rotatedTo(rotatedAcme.privateKey, 'acme.privateKey');
    assert.strictEqual(rotatedAcme.account.id, 'acct-1', 'ACME account data should survive the re-encode');

    rotatedTo(msgpack.decode(await redis.hgetBuffer(CERTS_KEY, `domain:${domain}:privateKey`)), 'domain.privateKey');

    const certData = msgpack.decode(await redis.hgetBuffer(CERTS_KEY, `domain:${domain}:cert`));
    assert.strictEqual(certData.cert, 'PLAIN CERT PEM', 'a non-encrypted certs entry should be left untouched');
});

// The other ways the tool is run: again over records it already rotated, and with no new secret,
// which removes the encryption. Both must leave every value readable.
test('emailengine encrypt is idempotent and can remove the encryption', async t => {
    const redis = new Redis(config.dbs.redis);
    const prefix = `${TEST_PREFIX}-rerun`;

    t.after(async () => {
        const keys = await redis.keys(`${prefix}*`);
        if (keys.length) {
            await redis.del(keys);
        }
        await redis.quit();
    });

    const run = async (...args) =>
        execFileAsync(process.execPath, [path.join(__dirname, '..', 'encrypt.js'), `--dbs.redis=${config.dbs.redis}`, ...args], {
            env: Object.assign({}, process.env, { EENGINE_REDIS_PREFIX: prefix })
        });

    const accountId = 'rerun-account';
    const accountKey = `${prefix}:iad:${accountId}`;
    await redis.sadd(`${prefix}:ia:accounts`, accountId);
    await redis.hmset(accountKey, {
        account: accountId,
        webhooks: encrypt('https://hook:pw@example.com/', OLD_SECRET),
        imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'u', pass: encrypt('imap-pass', OLD_SECRET) } })
    });

    await run(`--service.secret=${NEW_SECRET}`, `--decrypt=${OLD_SECRET}`);
    const first = await redis.hgetall(accountKey);

    // A second run with the same arguments finds everything already under the new secret
    const { stdout } = await run(`--service.secret=${NEW_SECRET}`, `--decrypt=${OLD_SECRET}`);
    assert.match(stdout, /Updated 0\/1 accounts/);
    assert.deepStrictEqual(await redis.hgetall(accountKey), first, 'a rerun rewrites nothing');

    // An empty secret removes the encryption (config/test.toml sets one, so it is spelled out):
    // every value goes back to cleartext
    await run('--service.secret=', `--decrypt=${NEW_SECRET}`);
    const cleared = await redis.hgetall(accountKey);
    assert.strictEqual(cleared.webhooks, 'https://hook:pw@example.com/');
    assert.strictEqual(JSON.parse(cleared.imap).auth.pass, 'imap-pass');
});
