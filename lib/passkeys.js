'use strict';

const crypto = require('crypto');
const { redis } = require('./db');
const settings = require('./settings');
const { REDIS_PREFIX, WEBAUTHN_CHALLENGE_TTL } = require('./consts');

const KEY_PREFIX = `${REDIS_PREFIX}webauthn:`;

// A WebAuthn challenge is a bare nonce, and nothing in the signed response the authenticator
// returns says which ceremony the server minted it for - that binding is the server's job.
// Registration is gated behind a password confirmation and sign-in deliberately is not, so while
// both ceremonies drew from one keyspace a nonce minted by the unauthenticated sign-in endpoint
// could be spent completing a registration, skipping the gate entirely. The purpose is part of the
// key, so each ceremony can only consume what it minted.
const CHALLENGE_REGISTER = 'register';
const CHALLENGE_AUTH = 'auth';
const CHALLENGE_PURPOSES = new Set([CHALLENGE_REGISTER, CHALLENGE_AUTH]);

function assertPurpose(purpose) {
    if (!CHALLENGE_PURPOSES.has(purpose)) {
        // Every caller passes one of the exported constants, so this is a programming error and
        // must not degrade into an unnamespaced key that would restore the bypass
        throw new Error(`Unknown WebAuthn challenge purpose: ${purpose}`);
    }
}

function challengeKey(challengeId, purpose) {
    assertPurpose(purpose);
    return `${KEY_PREFIX}challenge:${purpose}:${challengeId}`;
}

// Passkey data does not require encryption at rest. Unlike TOTP seeds or OAuth
// client secrets (which are shared secrets), passkeys use public-key cryptography.
// Only the public key is stored here -- the private key never leaves the
// authenticator device. An attacker with Redis access cannot use a public key
// to authenticate, so encrypting it adds no meaningful security.

function hydrateCredential(data) {
    if (!data || !data.id) {
        return null;
    }
    data.counter = parseInt(data.counter, 10) || 0;
    try {
        data.transports = JSON.parse(data.transports || '[]');
    } catch (err) {
        data.transports = [];
    }
    return data;
}

async function fetchCredentialsBySet(setKey) {
    let credIds = await redis.smembers(setKey);
    if (!credIds || !credIds.length) {
        return [];
    }

    let pipeline = redis.pipeline();
    for (let id of credIds) {
        pipeline.hgetall(`${KEY_PREFIX}cred:${id}`);
    }
    let results = await pipeline.exec();

    let credentials = [];
    for (let [err, data] of results) {
        let cred = !err && hydrateCredential(data);
        if (cred) {
            credentials.push(cred);
        }
    }
    return credentials;
}

redis.defineCommand('webauthnSaveIfUnderLimit', {
    numberOfKeys: 3,
    lua: `
local userSetKey = KEYS[1]
local credKey = KEYS[2]
local allSetKey = KEYS[3]
local maxCount = tonumber(ARGV[1])
local credId = ARGV[2]

local currentCount = redis.call('SCARD', userSetKey)
if currentCount >= maxCount then
    return 0
end

redis.call('SADD', userSetKey, credId)
redis.call('SADD', allSetKey, credId)
redis.call('HSET', credKey, unpack(ARGV, 3))
return 1
`
});

function serializeCredential({ id, publicKey, counter, transports, name, user }) {
    return {
        id,
        publicKey,
        counter: String(counter),
        transports: JSON.stringify(transports || []),
        name: name || 'Unnamed passkey',
        user,
        createdAt: new Date().toISOString()
    };
}

function credentialKeys(id, user) {
    return {
        credKey: `${KEY_PREFIX}cred:${id}`,
        userSetKey: `${KEY_PREFIX}creds:${user}`,
        allSetKey: `${KEY_PREFIX}all`
    };
}

module.exports = {
    CHALLENGE_REGISTER,
    CHALLENGE_AUTH,

    async getRpConfig() {
        let serviceUrl = await settings.get('serviceUrl');
        if (!serviceUrl) {
            return { rpId: null, origin: null };
        }
        let url = new URL(serviceUrl);
        return { rpId: url.hostname, origin: url.origin };
    },

    async storeChallenge(challenge, purpose) {
        let challengeId = crypto.randomBytes(32).toString('hex');
        await redis.set(challengeKey(challengeId, purpose), challenge, 'EX', WEBAUTHN_CHALLENGE_TTL);
        return challengeId;
    },

    async consumeChallenge(challengeId, purpose) {
        // Before the id check, so a caller that forgot the purpose trips the guardrail whatever
        // it passed as an id rather than getting a plausible null back
        assertPurpose(purpose);
        if (!challengeId || typeof challengeId !== 'string') {
            return null;
        }
        let challenge = await redis.getdel(challengeKey(challengeId, purpose));
        return challenge || null;
    },

    async saveCredential(cred) {
        let { credKey, userSetKey, allSetKey } = credentialKeys(cred.id, cred.user);

        let pipeline = redis.pipeline();
        pipeline.hset(credKey, serializeCredential(cred));
        pipeline.sadd(userSetKey, cred.id);
        pipeline.sadd(allSetKey, cred.id);
        await pipeline.exec();
    },

    async saveCredentialIfUnderLimit(cred, maxCount) {
        let { credKey, userSetKey, allSetKey } = credentialKeys(cred.id, cred.user);
        let fields = serializeCredential(cred);
        let fieldArgs = Object.entries(fields).flat();

        let added = await redis.webauthnSaveIfUnderLimit(userSetKey, credKey, allSetKey, maxCount, cred.id, ...fieldArgs);

        return !!added;
    },

    async getCredential(credentialId) {
        if (!credentialId || typeof credentialId !== 'string') {
            return null;
        }
        let data = await redis.hgetall(`${KEY_PREFIX}cred:${credentialId}`);
        return hydrateCredential(data);
    },

    // Called after a verified assertion, so it stamps the sign-in time alongside the
    // signature counter. The stamp is what the security page shows as "Last used";
    // credentials registered before it existed carry no field and render as unknown
    // rather than as never used.
    async recordAuthentication(credentialId, newCounter) {
        await redis.hset(`${KEY_PREFIX}cred:${credentialId}`, 'counter', String(newCounter), 'lastUsedAt', new Date().toISOString());
    },

    async listCredentials(user) {
        let credentials = await fetchCredentialsBySet(`${KEY_PREFIX}creds:${user}`);
        credentials.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        return credentials;
    },

    async deleteCredential(credentialId, user) {
        let cred = await this.getCredential(credentialId);
        if (!cred) {
            return false;
        }
        if (user && cred.user !== user) {
            return false;
        }

        let pipeline = redis.pipeline();
        pipeline.del(`${KEY_PREFIX}cred:${credentialId}`);
        pipeline.srem(`${KEY_PREFIX}all`, credentialId);
        if (cred.user) {
            pipeline.srem(`${KEY_PREFIX}creds:${cred.user}`, credentialId);
        }
        await pipeline.exec();
        return true;
    },

    async countCredentials(user) {
        return await redis.scard(`${KEY_PREFIX}creds:${user}`);
    },

    async hasPasskeys() {
        let count = await redis.scard(`${KEY_PREFIX}all`);
        return count > 0;
    },

    async getAllCredentials() {
        return await fetchCredentialsBySet(`${KEY_PREFIX}all`);
    },

    async deleteAllCredentials(user) {
        let userSetKey = `${KEY_PREFIX}creds:${user}`;
        let allSetKey = `${KEY_PREFIX}all`;

        let credIds = await redis.smembers(userSetKey);
        if (!credIds || !credIds.length) {
            return 0;
        }

        let pipeline = redis.pipeline();
        for (let id of credIds) {
            pipeline.del(`${KEY_PREFIX}cred:${id}`);
            pipeline.srem(allSetKey, id);
        }
        pipeline.del(userSetKey);
        await pipeline.exec();

        return credIds.length;
    }
};
