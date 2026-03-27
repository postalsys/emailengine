'use strict';

const crypto = require('crypto');
const { redis } = require('./db');
const settings = require('./settings');
const { REDIS_PREFIX, WEBAUTHN_CHALLENGE_TTL } = require('./consts');

const KEY_PREFIX = `${REDIS_PREFIX}webauthn:`;

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
    data.transports = JSON.parse(data.transports || '[]');
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

module.exports = {
    async getRpConfig() {
        let serviceUrl = await settings.get('serviceUrl');
        if (!serviceUrl) {
            return { rpId: null, origin: null };
        }
        let url = new URL(serviceUrl);
        return { rpId: url.hostname, origin: url.origin };
    },

    async storeChallenge(challenge) {
        let challengeId = crypto.randomBytes(32).toString('hex');
        await redis.set(`${KEY_PREFIX}challenge:${challengeId}`, challenge, 'EX', WEBAUTHN_CHALLENGE_TTL);
        return challengeId;
    },

    async consumeChallenge(challengeId) {
        if (!challengeId || typeof challengeId !== 'string') {
            return null;
        }
        let key = `${KEY_PREFIX}challenge:${challengeId}`;
        let challenge = await redis.getdel(key);
        return challenge || null;
    },

    async saveCredential({ id, publicKey, counter, transports, name, user }) {
        let credKey = `${KEY_PREFIX}cred:${id}`;
        let userSetKey = `${KEY_PREFIX}creds:${user}`;
        let allSetKey = `${KEY_PREFIX}all`;

        let pipeline = redis.pipeline();
        pipeline.hset(credKey, {
            id,
            publicKey,
            counter: String(counter),
            transports: JSON.stringify(transports || []),
            name: name || 'Unnamed passkey',
            user,
            createdAt: new Date().toISOString()
        });
        pipeline.sadd(userSetKey, id);
        pipeline.sadd(allSetKey, id);
        await pipeline.exec();
    },

    async getCredential(credentialId) {
        if (!credentialId || typeof credentialId !== 'string') {
            return null;
        }
        let data = await redis.hgetall(`${KEY_PREFIX}cred:${credentialId}`);
        return hydrateCredential(data);
    },

    async updateCounter(credentialId, newCounter) {
        await redis.hset(`${KEY_PREFIX}cred:${credentialId}`, 'counter', String(newCounter));
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

    async hasPasskeys() {
        let count = await redis.scard(`${KEY_PREFIX}all`);
        return count > 0;
    },

    async getAllCredentials() {
        return await fetchCredentialsBySet(`${KEY_PREFIX}all`);
    }
};
