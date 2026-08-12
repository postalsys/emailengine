'use strict';

const { redis } = require('./db');
const { REDIS_PREFIX } = require('./consts');
const Boom = require('@hapi/boom');
const logger = require('./logger');

class ListHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;
    }

    getListsIndexKey() {
        return `${REDIS_PREFIX}lists:unsub:lists`;
    }

    getListsContentKey(listId) {
        return `${REDIS_PREFIX}lists:unsub:entries:${listId}`;
    }

    normalizeRecipient(recipient) {
        return (recipient || '').toString().toLowerCase().trim();
    }

    // does the list itself exist
    async exists(listId) {
        return (await this.redis.hexists(this.getListsIndexKey(), listId)) === 1;
    }

    // is the recipient suppressed on this list
    async has(listId, recipient) {
        return (await this.redis.hexists(this.getListsContentKey(listId), this.normalizeRecipient(recipient))) === 1;
    }

    // Adds a suppression record. The entry key is the normalized recipient address; the stored
    // record echoes the recipient and is stamped with a created time unless the caller provides
    // one. Returns 1 when the address was newly added, 0 when it was already listed (eeListAdd
    // keeps the list counter in sync atomically).
    async add(listId, recipient, meta) {
        let record = Object.assign({ recipient }, meta || {});
        if (!record.created) {
            record.created = new Date().toISOString();
        }
        return await this.redis.eeListAdd(
            this.getListsIndexKey(),
            this.getListsContentKey(listId),
            listId,
            this.normalizeRecipient(recipient),
            JSON.stringify(record)
        );
    }

    // Returns 1 when the address was removed, 0 when it was not listed
    async remove(listId, recipient) {
        return await this.redis.eeListRemove(this.getListsIndexKey(), this.getListsContentKey(listId), listId, this.normalizeRecipient(recipient));
    }

    // Drops a whole list with all of its entries. Returns true when the list existed.
    async deleteList(listId) {
        let result = await this.redis.multi().hdel(this.getListsIndexKey(), listId).del(this.getListsContentKey(listId)).exec();
        for (let [err] of result) {
            if (err) {
                throw err;
            }
        }
        return !!result[0][1];
    }

    async list(page, pageSize) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let listEntries = await this.redis.hgetall(this.getListsIndexKey());
        let listKeys = Object.keys(listEntries).sort((a, b) => a.localeCompare(b));

        let response = {
            total: listKeys.length,
            pages: Math.ceil(listKeys.length / pageSize),
            page,
            blocklists: []
        };

        if (listKeys.length <= startPos) {
            return response;
        }

        response.blocklists = listKeys.slice(startPos, startPos + pageSize).map(entry => ({ listId: entry, count: Number(listEntries[entry]) || 0 }));

        return response;
    }

    async listContent(listId, page, pageSize) {
        let exists = await this.exists(listId);
        if (!exists) {
            let message = 'Requested blocklist was not found';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            throw error;
        }

        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let listContentEntries = await this.redis.hgetall(this.getListsContentKey(listId));
        let contentKeys = Object.keys(listContentEntries).sort((a, b) => a.localeCompare(b));

        let response = {
            listId,
            total: contentKeys.length,
            pages: Math.ceil(contentKeys.length / pageSize),
            page,
            addresses: []
        };

        if (contentKeys.length <= startPos) {
            return response;
        }

        response.addresses = contentKeys
            .slice(startPos, startPos + pageSize)
            .map(key => {
                let entry = listContentEntries[key];
                try {
                    return JSON.parse(entry);
                } catch (err) {
                    logger.error({ msg: 'Failed to parse blocklist record', address: key, listId, record: entry, err });
                    return null;
                }
            })
            .filter(entry => entry);

        return response;
    }
}

module.exports.lists = new ListHandler({ redis });
