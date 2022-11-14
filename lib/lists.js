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
        let exists = await redis.hexists(this.getListsIndexKey(), listId);
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
