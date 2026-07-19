'use strict';

const msgpack = require('msgpack5')();
const Boom = require('@hapi/boom');
const { REDIS_PREFIX } = require('./consts');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const { customAlphabet } = require('nanoid');
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 16);
const { mergeObjects, filterListPage } = require('./tools');

class Gateway {
    constructor(options) {
        this.redis = options.redis;
        this.gateway = options.gateway || false;

        this.documentsQueue = options.documentsQueue || false;

        this.secret = options.secret;

        this.logger = options.logger || logger;
    }

    getGatewayKey(gateway) {
        return `${REDIS_PREFIX}gateway:${gateway || this.gateway}`;
    }

    unserialize(data) {
        let obj = {};
        let value;
        for (let key of Object.keys(data)) {
            switch (key) {
                case 'gateway':
                    value = data[key].toString();
                    break;
                case 'deliveries':
                    value = Number(data[key].toString()) || 0;
                    break;
                case 'pass':
                    value = decrypt(data[key].toString(), this.secret);
                    break;
                default:
                    if (data[key] && Buffer.isBuffer(data[key])) {
                        value = msgpack.decode(data[key]);
                    } else {
                        continue;
                    }
                    break;
            }
            obj[key] = value;
        }
        return obj;
    }

    serialize(data) {
        let obj = {};
        let value;
        for (let key of Object.keys(data)) {
            switch (key) {
                case 'gateway':
                    value = data[key];
                    break;
                case 'deliveries':
                    value = (Number(data[key]) || 0).toString();
                    break;
                case 'pass':
                    value = encrypt(data[key], this.secret);
                    break;
                default:
                    value = msgpack.encode(data[key]);
                    break;
            }
            obj[key] = value;
        }
        return obj;
    }

    async genId() {
        let id;
        let retries = 0;
        while (retries++ < 20) {
            id = nanoid();
            let alreadyExists = await this.redis.hexists(`${REDIS_PREFIX}gateway:${id}`, 'gateway');
            if (alreadyExists) {
                id = false;
            } else {
                break;
            }
        }
        return id;
    }

    async listGateways(page, limit, query) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        let gateways = (await this.redis.smembers(`${REDIS_PREFIX}gateways`)).sort((a, b) => a.localeCompare(b));

        // Without a query only the visible page's entries are fetched; with a query
        // all entries are loaded so the filter can run before pagination
        let selectedIds = query ? gateways : gateways.slice(skip, skip + limit);

        let req = this.redis.multi();

        for (let gateway of selectedIds) {
            req = req.hgetallBuffer(this.getGatewayKey(gateway));
        }

        let gatewayList = [];

        if (selectedIds.length) {
            let list = await req.exec();
            for (let entry of list) {
                if (entry[0]) {
                    throw entry[0];
                }
                if (entry[1]) {
                    gatewayList.push(this.unserialize(entry[1]));
                }
            }
        }

        let total = gateways.length;
        let pages = Math.ceil(total / limit);
        if (query) {
            let paged = filterListPage(gatewayList, ['gateway', 'name', 'host', 'user'], query, skip, limit);
            gatewayList = paged.entries;
            total = paged.total;
            pages = paged.pages;
        }

        let list = {
            total,
            pages,
            page,
            gateways: gatewayList.map(entry => ({
                gateway: entry.gateway,
                name: entry.name,
                deliveries: entry.deliveries || 0,
                lastUse: entry.lastUse || null,
                lastError: entry.lastError || null
            }))
        };

        return list;
    }

    async loadGatewayData(gateway) {
        if (!this.gateway || (gateway && gateway !== this.gateway)) {
            let message = 'Invalid gateway ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let result = await this.redis.hgetallBuffer(this.getGatewayKey());

        if (!result || !result.gateway) {
            let message = 'Gateway record was not found for requested ID';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            throw error;
        }

        return this.unserialize(result);
    }

    async create(gatewayData) {
        this.gateway = gatewayData.gateway;
        if (this.gateway === null) {
            // auogenerate ID
            this.gateway = gatewayData.gateway = await this.genId();
        }

        if (!this.gateway) {
            let message = 'Invalid gateway ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let result = await this.redis
            .multi()
            .hget(this.getGatewayKey(), 'gateway')
            .hmset(this.getGatewayKey(), this.serialize(gatewayData))
            .sadd(`${REDIS_PREFIX}gateways`, this.gateway)
            .exec();

        if (!result || !result[1] || result[1][0] || result[1][1] !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        // HGET returns the previous value if the gateway entry already existed
        let state = result[0][1] ? 'existing' : 'new';

        return { gateway: this.gateway, state };
    }

    async update(gatewayData) {
        let oldGatewayData = await this.loadGatewayData(gatewayData.gateway);

        for (let subKey of ['tls']) {
            if (!gatewayData[subKey] || typeof gatewayData[subKey] !== 'object') {
                continue;
            }

            let partial = gatewayData[subKey].partial;
            delete gatewayData[subKey].partial;
            if (!partial) {
                continue;
            }

            // merge old and new values
            if (!gatewayData[subKey]) {
                // nothing to merge
                continue;
            }

            mergeObjects(gatewayData[subKey], oldGatewayData[subKey]);
        }

        if (typeof gatewayData.deliveries === 'object' && gatewayData.deliveries && Number(gatewayData.deliveries.inc)) {
            try {
                await this.redis.hincrby(this.getGatewayKey(), 'deliveries', Number(gatewayData.deliveries.inc));
            } catch (err) {
                if (this.logger) {
                    this.logger.error({ msg: 'Failed to increment counter', err });
                }
            }
            delete gatewayData.deliveries;
        }

        let result = await this.redis.hmset(this.getGatewayKey(), this.serialize(gatewayData));

        if (!result || result !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        return {
            gateway: this.gateway
        };
    }

    async delete() {
        await this.loadGatewayData(this.gateway);

        let result = await this.redis.multi().del(this.getGatewayKey()).srem(`${REDIS_PREFIX}gateways`, this.gateway).exec();
        if (!result) {
            return {
                gateway: this.gateway,
                deleted: false
            };
        }

        for (let entry of result) {
            if (entry && entry[0]) {
                throw entry[0];
            }
        }

        if (!result[0] || !result[0][1]) {
            return {
                gateway: this.gateway,
                deleted: false
            };
        }

        return {
            gateway: this.gateway,
            deleted: true
        };
    }
}

module.exports = { Gateway };
