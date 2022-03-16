'use strict';

const crypto = require('crypto');
const { REDIS_BATCH_DELETE_SIZE } = require('./consts');

async function redisScanDelete(redis, logger, match) {
    let deletedKeys = 0;

    return new Promise((resolve, reject) => {
        const stream = redis.scanStream({ match, count: REDIS_BATCH_DELETE_SIZE });
        let pipeline = redis.pipeline();
        let batchKeys = [];

        let scanId = crypto.randomBytes(12).toString('base64');

        logger.trace({
            msg: `Streaming Redis keys for deletion`,
            scanId,
            match,
            batchSize: REDIS_BATCH_DELETE_SIZE
        });

        stream.on('data', resultKeys => {
            if (resultKeys.length) {
                logger.trace({
                    msg: `Keys scanned`,
                    scanId,
                    match,
                    keysRead: resultKeys.length,
                    cachedKeys: batchKeys.length
                });
            }

            for (let ik = 0; ik < resultKeys.length; ik++) {
                batchKeys.push(resultKeys[ik]);
                deletedKeys++;
                pipeline.del(resultKeys[ik]);
            }

            if (batchKeys.length >= REDIS_BATCH_DELETE_SIZE) {
                const keyCount = batchKeys.length;

                pipeline.exec(() => {
                    logger.trace({
                        msg: `Deleted keys in batch`,
                        scanId,
                        match,
                        keyCount
                    });
                });

                batchKeys = [];
                pipeline = redis.pipeline();
            }
        });

        stream.on('end', () => {
            const keyCount = batchKeys.length;
            if (!keyCount) {
                return resolve(deletedKeys);
            }

            pipeline.exec(() => {
                logger.trace({
                    msg: `Deleted keys in batch`,
                    scanId,
                    match,
                    keyCount
                });

                resolve(deletedKeys);
            });
        });

        stream.on('error', err => {
            logger.error({ msg: 'Scan error', scanId, err });
            reject(err);
        });
    });
}

module.exports = redisScanDelete;
