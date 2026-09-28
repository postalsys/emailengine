'use strict';

const crypto = require('crypto');
const { REDIS_BATCH_DELETE_SIZE } = require('./consts');

// Runs one batch of DELs and resolves to the number of keys Redis reports as removed. Rejects when
// the pipeline itself fails or any DEL in it answered with an error: counting a key as deleted
// before (or without) the command running made a failed cleanup look like a complete one.
function execBatch(pipeline) {
    return new Promise((resolve, reject) => {
        pipeline.exec((err, results) => {
            if (err) {
                return reject(err);
            }
            let removed = 0;
            for (let [cmdErr, reply] of results || []) {
                if (cmdErr) {
                    return reject(cmdErr);
                }
                removed += Number(reply) || 0;
            }
            resolve(removed);
        });
    });
}

async function redisScanDelete(redis, logger, match) {
    return new Promise((resolve, reject) => {
        const stream = redis.scanStream({ match, count: REDIS_BATCH_DELETE_SIZE });
        let pipeline = redis.pipeline();
        let batchKeys = [];
        let batches = [];

        let scanId = crypto.randomBytes(12).toString('base64');

        logger.trace({
            msg: `Streaming Redis keys for deletion`,
            scanId,
            match,
            batchSize: REDIS_BATCH_DELETE_SIZE
        });

        const flush = () => {
            const keyCount = batchKeys.length;
            const batch = execBatch(pipeline).then(
                removed => {
                    logger.trace({
                        msg: `Deleted keys in batch`,
                        scanId,
                        match,
                        keyCount,
                        removed
                    });
                    return removed;
                },
                err => {
                    logger.error({ msg: 'Failed to delete scanned keys', scanId, match, keyCount, err });
                    throw err;
                }
            );
            // Observed here so a batch failing while the scan is still running is not reported as
            // an unhandled rejection; the settled result is read again on stream end.
            batch.catch(() => {});
            batches.push(batch);

            batchKeys = [];
            pipeline = redis.pipeline();
        };

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
                pipeline.del(resultKeys[ik]);
            }

            if (batchKeys.length >= REDIS_BATCH_DELETE_SIZE) {
                flush();
            }
        });

        stream.on('end', () => {
            if (batchKeys.length) {
                flush();
            }

            Promise.all(batches).then(
                counts => resolve(counts.reduce((sum, count) => sum + count, 0)),
                err => reject(err)
            );
        });

        stream.on('error', err => {
            logger.error({ msg: 'Scan error', scanId, err });
            reject(err);
        });
    });
}

module.exports = redisScanDelete;
