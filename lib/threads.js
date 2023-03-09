'use strict';

const uuid = require('uuid');

async function getThread(client, index, account, messageData, logger) {
    if (messageData.threadId) {
        return messageData.threadId;
    }

    if (!client) {
        return;
    }

    let subject = (messageData.subject || '')
        .replace(/^([a-z]{1,8}:\s*)*/i, '')
        .trim()
        .toLowerCase();

    let references = new Set();

    if (messageData.headers) {
        []
            .concat(messageData.headers['message-id'] || [])
            .concat(messageData.headers['in-reply-to'] || [])
            .concat(messageData.headers.references || [])
            .concat(messageData.headers['thread-index'] || [])
            .concat(messageData.relatedMessageId || [])
            .flatMap(entry => entry)
            .flatMap(entry => entry.split(/\s+/))
            .map(entry => entry.trim())
            .filter(entry => entry)
            .forEach(entry => references.add(entry));
    }

    if (!references.size) {
        return false;
    }

    references = Array.from(references).slice(0, 20);

    let query = {
        bool: {
            must: [
                {
                    term: {
                        account
                    }
                },
                {
                    bool: {
                        should: references.map(ref => ({
                            term: {
                                references: ref
                            }
                        })),
                        minimum_should_match: 1
                    }
                }
            ]
        }
    };

    let searchResult;

    const maxThreadRetries = 5;
    for (let i = 0; i < 5; i++) {
        let failed;
        try {
            searchResult = await client.search({
                index: `${index}.threads`,
                query,
                size: 1
            });

            if (!searchResult.hits.total.value) {
                // create new thread
                let id = uuid.v4();
                let createResult = await client.create({
                    index: `${index}.threads`,
                    id,
                    document: {
                        account,
                        subject,
                        references,
                        created: new Date().toISOString()
                    }
                });
                return (createResult && createResult._id) || false;
            }
        } catch (err) {
            failed = err;
        }

        if (!failed) {
            // found an existing thread
            break;
        } else if (i < maxThreadRetries - 1) {
            // try again after a small delay
            logger.error({ msg: 'Failed to get thread entry, retrying', retry: i, err: failed });
            await new Promise(r => setTimeout(r, 150));
        } else {
            // too many retries
            throw failed;
        }
    }

    let threadEntry = searchResult.hits.hits[0];
    if (!threadEntry || !threadEntry._id) {
        return false;
    }

    // do not store more than 100 references per thread
    if (threadEntry._source.references.length < 128) {
        let missingRefs = [];
        for (let ref of references) {
            if (!threadEntry._source.references.includes(ref)) {
                missingRefs.push(ref);
            }
        }

        if (missingRefs.length) {
            // update thread entry
            try {
                let script = {
                    lang: 'painless',
                    source: `
                            for(ref in params.refs){
                                if(! ctx._source.references.contains(ref)){
                                    ctx._source.references.add(ref)
                                }
                            }`,
                    params: {
                        refs: missingRefs
                    }
                };

                await client.update({
                    index: `${index}.threads`,
                    id: threadEntry._id,
                    refresh: true,
                    script,
                    upsert: Object.assign(threadEntry._source, {
                        references: threadEntry._source.references.concat(missingRefs)
                    })
                });
            } catch (err) {
                logger.error({ msg: 'Failed to update thread entry', err });
            }
        }
    }

    return threadEntry._id;
}

module.exports = { getThread };
