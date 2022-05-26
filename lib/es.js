'use strict';

const assert = require('assert');

const analyzer = {
    htmlStripAnalyzer: {
        type: 'custom',
        tokenizer: 'standard',
        filter: ['lowercase'],
        char_filter: ['html_strip']
    },
    filenameSearch: {
        tokenizer: 'filename',
        filter: ['lowercase']
    },
    filenameIndex: {
        tokenizer: 'filename',
        filter: ['lowercase', 'edgeNgram']
    }
};

const tokenizer = {
    filename: {
        pattern: '[^\\p{L}\\d]+',
        type: 'pattern'
    }
};

const filter = {
    edgeNgram: {
        side: 'front',
        max_gram: 20,
        min_gram: 1,
        type: 'edge_ngram'
    }
};

const mappings = {
    account: {
        type: 'keyword',
        ignore_above: 256
    },
    answered: {
        type: 'boolean'
    },
    attachments: {
        type: 'nested',
        properties: {
            contentId: {
                type: 'keyword',
                ignore_above: 128
            },
            contentType: {
                type: 'keyword',
                ignore_above: 128
            },
            embedded: {
                type: 'boolean'
            },
            encodedSize: {
                type: 'long'
            },
            filename: {
                type: 'text',
                analyzer: 'filenameIndex',
                search_analyzer: 'filenameSearch'
            },
            id: {
                type: 'keyword',
                ignore_above: 128
            },
            inline: {
                type: 'boolean'
            }
        }
    },
    bcc: {
        properties: {
            address: {
                type: 'keyword',
                ignore_above: 256
            },
            name: {
                type: 'text'
            }
        }
    },
    bounces: {
        type: 'nested',
        properties: {
            action: {
                type: 'keyword',
                ignore_above: 128
            },
            date: {
                type: 'date'
            },
            message: {
                type: 'keyword',
                ignore_above: 128
            },
            recipient: {
                type: 'keyword',
                ignore_above: 256
            },
            response: {
                properties: {
                    message: {
                        type: 'text'
                    },
                    status: {
                        type: 'keyword',
                        ignore_above: 128
                    }
                }
            }
        }
    },
    cc: {
        properties: {
            address: {
                type: 'keyword',
                ignore_above: 256
            },
            name: {
                type: 'text'
            }
        }
    },
    created: {
        type: 'date'
    },
    date: {
        type: 'date'
    },
    draft: {
        type: 'boolean'
    },
    emailId: {
        type: 'keyword',
        ignore_above: 128
    },
    flagged: {
        type: 'boolean'
    },
    flags: {
        type: 'keyword',
        ignore_above: 128
    },
    from: {
        properties: {
            address: {
                type: 'keyword',
                ignore_above: 256
            },
            name: {
                type: 'text'
            }
        }
    },
    headers: {
        type: 'nested',
        properties: {
            key: {
                type: 'keyword',
                ignore_above: 256
            },
            value: {
                type: 'text'
            }
        }
    },
    id: {
        type: 'keyword',
        ignore_above: 128
    },
    inReplyTo: {
        type: 'keyword',
        ignore_above: 998
    },
    isAutoReply: {
        type: 'boolean'
    },
    messageId: {
        type: 'keyword',
        ignore_above: 998
    },
    path: {
        type: 'keyword',
        ignore_above: 998
    },
    replyTo: {
        properties: {
            address: {
                type: 'keyword',
                ignore_above: 256
            },
            name: {
                type: 'text'
            }
        }
    },
    seemsLikeNew: {
        type: 'boolean'
    },
    sender: {
        properties: {
            address: {
                type: 'keyword',
                ignore_above: 256
            },
            name: {
                type: 'text'
            }
        }
    },
    size: {
        type: 'long'
    },
    specialUse: {
        type: 'keyword',
        ignore_above: 64
    },
    subject: {
        type: 'text'
    },
    text: {
        properties: {
            id: {
                type: 'keyword',
                ignore_above: 128
            },
            html: {
                type: 'text',
                analyzer: 'htmlStripAnalyzer'
            },
            plain: {
                type: 'text'
            },
            encodedSize: {
                properties: {
                    html: {
                        type: 'integer'
                    },
                    plain: {
                        type: 'integer'
                    }
                }
            }
        }
    },
    threadId: {
        type: 'keyword',
        ignore_above: 128
    },
    to: {
        properties: {
            name: {
                type: 'text'
            },
            address: {
                type: 'keyword',
                ignore_above: 256
            }
        }
    },
    uid: {
        type: 'long'
    },
    unseen: {
        type: 'boolean'
    }
};

/**
 * Function to either create or update an index to match the definition
 * @param {Object} client ElasticSearch client object
 * @param {String} index Index name
 */
const ensureIndex = async (client, index) => {
    let indexExists = await client.indices.exists({ index });

    if (!indexExists) {
        // create new
        let createResult = await client.indices.create({
            index,
            mappings: { properties: mappings },
            settings: {
                analysis: {
                    analyzer,
                    tokenizer,
                    filter
                }
            }
        });
        assert(createResult && createResult.acknowledged);
        return { created: true };
    } else {
        let indexData = await client.indices.get({ index });
        if (!indexData || !indexData[index]) {
            throw new Error('Missing index data');
        }

        let changes = {};

        // compare settings and update if needed
        let analysisData = (indexData[index].settings && indexData[index].settings.index && indexData[index].settings.index.analysis) || {};
        let missingAnalyzers = {};
        for (let key of Object.keys(analyzer)) {
            if (!analysisData.analyzer || !analysisData.analyzer[key]) {
                missingAnalyzers[key] = analyzer[key];
            }
        }

        // found missing analyzers, update settings
        if (Object.keys(missingAnalyzers).length) {
            // index needs to be closed when changing analyser settings
            let closeResult = await client.indices.close({ index });
            assert(closeResult && closeResult.acknowledged);
            try {
                let updateResult = await client.indices.putSettings({
                    index,
                    settings: {
                        analysis: {
                            analyzer,
                            tokenizer,
                            filter
                        }
                    }
                });
                assert(updateResult && updateResult.acknowledged);
                changes.analyzers = true;
            } finally {
                // try to open even if update failed
                let openResult = await client.indices.open({ index });
                assert(openResult && openResult.acknowledged);
            }
        }

        // Compare mappings and add missing
        let storedMappings = (indexData[index].mappings && indexData[index].mappings.properties) || {};
        let missingMappings = {};
        for (let key of Object.keys(mappings)) {
            if (!storedMappings[key]) {
                missingMappings[key] = mappings[key];
            }
        }

        // add missing mappings if needed
        if (Object.keys(missingMappings).length) {
            try {
                const updateRes = await client.indices.putMapping({ index, properties: missingMappings });
                assert(updateRes && updateRes.acknowledged);
                changes.mappings = true;
            } catch (err) {
                // other than that update everything succeeded, so ignore for now
            }
        }

        if (!Object.keys(changes).length) {
            return { exists: true };
        } else {
            return { updated: true, changes };
        }
    }
};

module.exports = { ensureIndex };

/*
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
async function main() {
    const client = new ElasticSearch({
        node: { url: new URL('https://127.0.0.1:9200'), tls: { rejectUnauthorized: false } },
        auth: {
            username: 'elastic',
            password: 'NqDHHrrPVBQtxy9cvIYa'
        }
    });

    for (let index of ['emailengine', 'mastiff', 'kastiff']) {
        console.log(index, await ensureIndex(client, index));
    }
}

main().catch(err => console.error(err));
*/
