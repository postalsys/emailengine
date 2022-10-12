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
                    source: {
                        type: 'keyword',
                        ignore_above: 128
                    },
                    message: {
                        type: 'text'
                    },
                    status: {
                        type: 'keyword',
                        ignore_above: 128
                    }
                }
            },
            mta: {
                type: 'keyword',
                ignore_above: 256
            },
            queueId: {
                type: 'keyword',
                ignore_above: 256
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
    isBounce: {
        type: 'boolean'
    },
    labels: {
        type: 'keyword',
        ignore_above: 998
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
    category: {
        type: 'keyword',
        ignore_above: 128
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

    preview: {
        type: 'text',
        index: false
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
    thread: {
        type: 'keyword',
        ignore_above: 128
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

const threadMappings = {
    account: {
        type: 'keyword',
        ignore_above: 256
    },
    subject: {
        type: 'keyword',
        ignore_above: 256
    },
    references: {
        type: 'keyword',
        ignore_above: 256
    },
    created: {
        type: 'date'
    }
};

const threadPolicy = {
    phases: {
        hot: {
            actions: {
                rollover: {
                    max_primary_shard_size: '50GB',
                    max_age: '30d'
                }
            }
        },
        delete: {
            min_age: '90d',
            actions: {
                delete: {}
            }
        }
    }
};

const threadTemplateSettings = {
    number_of_shards: 1,
    number_of_replicas: 1
};

/**
 * Function to either create or update an index to match the definition
 * @param {Object} client ElasticSearch client object
 * @param {String} index Index name
 */
const ensureIndex = async (client, index, opts) => {
    const { mappings, analyzer, tokenizer, filter, aliases } = opts;

    let indexExists = await client.indices.exists({ index });

    if (!indexExists) {
        // create new

        let indexOpts = {
            index,
            mappings: { properties: mappings }
        };

        if (analyzer || tokenizer || filter) {
            indexOpts.settings = {
                analysis: {
                    analyzer,
                    tokenizer,
                    filter
                }
            };
        }

        if (aliases) {
            indexOpts.aliases = aliases;
        }

        let createResult = await client.indices.create(indexOpts);
        assert(createResult && createResult.acknowledged);
        return { created: true };
    } else {
        let indexData = await client.indices.get({ index });
        if (!indexData || !indexData[index]) {
            throw new Error('Missing index data');
        }

        let changes = {};

        if (analyzer || tokenizer || filter) {
            // compare settings and update if needed
            let analysisData = (indexData[index].settings && indexData[index].settings.index && indexData[index].settings.index.analysis) || {};
            let missingAnalyzers = {};
            for (let key of Object.keys(analyzer || {})) {
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

async function ensureThreadIndex(client, index) {
    // Separate ILM index for threading
    const policyName = `${index}.threads.policy`;
    const templateName = `${index}.threads.template`;
    const patternName = `${index}.threads`;

    let policyRes;
    try {
        policyRes = await client.ilm.getLifecycle({
            name: policyName
        });
    } catch (err) {
        if (err.meta && err.meta.body && err.meta.body.status === 404) {
            // policy not found
        } else {
            throw err;
        }
    }

    if (!policyRes) {
        let createPolicyRes = await client.ilm.putLifecycle({
            name: policyName,
            policy: threadPolicy
        });
        assert(createPolicyRes && createPolicyRes.acknowledged);
    }

    let existsTemplateRes = await client.indices.existsIndexTemplate({
        name: templateName
    });

    if (!existsTemplateRes) {
        let putTemplateRes = await client.indices.putIndexTemplate({
            name: templateName,
            index_patterns: [`${patternName}-*`],
            template: {
                settings: Object.assign(
                    {
                        'index.lifecycle.name': policyName,
                        'index.lifecycle.rollover_alias': patternName
                    },
                    threadTemplateSettings
                ),
                mappings: {
                    _source: {
                        enabled: true
                    },
                    properties: threadMappings
                }
            }
        });
        assert(putTemplateRes && putTemplateRes.acknowledged);
    }

    let aliasExists = await client.indices.existsAlias({ name: patternName });
    if (!aliasExists) {
        await ensureIndex(client, `${patternName}-000001`, {
            mappings: threadMappings,
            aliases: {
                [patternName]: {
                    is_write_index: true
                }
            }
        });
    }
}

module.exports = {
    async ensureIndex(client, index) {
        let indexResult = await ensureIndex(client, index, { mappings, analyzer, tokenizer, filter });

        await ensureThreadIndex(client, index);

        return indexResult;
    }
};

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

    for (let index of ['mastiff', 'kastiff']) {
        console.log(index, await module.exports.ensureIndex(client, index, { mappings, analyzer, tokenizer, filter }));

        await client.index({
            index: `${index}.threads`,
            id: 'test',
            document: {
                tere: 'vana'
            }
        });
    }
}

main().catch(err => console.error(err));
*/
