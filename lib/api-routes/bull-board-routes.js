'use strict';

const { createBullBoard } = require('@bull-board/api');
const { BullMQAdapter } = require('@bull-board/api/bullMQAdapter');
const { HapiAdapter } = require('@bull-board/hapi');
const { notifyQueue, submitQueue, documentsQueue } = require('../db');

async function init(args) {
    const { server } = args;

    const serverAdapter = new HapiAdapter();

    let queues = [
        {
            queue: notifyQueue,
            prefix: 'Webhooks Queue - ',
            description: 'This queue processes all email events that may trigger webhooks. Events that do not trigger a webhook are silently discarded.'
        },
        {
            queue: submitQueue,
            prefix: 'Submission Queue - ',
            description: 'This queue contains emails that are scheduled to be sent.'
        },
        {
            queue: documentsQueue,
            prefix: 'Document Queue - ',
            description: '(Deprecated) This queue was used for indexing email information in the Document Store'
        }
    ];
    let queueAdapters = queues.map(queue => {
        let adapter = new BullMQAdapter(queue.queue, {
            description: queue.description,
            prefix: queue.prefix
        });

        //adapter.setFormatter('name', job => `#Queue1 - ${job.name}`);

        return adapter;
    });

    createBullBoard({
        queues: queueAdapters,
        serverAdapter,
        options: {
            uiConfig: {
                boardTitle: 'Bull Board',
                boardLogo: { path: '/static/logo.png', width: '28px', height: '28px' },
                favIcon: { default: '/static/favicon/android-chrome-512x512.png', alternative: 'static/favicon/favicon-32x32.png' },
                miscLinks: [{ text: 'Dashboard', url: '/admin' }]
            }
        }
    });

    serverAdapter.setBasePath('/admin/bull-board');
    await server.register(serverAdapter.registerPlugin(), {
        routes: { prefix: '/admin/bull-board' }
    });
}

module.exports = init;
