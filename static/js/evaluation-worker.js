/* global onmessage: true, postMessage: false */
/* eslint no-unused-vars: 0 */
'use strict';

onmessage = e => {
    try {
        let source = `
            return (async (payload) =>{
                ${e.data.code}
            })(payload);
        `;

        const logger = {};

        for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']) {
            logger[level] = msg => {
                postMessage({ type: 'log', result: { level, msg: JSON.stringify(msg) } });
            };
        }

        let fn = new Function('payload', 'logger', 'fetch', 'env', source);

        let proxiedFetch = (...args) => {
            console.log('FETCH', ...args);
            return fetch(...args);
        };

        let env = {};
        if (e.data.env) {
            try {
                env = JSON.parse(e.data.env);
            } catch (err) {
                console.error('Failed to parse scriptEnv', env, err);
            }
        }

        fn(e.data.payload, logger, proxiedFetch, env)
            .then(result => {
                postMessage({ type: e.data.type, result });
            })
            .catch(err => {
                postMessage({ type: e.data.type, error: err.message });
            });
    } catch (err) {
        postMessage({ type: e.data.type, error: err.message });
    }
};
