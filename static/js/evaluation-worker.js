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

        let fn = new Function('payload', 'logger', source);

        fn(e.data.payload, logger)
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
