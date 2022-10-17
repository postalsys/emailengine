/* global onmessage: true, postMessage: false */
/* eslint no-unused-vars: 0 */
'use strict';

onmessage = e => {
    try {
        let fn = new Function('payload', e.data.code);
        let result = fn(e.data.payload);
        postMessage({ type: e.data.type, result });
    } catch (err) {
        postMessage({ type: e.data.type, error: err.message });
    }
};
