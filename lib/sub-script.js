'use strict';

const crypto = require('crypto');
const vm = require('vm');
const logger = require('./logger');

const { FETCH_TIMEOUT, SUBSCRIPT_RUNTIME_TIMEOUT } = require('./consts');

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });
let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

const fnCache = new Map();

function getCompiledScript(code) {
    let fnHash = crypto.createHash('md5').update(code).digest('hex');
    if (fnCache.has(fnHash)) {
        let { fn, err } = fnCache.get(fnHash);
        if (err) {
            throw err;
        }
        return fn;
    }

    let fn;
    try {
        let source = `
            (async (payload) =>{
                ${code}
            })(payload);
        `;
        fn = new vm.Script(source);
        fnCache.set(fnHash, { fn });
        return fn;
    } catch (err) {
        fnCache.set(fnHash, { err });
        throw err;
    }
}

const wrappedFetch = (...args) => {
    let opts = {};

    if (args[1] && typeof args[1] === 'object') {
        opts = args[1];
    }

    return fetchCmd(args[0], Object.assign({}, opts, { dispatcher: fetchAgent }));
};

class SubScript {
    static create(name, code) {
        return new SubScript(name, code);
    }

    constructor(name, code) {
        this.name = name;
        this.fn = getCompiledScript(code);
    }

    async exec(payload) {
        if (!this.fn) {
            throw new Error('Subscript not compiled');
        }

        try {
            let ctx = {
                payload: payload ? pfStructuredClone(payload) : {},
                fetch: wrappedFetch
            };

            vm.createContext(ctx);
            let result = await this.fn.runInContext(ctx, {
                timeout: SUBSCRIPT_RUNTIME_TIMEOUT,
                microtaskMode: 'afterEvaluate'
            });

            logger.trace({ msg: 'Sub-script executed', action: 'subscript', subscript: this.name });

            return result;
        } catch (err) {
            logger.trace({ msg: 'Execution failed', action: 'subscript', subscript: this.name, err });
            throw err;
        }
    }
}

module.exports = { SubScript };
