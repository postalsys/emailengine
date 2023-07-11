'use strict';

const crypto = require('crypto');
const vm = require('vm');
const logger = require('./logger');
const settings = require('./settings');

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
        this.logger = logger.child({ component: 'subscript', subscript: this.name });
        this.fn = getCompiledScript(code);

        this.localLogger = {};
        for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']) {
            this.localLogger[level] = msg => {
                this.logger[level](msg);
            };
        }
    }

    async exec(payload) {
        if (!this.fn) {
            throw new Error('Subscript not compiled');
        }

        let start = Date.now();

        try {
            let scriptEnv = await settings.get('scriptEnv');
            let env = {};
            if (scriptEnv && typeof scriptEnv === 'string' && scriptEnv.length) {
                env = JSON.parse(scriptEnv);
            }

            let ctx = {
                payload: payload ? pfStructuredClone(payload) : {},
                fetch: wrappedFetch,
                URL,
                logger: this.localLogger,
                env
            };

            this.logger.trace({ msg: 'Executing sub-script' });

            vm.createContext(ctx);
            let result = await this.fn.runInContext(ctx, {
                timeout: SUBSCRIPT_RUNTIME_TIMEOUT,
                microtaskMode: 'afterEvaluate'
            });

            this.logger.trace({ msg: 'Sub-script executed', duration: Date.now() - start });
            return result;
        } catch (err) {
            this.logger.error({ msg: 'Sub-script execution failed', duration: Date.now() - start, err });
            throw err;
        }
    }
}

module.exports = { SubScript };
