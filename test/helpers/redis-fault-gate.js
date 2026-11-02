'use strict';

// Answers some Redis commands with an error reply instead of passing them on, for the chaos runs and
// the tests that need a Redis call to fail. Sits inside test/helpers/latency-proxy.js, one gate per
// connection, and understands just enough RESP (2 and 3) to know where every request and reply ends.
//
// A cut or paused connection never fails a command in EmailEngine: ioredis runs with
// maxRetriesPerRequest null, so it queues the command and sends it again once it has reconnected.
// What does reach the code as a failure is an error reply, and Redis sends those in production: OOM
// once maxmemory is reached, for the commands that add data (the ones Redis flags denyoom: SET,
// HSET, ZADD, ... and every script) while reads and deletes still work, and LOADING for everything
// while a restarted Redis loads its dataset. The gate has two kinds: `oom` fails only what a real
// OOM fails, `any` fails any command (OOM for those, LOADING for the rest), which no single real
// condition does but which reaches every error path.
//
// What it never touches, because Redis itself would not fail it or because failing it would make
// the connection behave in a way no real server does:
//   - connection setup (HELLO, AUTH, SELECT, CLIENT, INFO, QUIT, READONLY, PING, SCRIPT)
//   - MULTI, EXEC and DISCARD themselves. A command queued inside MULTI can be failed, and then the
//     transaction goes the way Redis takes it: the command never reaches the server, and the EXEC
//     is sent as DISCARD and answered EXECABORT, so nothing of it is applied (ioredis reports the
//     failed command in the error's previousErrors)
//   - a connection in subscriber mode, which it passes through unparsed from then on
//
// Replies go back in the order the requests came, pipelined or not: an injected error waits for the
// server's replies to the requests sent before it.

const CRLF = Buffer.from('\r\n');

const NEVER = new Set([
    'HELLO',
    'AUTH',
    'SELECT',
    'CLIENT',
    'INFO',
    'QUIT',
    'READONLY',
    'READWRITE',
    'PING',
    'SCRIPT',
    'MULTI',
    'EXEC',
    'DISCARD',
    'WATCH',
    'UNWATCH'
]);
const SUBSCRIBE = new Set(['SUBSCRIBE', 'PSUBSCRIBE', 'SSUBSCRIBE', 'MONITOR']);
const SCRIPTS = new Set(['EVAL', 'EVALSHA', 'EVAL_RO', 'EVALSHA_RO', 'FCALL', 'FCALL_RO']);
// The commands Redis 7 flags denyoom, refused while used memory is over maxmemory; deletes, pops and
// expiries are not among them, a full Redis still lets a client free memory
const DENYOOM =
    /^(SET|SETNX|SETEX|PSETEX|MSET|MSETNX|GETSET|GETEX|APPEND|INCR|INCRBY|INCRBYFLOAT|DECR|DECRBY|SETRANGE|SETBIT|BITFIELD|BITOP|COPY|RESTORE|H(SET|SETNX|MSET|INCRBY|INCRBYFLOAT)|S(ADD|MOVE|INTERSTORE|UNIONSTORE|DIFFSTORE)|Z(ADD|INCRBY|UNIONSTORE|INTERSTORE|DIFFSTORE|RANGESTORE)|L(PUSH|PUSHX|SET|INSERT|MOVE)|R(PUSH|PUSHX|POPLPUSH)|BLMOVE|BRPOPLPUSH|XADD|PFADD|PFMERGE|GEOADD|SORT)$/;

const OOM = Buffer.from("-OOM command not allowed when used memory > 'maxmemory'.\r\n");
const LOADING = Buffer.from('-LOADING Redis is loading the dataset in memory\r\n');
const EXECABORT = Buffer.from('-EXECABORT Transaction discarded because of previous errors.\r\n');
const DISCARD = Buffer.from('*1\r\n$7\r\nDISCARD\r\n');

/**
 * Where the RESP frame starting at `pos` ends
 * @param {Buffer} buf
 * @param {number} pos
 * @returns {number} The index after the frame, -1 while it is incomplete
 * @throws {Error} On something that is not RESP 2 or 3 (a streamed string, say)
 */
function frameEnd(buf, pos) {
    if (pos >= buf.length) {
        return -1;
    }
    const lineEnd = buf.indexOf(CRLF, pos);
    if (lineEnd < 0) {
        return -1;
    }
    const type = String.fromCharCode(buf[pos]);
    const header = buf.toString('latin1', pos + 1, lineEnd);
    let next = lineEnd + 2;
    switch (type) {
        case '+':
        case '-':
        case ':':
        case '_':
        case '#':
        case ',':
        case '(':
            return next;
        case '$':
        case '!':
        case '=': {
            const length = parseCount(header);
            if (length < 0) {
                return next;
            }
            const end = next + length + 2;
            return end > buf.length ? -1 : end;
        }
        case '*':
        case '~':
        case '>':
        case '%':
        case '|': {
            const count = parseCount(header);
            const elements = type === '%' || type === '|' ? count * 2 : count;
            for (let i = 0; i < elements; i++) {
                next = frameEnd(buf, next);
                if (next < 0) {
                    return -1;
                }
            }
            return next;
        }
        default:
            throw new Error(`Not a RESP frame: ${JSON.stringify(type)}`);
    }
}

function parseCount(header) {
    if (!/^-?\d+$/.test(header)) {
        throw new Error(`Bad RESP length ${JSON.stringify(header)}`);
    }
    return Number(header);
}

/**
 * The upper-cased command name of a request frame (an array of bulk strings)
 * @param {Buffer} frame
 * @returns {string}
 */
function commandName(frame) {
    if (frame[0] !== 0x2a) {
        throw new Error('Not a request');
    }
    const first = frame.indexOf(CRLF) + 2;
    const lineEnd = frame.indexOf(CRLF, first);
    const length = parseCount(frame.toString('latin1', first + 1, lineEnd));
    return frame.toString('latin1', lineEnd + 2, lineEnd + 2 + length).toUpperCase();
}

class RespFaultGate {
    /**
     * @param {Object} opts
     * @param {Function} opts.toServer - (chunk) sends bytes on to Redis
     * @param {Function} opts.toClient - (chunk) sends bytes back to the client
     * @param {Function} opts.decide - (command) => Buffer of the error reply to answer with, or null
     */
    constructor({ toServer, toClient, decide }) {
        this.toServer = toServer;
        this.toClient = toClient;
        this.decide = decide;
        this.fromClientBuf = Buffer.alloc(0);
        this.fromServerBuf = Buffer.alloc(0);
        // One entry per request still owed a reply: { reply: Buffer } answered here, { server: true }
        // waiting for Redis, { server: true, replace } waiting for Redis but answered with `replace`
        this.pending = [];
        this.inTransaction = false;
        // A command of the open transaction was failed, so its EXEC is answered EXECABORT
        this.transactionFailed = false;
        this.passthrough = false;
        this.passthroughWhenDrained = false;
    }

    fromClient(chunk) {
        if (this.passthrough) {
            return this.toServer(chunk);
        }
        this.fromClientBuf = this.fromClientBuf.length ? Buffer.concat([this.fromClientBuf, chunk]) : chunk;
        let pos = 0;
        try {
            for (;;) {
                const end = frameEnd(this.fromClientBuf, pos);
                if (end < 0) {
                    break;
                }
                this.onRequest(this.fromClientBuf.subarray(pos, end));
                pos = end;
                if (this.passthrough) {
                    break;
                }
            }
        } catch {
            // Something the gate does not understand: stop interfering with this connection
            this.passthrough = true;
        }
        const rest = this.fromClientBuf.subarray(pos);
        this.fromClientBuf = Buffer.alloc(0);
        if (this.passthrough && rest.length) {
            this.toServer(rest);
        } else if (rest.length) {
            this.fromClientBuf = Buffer.from(rest);
        }
    }

    onRequest(frame) {
        const command = commandName(frame);

        if (SUBSCRIBE.has(command)) {
            // Its replies (and everything after them) are pushes the gate does not track
            this.toServer(frame);
            if (this.pending.length) {
                this.passthroughWhenDrained = true;
            } else {
                this.passthrough = true;
            }
            return;
        }

        if (this.passthroughWhenDrained) {
            // Still owed a reply ahead of the subscription, so still counted
            this.toServer(frame);
            this.pending.push({ server: true });
            return;
        }

        if (command === 'MULTI') {
            this.inTransaction = true;
            this.transactionFailed = false;
        } else if (command === 'DISCARD') {
            this.inTransaction = false;
        } else if (command === 'EXEC') {
            this.inTransaction = false;
            if (this.transactionFailed) {
                this.toServer(DISCARD);
                this.pending.push({ server: true, replace: EXECABORT });
                return;
            }
        } else if (!NEVER.has(command)) {
            const reply = this.decide(command);
            if (reply) {
                this.transactionFailed = this.transactionFailed || this.inTransaction;
                this.pending.push({ reply });
                this.flush();
                return;
            }
        }

        this.toServer(frame);
        this.pending.push({ server: true });
    }

    fromServer(chunk) {
        if (this.passthrough) {
            return this.toClient(chunk);
        }
        this.fromServerBuf = this.fromServerBuf.length ? Buffer.concat([this.fromServerBuf, chunk]) : chunk;
        let pos = 0;
        try {
            for (;;) {
                const end = frameEnd(this.fromServerBuf, pos);
                if (end < 0) {
                    break;
                }
                this.onReply(this.fromServerBuf.subarray(pos, end));
                pos = end;
                if (this.passthrough) {
                    break;
                }
            }
        } catch {
            this.passthrough = true;
        }
        const rest = this.fromServerBuf.subarray(pos);
        this.fromServerBuf = Buffer.alloc(0);
        if (this.passthrough && rest.length) {
            this.toClient(rest);
        } else if (rest.length) {
            this.fromServerBuf = Buffer.from(rest);
        }
    }

    onReply(frame) {
        const type = frame[0];
        // A push (RESP3) answers no request, and an attribute comes ahead of the reply it describes
        if (type === 0x3e || type === 0x7c) {
            this.toClient(frame);
            return;
        }
        const entry = this.pending.shift();
        this.toClient(entry && entry.replace ? entry.replace : frame);
        this.flush();
    }

    /** Sends the injected replies that are next in line */
    flush() {
        while (this.pending.length && this.pending[0].reply) {
            this.toClient(this.pending.shift().reply);
        }
        if (!this.pending.length && this.passthroughWhenDrained) {
            this.passthroughWhenDrained = false;
            this.passthrough = true;
        }
    }
}

/**
 * A decide() for RespFaultGate: fails `rate` of the eligible commands
 * @param {Object} faults - Read on every call, so it can be changed while connections are open:
 *   `rate` (0..1), `kind` ('oom', the default: only what a real OOM refuses; 'any': any command,
 *   OOM for those and LOADING for the rest), `random` (() => number), optional `only` (a Set of
 *   command names), `injected` (incremented per injection)
 * @returns {Function}
 */
function faultDecider(faults) {
    return command => {
        if (!faults.rate || (faults.only && !faults.only.has(command))) {
            return null;
        }
        const oom = SCRIPTS.has(command) || DENYOOM.test(command);
        if (!oom && faults.kind !== 'any') {
            return null;
        }
        if ((faults.random || Math.random)() >= faults.rate) {
            return null;
        }
        faults.injected = (faults.injected || 0) + 1;
        return oom ? OOM : LOADING;
    };
}

module.exports = { RespFaultGate, faultDecider, frameEnd, commandName };
