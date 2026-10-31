'use strict';

// Starts test/multi/load/harness-host.js and calls it

const { fork } = require('node:child_process');
const path = require('node:path');

function startHarnessHost() {
    const child = fork(path.join(__dirname, 'harness-host.js'), [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    const pending = new Map();
    let seq = 0;

    child.on('message', ({ id, result, error }) => {
        const entry = pending.get(id);
        if (!entry) {
            return;
        }
        pending.delete(id);
        if (error) {
            entry.reject(new Error(error));
        } else {
            entry.resolve(result);
        }
    });
    child.on('exit', code => {
        for (const entry of pending.values()) {
            entry.reject(new Error(`Harness host exited with ${code}`));
        }
        pending.clear();
    });
    process.on('exit', () => child.kill('SIGKILL'));

    const call = (cmd, args) =>
        new Promise((resolve, reject) => {
            const id = ++seq;
            pending.set(id, { resolve, reject });
            child.send({ id, cmd, args });
        });

    return {
        call,
        async stop() {
            await call('stop').catch(() => false);
            child.kill();
        }
    };
}

module.exports = { startHarnessHost };
