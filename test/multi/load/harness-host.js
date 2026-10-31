'use strict';

// The ImapKit farm and the webhook ledger in a process of their own, driven over IPC by the load and
// chaos runners. Kept apart from the load generator so neither the mail servers nor the webhook
// receiver compete with it for the event loop: a latency measured by the generator is EmailEngine's,
// and an injection and its webhook are timed on the same clock, here.

const { startFarm } = require('../../helpers/imapkit-farm');
const { startLedger } = require('../../helpers/webhook-ledger');

let farm;
let ledger;
const injections = [];

const handlers = {
    async start({ accounts, servers }) {
        farm = await startFarm({ accounts, servers });
        ledger = await startLedger();
        return { webhookUrl: ledger.url, imap: Object.fromEntries(accounts.map(account => [account, farm.imapSettings(account)])) };
    },

    /** Injects into one server per call; every account on it receives the message */
    inject({ account, raw, label }) {
        const token = ledger.newToken();
        const subject = ledger.subjectFor(token, label || 'Load message');
        const { injectedAt } = farm.inject(account, raw ? { raw: raw.replace('{{SUBJECT}}', subject) } : { subject });
        for (const recipient of farm.expectedRecipients(account)) {
            injections.push({ account: recipient, token, injectedAt });
        }
        return { token, injectedAt };
    },

    /** Latencies and exactly-once accounting of every injection made since `since` */
    reconcile({ since = 0, settle = 0 } = {}) {
        const relevant = injections.filter(entry => entry.injectedAt >= since && entry.injectedAt <= Date.now() - settle);
        const { latencies, duplicates, missing } = ledger.reconcile(relevant);
        return { injected: relevant.length, latencies, duplicates, missing };
    },

    sessionsPerAccount({ accounts }) {
        return Object.fromEntries(accounts.map(account => [account, farm.sessionsFor(account).length]));
    },

    addRule({ rule, account }) {
        farm.addRule(rule, account);
        return true;
    },

    clearRules() {
        farm.clearRules();
        return true;
    },

    disconnectAll({ serverIndex }) {
        farm.disconnectAll(serverIndex);
        return true;
    },

    serverCount() {
        return farm.servers.length;
    },

    /** CPU this process used, so a run can tell when the harness itself was the limit */
    usage() {
        return { cpu: process.cpuUsage(), uptime: process.uptime() };
    },

    async stop() {
        await farm.stop();
        await ledger.stop();
        return true;
    }
};

process.on('message', async ({ id, cmd, args }) => {
    try {
        const result = await handlers[cmd](args || {});
        process.send({ id, result });
    } catch (err) {
        process.send({ id, error: err.stack || err.message });
    }
});

process.on('disconnect', () => process.exit(0));
