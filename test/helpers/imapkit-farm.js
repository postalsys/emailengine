'use strict';

// A farm of in-memory ImapKit servers for the multi-instance tier and the load and chaos runs.
//
// ImapKit keeps one mailbox tree per server and every user of a server sees it, so a message
// injected into a server lands in the INBOX of every account placed on that server. A test that
// wants one webhook per injected message gives every account its own server (servers equal to
// accounts); a load run with more accounts than servers expects one webhook per account on the
// server instead. expectedRecipients() answers that question either way.
//
// Accounts are placed round robin: account i lives on server i % servers, as user `user<i>`.

const imapkit = require('imapkit');

// What EmailEngine negotiates against a real server, minus nothing it depends on. QRESYNC is left
// out on purpose: ImapKit's strict VANISHED handling is not what this tier is about.
const PLUGINS = ['IDLE', 'ID', 'ENABLE', 'UIDPLUS', 'MOVE', 'SPECIAL-USE', 'CONDSTORE', 'UNSELECT', 'LITERALPLUS'];

const PASSWORD = 'pass';

// A Sent and a Trash folder so submit and move flows have somewhere to go
const STORAGE = {
    INBOX: {},
    '': {
        separator: '/',
        folders: {
            Sent: { 'special-use': '\\Sent' },
            Trash: { 'special-use': '\\Trash' }
        }
    }
};

/**
 * @param {Object} opts
 * @param {string[]} opts.accounts - EmailEngine account ids, in placement order
 * @param {number} [opts.servers] - Server count, defaults to one per account
 * @param {Object[]} [opts.script] - ImapKit script rules every server starts with
 * @returns {Promise<Object>} The farm
 */
async function startFarm({ accounts, servers, script }) {
    const serverCount = Math.max(1, Math.min(servers || accounts.length, accounts.length));
    const placement = new Map();
    const usersPerServer = Array.from({ length: serverCount }, () => ({}));

    accounts.forEach((account, i) => {
        const serverIndex = i % serverCount;
        const user = `user${i}`;
        placement.set(account, { serverIndex, user });
        usersPerServer[serverIndex][user] = { password: PASSWORD };
    });

    const farmServers = [];
    for (let i = 0; i < serverCount; i++) {
        const server = imapkit({
            plugins: PLUGINS,
            users: usersPerServer[i],
            storage: JSON.parse(JSON.stringify(STORAGE)),
            script: script || []
        });
        const port = await server.start(0, '127.0.0.1');
        farmServers.push({ server, port, index: i });
    }

    const locate = account => {
        const entry = placement.get(account);
        if (!entry) {
            throw new Error(`Account ${account} is not part of this farm`);
        }
        return Object.assign({ farmServer: farmServers[entry.serverIndex] }, entry);
    };

    return {
        servers: farmServers,

        /**
         * The `imap` block for POST /v1/account. SMTP is pointed at nothing reachable on purpose:
         * the tier delivers through a capture server it configures itself when it needs to
         */
        imapSettings(account) {
            const { farmServer, user } = locate(account);
            return {
                host: '127.0.0.1',
                port: farmServer.port,
                secure: false,
                // The farm speaks cleartext: the tier measures the cluster, not TLS handshakes
                requireTLS: false,
                auth: { user, pass: PASSWORD }
            };
        },

        /**
         * Adds a message the way an MTA would, returning the time it was added so latency is
         * measured from the moment the message existed
         */
        inject(account, { subject, body, from, to, raw: rawMessage } = {}) {
            const { farmServer } = locate(account);
            const raw =
                rawMessage ||
                [
                    `From: ${from || 'Sender <sender@example.com>'}`,
                    `To: ${to || 'Recipient <recipient@example.com>'}`,
                    `Subject: ${subject || 'Test message'}`,
                    `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@farm.test>`,
                    `Date: ${new Date().toUTCString()}`,
                    'MIME-Version: 1.0',
                    'Content-Type: text/plain; charset=utf-8',
                    '',
                    body || 'Hello from the ImapKit farm',
                    ''
                ].join('\r\n');
            const injectedAt = Date.now();
            const { uid } = farmServer.server.control.addMessage('INBOX', { raw });
            return { uid, injectedAt, serverIndex: farmServer.index };
        },

        /** Accounts that see a message injected for `account`, see the top of this file */
        expectedRecipients(account) {
            const { serverIndex } = locate(account);
            return accounts.filter(other => placement.get(other).serverIndex === serverIndex);
        },

        /** Open IMAP sessions logged in as the account's user */
        sessionsFor(account) {
            const { farmServer, user } = locate(account);
            return farmServer.server.control.sessions().filter(session => session.user === user);
        },

        /**
         * Adds a script rule to every server, or to the server of one account. Resolves to the
         * handles, each of which has remove()
         */
        addRule(rule, account) {
            const targets = account ? [locate(account).farmServer] : farmServers;
            return targets.map(({ server }) => server.script.add(rule));
        },

        /** Removes every script rule, including the ones the farm started with */
        clearRules() {
            for (const { server } of farmServers) {
                server.script.clear();
            }
        },

        /** Closes every session of one server, or of all of them */
        disconnectAll(serverIndex) {
            const targets = typeof serverIndex === 'number' ? [farmServers[serverIndex]] : farmServers;
            for (const { server } of targets) {
                for (const session of server.control.sessions()) {
                    server.control.disconnect(session.session);
                }
            }
        },

        async stop() {
            await Promise.all(farmServers.map(({ server }) => server.stop().catch(() => false)));
        }
    };
}

module.exports = { startFarm, PASSWORD };
