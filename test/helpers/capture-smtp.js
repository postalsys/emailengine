'use strict';

// An SMTP server that accepts everything and keeps it, for tiers that need to see what EmailEngine
// delivered through an account's own SMTP settings.

const { SMTPServer } = require('smtp-server');

async function startCaptureSmtp() {
    const received = [];
    const smtp = new SMTPServer({
        authOptional: true,
        disabledCommands: ['STARTTLS'],
        logger: false,
        onAuth(auth, session, callback) {
            callback(null, { user: auth.username });
        },
        onData(stream, session, callback) {
            const chunks = [];
            stream.on('data', chunk => chunks.push(chunk));
            stream.on('end', () => {
                received.push({
                    receivedAt: Date.now(),
                    from: session.envelope.mailFrom && session.envelope.mailFrom.address,
                    to: session.envelope.rcptTo.map(rcpt => rcpt.address),
                    raw: Buffer.concat(chunks).toString('utf8')
                });
                callback();
            });
        }
    });
    await new Promise(resolve => smtp.listen(0, '127.0.0.1', resolve));
    return {
        port: smtp.server.address().port,
        received,
        close: () => new Promise(resolve => smtp.close(resolve))
    };
}

module.exports = { startCaptureSmtp };
