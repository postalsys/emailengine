'use strict';

// Stand-ins for the network the autodiscovery resolvers reach, shared by the autodetect test files

// A DNS answer for a name that does not exist
const notFound = () => Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));

// A stand-in response carrying a text body, like the one runAutodiscovery's stubs return
const textResponse = (status, body) => ({ ok: status >= 200 && status < 300, status, url: '', headers: { get: () => null }, text: async () => body || '' });

// A minimal Mozilla autoconfig document naming an IMAP server, optionally padded past the size cap
const autoconfigDoc = (host, padding) => `<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <!--${padding || ''}-->
  <emailProvider id="example.com">
    <incomingServer type="imap"><hostname>${host}</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
  </emailProvider>
</clientConfig>`;

module.exports = { notFound, textResponse, autoconfigDoc };
