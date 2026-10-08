'use strict';

const http = require('node:http');
const net = require('node:net');

// Helper: create an HTTP CONNECT proxy server
async function startProxyServer() {
    let connectCount = 0;
    let httpCount = 0;

    const server = http.createServer((req, res) => {
        // Handle plain HTTP requests (non-CONNECT)
        httpCount++;
        const targetUrl = new URL(req.url);
        const proxyReq = http.request(
            {
                hostname: targetUrl.hostname,
                port: targetUrl.port,
                path: targetUrl.pathname + targetUrl.search,
                method: req.method,
                headers: req.headers
            },
            proxyRes => {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                proxyRes.pipe(res);
            }
        );
        req.pipe(proxyReq);
    });

    server.on('connect', (req, clientSocket, head) => {
        connectCount++;
        const [hostname, port] = req.url.split(':');
        const targetSocket = net.connect(Number(port), hostname, () => {
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            if (head.length) {
                targetSocket.write(head);
            }
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
        });
        targetSocket.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => targetSocket.destroy());
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        port,
        url: `http://127.0.0.1:${port}`,
        getConnectCount: () => connectCount,
        getHttpCount: () => httpCount
    };
}

module.exports = { startProxyServer };
