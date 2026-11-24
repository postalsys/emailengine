'use strict';

const http = require('node:http');
const net = require('node:net');

// Helper: create an HTTP CONNECT proxy server. `opts.targetHost` sends every tunnel there instead
// of to the host the client named, for names that only exist in a test.
async function startProxyServer(opts) {
    const { targetHost } = opts || {};
    let connectCount = 0;
    let httpCount = 0;
    // Every CONNECT target as the client named it (`host:port`), and every socket still open
    const requested = [];
    const sockets = new Set();
    const track = socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
    };

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
        requested.push(req.url);
        const [hostname, port] = req.url.split(':');
        const targetSocket = net.connect(Number(port), targetHost || hostname, () => {
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            if (head.length) {
                targetSocket.write(head);
            }
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
        });
        targetSocket.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => targetSocket.destroy());
        track(clientSocket);
        track(targetSocket);
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        port,
        url: `http://127.0.0.1:${port}`,
        getConnectCount: () => connectCount,
        getHttpCount: () => httpCount,
        getRequested: () => requested.slice(),
        // Closes the server along with the tunnels still open through it
        close: () => {
            for (const socket of sockets) {
                socket.destroy();
            }
            return new Promise(resolve => server.close(resolve));
        }
    };
}

module.exports = { startProxyServer };
