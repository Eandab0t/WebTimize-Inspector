import http from "node:http";
import net from "node:net";

/**
 * A loopback HTTP/CONNECT proxy for the audit browser. Chrome hands it the
 * hostname, the proxy resolves and validates that destination, then connects to
 * the validated address. This closes the browser's independent-DNS gap without
 * changing the scanner's HTTP client.
 */
export async function startValidatingProxy({
  policy,
  timeoutMs = 30_000,
  maxBytes = 5 * 1024 * 1024
} = {}) {
  if (!policy) throw new Error("proxy requires a UrlPolicy");
  const sockets = new Set();
  const stats = { httpRequests: 0, connections: 0, blocked: 0, bytes: 0 };

  const reject = (response, status, message) => {
    if (response.headersSent) return;
    response.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    response.end(message);
  };

  const server = http.createServer(async (request, response) => {
    stats.httpRequests += 1;
    let target;
    try {
      target = new URL(request.url);
    } catch {
      stats.blocked += 1;
      reject(response, 400, "proxy requires an absolute HTTP URL");
      return;
    }
    if (target.protocol !== "http:") {
      stats.blocked += 1;
      reject(response, 400, "only HTTP URLs may use the non-tunnel proxy path");
      return;
    }
    let address;
    try {
      [address] = await policy.resolve(target.href);
    } catch (error) {
      stats.blocked += 1;
      reject(response, 403, `blocked by Inspector URL policy: ${error.message}`);
      return;
    }
    const upstream = http.request({
      hostname: address,
      port: Number(target.port) || 80,
      method: request.method,
      path: `${target.pathname}${target.search}`,
      headers: { ...request.headers, host: target.host },
      timeout: timeoutMs,
      agent: false
    }, (upstreamResponse) => {
      let responseBytes = 0;
      response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
      upstreamResponse.on("data", (chunk) => {
        responseBytes += chunk.length;
        stats.bytes += chunk.length;
        if (responseBytes > maxBytes) {
          upstreamResponse.destroy();
          response.destroy();
        }
      });
      upstreamResponse.pipe(response);
    });
    upstream.on("timeout", () => upstream.destroy(new Error("proxy upstream timeout")));
    upstream.on("error", (error) => {
      if (!response.headersSent) reject(response, 502, `proxy upstream failed: ${error.message}`);
      else response.destroy();
    });
    request.pipe(upstream);
  });

  server.on("connect", async (request, clientSocket, head) => {
    stats.connections += 1;
    let target;
    try {
      target = new URL(`https://${request.url}`);
    } catch {
      stats.blocked += 1;
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    let address;
    try {
      [address] = await policy.resolve(target.href);
    } catch (error) {
      stats.blocked += 1;
      clientSocket.end(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n`);
      return;
    }
    const upstream = net.connect({
      host: address,
      port: Number(target.port) || 443
    });
    upstream.setTimeout(timeoutMs, () => upstream.destroy(new Error("proxy tunnel timeout")));
    upstream.once("connect", () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on("error", () => {
      if (!clientSocket.destroyed) clientSocket.destroy();
    });
    clientSocket.on("error", () => upstream.destroy());
  });

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    stats,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}
