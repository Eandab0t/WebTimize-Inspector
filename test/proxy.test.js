import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { after, before, test } from "node:test";
import { createFixtureServer } from "../fixtures/site-server.js";
import { startValidatingProxy } from "../src/core/proxy.js";
import { UrlPolicy } from "../src/core/url-policy.js";

let fixture;
before(async () => { fixture = await createFixtureServer(); });
after(async () => { if (fixture) await fixture.close(); });

function proxyGet(proxy, target) {
  return new Promise((resolve, reject) => {
    const address = new URL(proxy.url);
    const request = http.request({
      hostname: address.hostname,
      port: address.port,
      path: target,
      headers: { host: new URL(target).host }
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.on("error", reject);
    request.end();
  });
}

function proxyConnect(proxy, target) {
  return new Promise((resolve, reject) => {
    const address = new URL(proxy.url);
    const socket = net.connect(Number(address.port), address.hostname);
    const crlf = String.fromCharCode(13, 10);
    let data = "";
    socket.once("connect", () => socket.write(`CONNECT ${target} HTTP/1.1${crlf}Host: ${target}${crlf}${crlf}`));
    socket.on("data", (chunk) => {
      data += chunk.toString();
      socket.destroy();
      resolve(data);
    });
    socket.on("error", reject);
    socket.setTimeout(3000, () => { socket.destroy(); reject(new Error("proxy connect timeout")); });
  });
}

test("the browser proxy validates HTTP and CONNECT destinations before connecting", async () => {
  const open = await startValidatingProxy({ policy: new UrlPolicy({ allowPrivate: true }) });
  const closed = await startValidatingProxy({ policy: new UrlPolicy() });
  try {
    const response = await proxyGet(open, fixture.url);
    assert.equal(response.status, 200);
    assert.match(response.body, /Controlled audit fixture/);
    const tunnel = await proxyConnect(open, `${fixture.host}:${fixture.port}`);
    assert.match(tunnel, /200 Connection Established/);
    assert.match((await proxyGet(closed, fixture.url)).body, /blocked by Inspector URL policy/);
    assert.match(await proxyConnect(closed, `${fixture.host}:${fixture.port}`), /403 Forbidden/);
    assert.ok(open.stats.httpRequests >= 1);
    assert.ok(open.stats.connections >= 1);
  } finally {
    await open.close();
    await closed.close();
  }
});
