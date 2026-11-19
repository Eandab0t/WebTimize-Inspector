import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { after, before, test } from "node:test";
import { createStaticServer } from "../src/core/local-server.js";
import { verifyManifest } from "../src/report/compressor.js";
import { compareReports, renderComparisonHtml, renderHtml } from "../src/report/report.js";
import { createFinding } from "../src/core/findings.js";
import { runScan } from "../src/core/scanner.js";

let server;
let temp;
before(async () => {
  server = await createStaticServer(path.resolve("fixtures/local-site"));
  temp = await fs.mkdtemp(path.join(os.tmpdir(), "webtim-inspector-test-"));
});
after(async () => {
  if (server) await server.close();
  if (temp) await fs.rm(temp, { recursive: true, force: true });
});

test("HTML reports escape untrusted values and include the reproducible report JSON", async () => {
  const report = await runScan({ url: server.url, allowPrivate: true, categories: ["security"], runs: 1 });
  const html = renderHtml({ ...report, target: { ...report.target, requestedUrl: "<script>alert(1)</script>" } });
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /application\/json/);
  assert.match(html, /<strong>Viewport:<\/strong> 1440×900/);
});

test("manifest verification checks bytes and MIME type without importing Compressor", async () => {
  const css = await fs.readFile(path.resolve("fixtures/local-site/styles.css"));
  const hash = createHash("sha256").update(css).digest("hex");
  const manifestPath = path.join(temp, "manifest.json");
  await fs.writeFile(manifestPath, JSON.stringify({
    schema_version: 1,
    assets: [{ original: "styles.css", final: "styles.css", sha256: hash, type: "text/css" }]
  }));
  const good = await verifyManifest(manifestPath, server.url, { allowPrivate: true });
  assert.equal(good.summary.failures, 0);
  assert.equal(good.assets[0].hashMatch, true);
  assert.equal(good.assets[0].typeMatch, true);

  await fs.writeFile(manifestPath, JSON.stringify({
    schema_version: 1,
    assets: [{ original: "styles.css", final: "styles.css", sha256: "0".repeat(64), type: "text/css" }]
  }));
  const bad = await verifyManifest(manifestPath, server.url, { allowPrivate: true });
  assert.equal(bad.summary.failures, 1);
  assert.equal(bad.assets[0].hashMatch, false);
});

test("manifest verification refuses entries that would select another origin or escape the root", async () => {
  const css = await fs.readFile(path.resolve("fixtures/local-site/styles.css"));
  const cssHash = createHash("sha256").update(css).digest("hex");
  let attackHits = 0;
  const attackServer = http.createServer((request, response) => {
    attackHits += 1;
    response.writeHead(200, { "content-type": "text/css" });
    response.end("body{color:red}");
  });
  await new Promise((resolve) => attackServer.listen(0, "127.0.0.1", resolve));
  const attack = `127.0.0.1:${attackServer.address().port}`;
  // The `..` and same-origin absolute entries resolve to the base fixture origin, so record
  // what the base server is actually asked for: only the one good asset may appear.
  const baseRequests = [];
  const recordBase = (request) => baseRequests.push(request.url);
  server.server.on("request", recordBase);
  try {
    const entry = (final, original = "x.css") => ({ original, final, sha256: cssHash, type: "text/css" });
    const manifestPath = path.join(temp, "manifest-traversal.json");
    await fs.writeFile(manifestPath, JSON.stringify({
      schema_version: 1,
      assets: [
        entry("styles.css", "styles.css"),
        entry(`http://${attack}/steal.css`),
        entry(`//${attack}/protocol-relative.css`),
        entry("../../outside.css"),
        entry("..\\..\\outside.css"),
        entry("%2e%2e%2foutside.css"),
        entry("%2E%2E/outside.css"),
        entry(`${server.url}styles.css`)
      ]
    }));
    const result = await verifyManifest(manifestPath, server.url, { allowPrivate: true });
    assert.deepEqual(baseRequests, ["/styles.css"], "only the good relative entry may reach the base origin");
    assert.equal(attackHits, 0, "a manifest-supplied origin must never be requested");
    assert.equal(result.summary.total, 8);
    assert.equal(result.summary.failures, 7);
    assert.equal(result.assets[0].error, null);
    assert.equal(result.assets[0].hashMatch, true);
    assert.equal(result.assets[0].typeMatch, true);
    for (const bad of result.assets.slice(1)) {
      assert.match(bad.error, /^invalid manifest entry:/);
      assert.equal(bad.status, null);
      assert.equal(bad.url, null);
    }
  } finally {
    server.server.off("request", recordBase);
    await new Promise((resolve) => attackServer.close(resolve));
  }
});

test("manifest verification treats an asset name with # as a file path, not a fragment", async () => {
  const body = "logo bytes";
  const requested = [];
  const hashServer = http.createServer((request, response) => {
    requested.push(request.url);
    response.writeHead(200, { "content-type": "image/png" });
    response.end(body);
  });
  await new Promise((resolve) => hashServer.listen(0, "127.0.0.1", resolve));
  try {
    const manifestPath = path.join(temp, "manifest-hash-name.json");
    await fs.writeFile(manifestPath, JSON.stringify({
      schema_version: 1,
      assets: [{
        original: "img/logo#1.png",
        final: "img/logo#1.a4bcd7b8.png",
        sha256: createHash("sha256").update(body).digest("hex"),
        type: "image/png"
      }]
    }));
    const result = await verifyManifest(manifestPath, `http://127.0.0.1:${hashServer.address().port}`, { allowPrivate: true });
    assert.deepEqual(requested, ["/img/logo%231.a4bcd7b8.png"]);
    assert.equal(result.summary.failures, 0);
    assert.equal(result.assets[0].hashMatch, true);
    assert.equal(result.assets[0].typeMatch, true);
  } finally {
    await new Promise((resolve) => hashServer.close(resolve));
  }
});

test("manifest verification encodes a percent in an asset name instead of letting a server decode it", async () => {
  const body = "body{color:#010203}";
  const requested = [];
  const percentServer = http.createServer((request, response) => {
    requested.push(request.url);
    response.writeHead(200, { "content-type": "text/css" });
    response.end(body);
  });
  await new Promise((resolve) => percentServer.listen(0, "127.0.0.1", resolve));
  try {
    const manifestPath = path.join(temp, "manifest-percent-name.json");
    await fs.writeFile(manifestPath, JSON.stringify({
      schema_version: 1,
      assets: [{
        original: "css/a%2eb.css",
        final: "css/a%2eb.722ba28f.css",
        sha256: createHash("sha256").update(body).digest("hex"),
        type: "text/css"
      }]
    }));
    const result = await verifyManifest(manifestPath, `http://127.0.0.1:${percentServer.address().port}`, { allowPrivate: true });
    assert.deepEqual(requested, ["/css/a%252eb.722ba28f.css"]);
    assert.equal(result.summary.failures, 0);
    assert.equal(result.assets[0].hashMatch, true);
    assert.equal(result.assets[0].typeMatch, true);
  } finally {
    await new Promise((resolve) => percentServer.close(resolve));
  }
});

test("manifest verification accepts the JavaScript MIME spelling real servers send", async () => {
  const body = "console.log('contract');\n";
  const jsServer = http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
    response.end(body);
  });
  await new Promise((resolve) => jsServer.listen(0, "127.0.0.1", resolve));
  try {
    const manifestPath = path.join(temp, "manifest-js.json");
    await fs.writeFile(manifestPath, JSON.stringify({
      schema_version: 1,
      assets: [{
        original: "js/app.js",
        final: "js/app.js",
        sha256: createHash("sha256").update(body).digest("hex"),
        type: "text/javascript"
      }]
    }));
    const result = await verifyManifest(manifestPath, `http://127.0.0.1:${jsServer.address().port}`, { allowPrivate: true });
    assert.equal(result.summary.failures, 0);
    assert.equal(result.assets[0].hashMatch, true);
    assert.equal(result.assets[0].typeMatch, true);
  } finally {
    await new Promise((resolve) => jsServer.close(resolve));
  }
});

test("finding fingerprints survive an ephemeral local port change", () => {
  const first = createFinding({
    ruleId: "same-rule", category: "security", title: "Same rule", description: "Evidence",
    severity: "low", url: "http://127.0.0.1:50000/"
  });
  const second = createFinding({
    ruleId: "same-rule", category: "security", title: "Same rule", description: "Evidence",
    severity: "low", url: "http://127.0.0.1:50001/"
  });
  assert.equal(first.id, second.id);
  assert.equal(first.ruleId, "security.same-rule");
});

test("comparison distinguishes new, absent and persistent findings", () => {
  const finding = (id, title, severity = "medium") => ({
    id, title, severity, ruleId: `test.${id}`, category: "test"
  });
  const before = {
    scanId: "before",
    target: { requestedUrl: "https://example.com" },
    startedAt: "2026-01-01T00:00:00.000Z",
    findings: [finding("same", "Same"), finding("gone", "Gone")],
    categories: { performance: { metrics: { lcpMs: { median: 3000 }, cls: { median: 0.2 } } } }
  };
  const after = {
    scanId: "after",
    target: { requestedUrl: "https://example.com" },
    startedAt: "2026-01-02T00:00:00.000Z",
    findings: [finding("same", "Same"), finding("new", "New", "high")],
    categories: { performance: { metrics: { lcpMs: { median: 2000 }, cls: { median: 0.1 } } } }
  };
  const comparison = compareReports(before, after);
  assert.equal(comparison.added.length, 1);
  assert.equal(comparison.resolved.length, 1);
  assert.equal(comparison.persistent.length, 1);
  assert.equal(comparison.metricDelta.lcpMs, -1000);
  assert.match(renderComparisonHtml(comparison), /New findings/);
});

test("site comparison keeps findings on unscanned pages out of resolved", () => {
  const finding = (id, pages) => ({
    id, title: id, severity: "medium", ruleId: `test.${id}`, category: "test", affectedPages: pages
  });
  const before = {
    scanId: "before", target: {}, findings: [finding("unscanned", ["https://example.com/a"]), finding("fixed", ["https://example.com/b"])],
    crawl: { pages: [{ url: "https://example.com/a" }, { url: "https://example.com/b" }] }
  };
  const after = {
    scanId: "after", target: {}, findings: [],
    crawl: { pages: [{ url: "https://example.com/b" }] }
  };
  const comparison = compareReports(before, after);
  assert.equal(comparison.resolved.length, 1);
  assert.equal(comparison.resolved[0].id, "fixed");
  assert.equal(comparison.unscannedFindings.length, 1);
  assert.equal(comparison.notScanned[0], "https://example.com/a");
});

test("site comparison treats a local port change as the same page path", () => {
  const finding = {
    id: "same", title: "Same", severity: "medium", ruleId: "test.same", category: "test",
    affectedPages: ["http://127.0.0.1:50000/a"]
  };
  const afterFinding = { ...finding, affectedPages: ["http://127.0.0.1:50001/a"] };
  const before = { scanId: "before", target: {}, findings: [finding], crawl: { pages: [{ url: finding.affectedPages[0] }] } };
  const after = { scanId: "after", target: {}, findings: [afterFinding], crawl: { pages: [{ url: afterFinding.affectedPages[0] }] } };
  const comparison = compareReports(before, after);
  assert.equal(comparison.newlyAffected.length, 0);
  assert.equal(comparison.noLongerAffected.length, 0);
  assert.equal(comparison.notScanned.length, 0);
  assert.equal(comparison.persistent.length, 1);
});

test("the committed Compressor 0.3.0 manifest verifies against its own build output", async () => {
  const root = path.resolve("fixtures/compressor-0.3.0");
  const manifestPath = path.join(root, "manifest.json");
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.tool.name, "webtim");
  assert.equal(manifest.tool.version, "0.3.0");
  // Pinned producer output: schema drift in Compressor must show up as a failing fixture test.
  assert.deepEqual(manifest.assets.map((asset) => asset.final).sort(), [
    "css/app.884546c4.css",
    "img/logo-ü.a4bcd7b8.png",
    "img/nested/deep/icon.a4bcd7b8.png",
    "img/pct%2ename.a4bcd7b8.png",
    "img/pic#1.a4bcd7b8.png",
    "img/with space.a4bcd7b8.png",
    "js/main.9c15ce33.js"
  ]);
  const fixtureServer = await createStaticServer(root);
  try {
    const result = await verifyManifest(manifestPath, fixtureServer.url, { allowPrivate: true });
    assert.equal(result.summary.total, 7);
    assert.equal(result.summary.failures, 0);
    for (const asset of result.assets) {
      assert.equal(asset.status, 200, asset.final);
      assert.equal(asset.hashMatch, true, asset.final);
      assert.equal(asset.typeMatch, true, asset.final);
    }
  } finally {
    fixtureServer.server.closeAllConnections();  // fetch keeps sockets alive; do not wait 4s
    await fixtureServer.close();
  }
});
