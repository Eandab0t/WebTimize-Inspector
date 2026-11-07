import assert from "node:assert/strict";
import fs from "node:fs/promises";
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
