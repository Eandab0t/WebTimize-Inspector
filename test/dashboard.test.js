import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { startDashboard } from "../src/ui/dashboard.js";

test("dashboard is loopback-only, token-protected and returns a real local scan", async () => {
  const dashboard = await startDashboard({ port: 0 });
  const base = dashboard.url;
  try {
    const page = await fetch(base);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /WebTimize Inspector/);
    assert.match(html, /data-token=/);

    const noToken = await fetch(`${base}/api/health`);
    assert.equal(noToken.status, 403);

    const headers = { "content-type": "application/json", "x-inspector-token": dashboard.token, origin: base };
    const scan = await fetch(`${base}/api/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        localDir: path.resolve("fixtures/local-site"),
        categories: ["security"],
        runs: 1
      })
    });
    assert.equal(scan.status, 202);
    const { id } = await scan.json();
    let body;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const response = await fetch(`${base}/api/scans/${id}`, {
        headers: { "x-inspector-token": dashboard.token }
      });
      body = await response.json();
      if (body.job?.status !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(body.job.status, "done");
    assert.ok(body.report);
    assert.equal(body.report.status, "complete");
    assert.ok(body.report.findings.some((finding) => finding.ruleId === "security.no-https"));

    const report = await fetch(`${base}/api/report/${body.report.scanId}`, {
      headers: { "x-inspector-token": dashboard.token }
    });
    assert.equal(report.status, 200);
    assert.match(report.headers.get("content-type"), /application\/json/);
    assert.equal((await report.json()).scanId, body.report.scanId);

    const history = await (await fetch(`${base}/api/scans`, {
      headers: { "x-inspector-token": dashboard.token }
    })).json();
    const historyEntry = history.scans.find((entry) => entry.scanId === body.report.scanId);
    assert.ok(historyEntry);
    assert.match(historyEntry.url, /^http:\/\/127\.0\.0\.1:/);

    const compare = await fetch(`${base}/api/compare?before=${body.report.scanId}&after=${body.report.scanId}`, {
      headers: { "x-inspector-token": dashboard.token }
    });
    assert.equal(compare.status, 200);
    assert.equal((await compare.json()).persistent.length, body.report.findings.length);

    const crossOrigin = await fetch(`${base}/api/scan`, {
      method: "POST",
      headers: { ...headers, origin: "http://evil.example" },
      body: JSON.stringify({ url: "https://example.com" })
    });
    assert.equal(crossOrigin.status, 403);
  } finally {
    await new Promise((resolve) => dashboard.server.close(resolve));
  }
});

test("dashboard accepts a bounded site crawl and exposes its page coverage", async () => {
  const dashboard = await startDashboard({ port: 0 });
  const headers = { "content-type": "application/json", "x-inspector-token": dashboard.token, origin: dashboard.url };
  try {
    const response = await fetch(`${dashboard.url}/api/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        localDir: path.resolve("fixtures/local-site"),
        categories: ["security"],
        crawl: true,
        maxPages: 2,
        maxDepth: 2
      })
    });
    assert.equal(response.status, 202);
    const { id } = await response.json();
    let body;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      body = await (await fetch(`${dashboard.url}/api/scans/${id}`, {
        headers: { "x-inspector-token": dashboard.token }
      })).json();
      if (body.job?.status !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(body.job.kind, "crawl");
    assert.equal(body.job.status, "done");
    assert.ok(body.job.coverage.audited >= 2);
    assert.ok(body.job.coverage.discovered >= 2);
    assert.equal(body.report.target.scope, "site");
    assert.ok(body.report.crawl.pages.length >= 2);
    assert.ok(body.report.crawl.coverage.discovered >= 2);
  } finally {
    await new Promise((resolve) => dashboard.server.close(resolve));
  }
});

test("dashboard cancellation stops a running crawl and saves a partial report", async () => {
  const dashboard = await startDashboard({ port: 0 });
  const headers = { "content-type": "application/json", "x-inspector-token": dashboard.token, origin: dashboard.url };
  try {
    const response = await fetch(`${dashboard.url}/api/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        localDir: path.resolve("fixtures/local-site"),
        categories: ["performance", "accessibility", "seo", "security", "reliability", "privacy"],
        crawl: true,
        maxPages: 25,
        maxDepth: 2
      })
    });
    assert.equal(response.status, 202);
    const { id } = await response.json();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const cancel = await fetch(`${dashboard.url}/api/scans/${id}/cancel`, {
      method: "POST",
      headers,
      body: "{}"
    });
    assert.equal(cancel.status, 202);
    let body;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      body = await (await fetch(`${dashboard.url}/api/scans/${id}`, {
        headers: { "x-inspector-token": dashboard.token }
      })).json();
      if (body.job?.status !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(body.job.status, "cancelled");
    assert.equal(body.report.status, "partial");
    assert.equal(body.report.crawl.cancelled, true);
  } finally {
    await new Promise((resolve) => dashboard.server.close(resolve));
  }
});
