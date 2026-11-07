import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createFixtureServer } from "../fixtures/site-server.js";
import { runScan } from "../src/core/scanner.js";
import { renderHtml } from "../src/report/report.js";

let fixture;
before(async () => { fixture = await createFixtureServer(); });
after(async () => { if (fixture) await fixture.close(); });

test("a scan records real browser, accessibility, SEO and security observations", async () => {
  const report = await runScan({
    url: fixture.url,
    allowPrivate: true,
    categories: ["performance", "accessibility", "seo", "security", "reliability", "privacy"],
    runs: 1,
    maxLinks: 10
  });
  assert.equal(report.status, "complete");
  assert.equal(report.tool.name, "webtim-inspector");
  assert.equal(report.environment.browser.version.startsWith("157."), true);
  assert.equal(report.categories.accessibility.status, "ok");
  assert.equal(report.categories.performance.metrics.lcpMs.count, 1);
  assert.ok(report.categories.performance.metrics.lcpMs.median > 0);
  assert.ok(report.findings.some((finding) => finding.ruleId === "accessibility.image-alt"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "accessibility.label"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "seo.broken-internal-link"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "security.no-https"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "reliability.javascript-exception"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "reliability.broken-image"));
  assert.ok(report.findings.every((finding) => finding.severity && finding.confidence && finding.remediation));
  assert.doesNotMatch(JSON.stringify(report), /fixture=1/);
  assert.match(renderHtml(report), /WebTimize Inspector/);
  assert.doesNotMatch(renderHtml(report), /<script>alert/);
});

test("multiple runs expose individual results and variation", async () => {
  const report = await runScan({
    url: fixture.url,
    allowPrivate: true,
    categories: ["performance"],
    runs: 2,
    viewport: "390x844"
  });
  assert.equal(report.configuration.runs, 2);
  assert.equal(report.categories.performance.metrics.lcpMs.count, 2);
  assert.equal(report.categories.performance.metrics.runs.length, 2);
  assert.equal(report.categories.performance.metrics.runs[1].run, 2);
  assert.ok(report.categories.performance.checks.some((check) => check.id === "performance.speed-index" && check.status === "skipped"));
});

test("the browser request guard blocks an SSRF metadata subresource", async () => {
  const report = await runScan({
    url: new URL("/ssrf.html", fixture.url).href,
    allowPrivate: true,
    categories: ["reliability"],
    runs: 1,
    timeoutMs: 20_000
  });
  assert.ok(report.findings.some((finding) => finding.ruleId === "reliability.blocked-by-policy"));
  assert.match(report.findings.find((finding) => finding.ruleId === "reliability.blocked-by-policy").evidence, /169\.254\.169\.254/);
});

test("the default policy rejects a local target", async () => {
  await assert.rejects(
    () => runScan({ url: fixture.url, categories: ["security"] }),
    /blocked|private/i
  );
});
