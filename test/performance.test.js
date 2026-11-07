import assert from "node:assert/strict";
import test from "node:test";
import { performanceAudit } from "../src/audits/performance.js";

function page({ lcp = 3000, cls = 0.2, resources = [], blocking = 1, longTasks = 6 } = {}) {
  return {
    title: "Synthetic",
    navigation: { ttfb: 100, load: 4500, transferSize: 1000 },
    paint: { "first-contentful-paint": 1200 },
    perf: { lcp, cls, longTasks: Array.from({ length: longTasks }, () => ({ duration: 60 })), interactions: [] },
    resources,
    scripts: [],
    links: [],
    images: [],
    headings: [],
    meta: {},
    structuredData: [],
    viewport: { clientWidth: 1440, scrollWidth: 1440 },
    renderBlocking: blocking
  };
}

test("lab thresholds become findings while remaining explicitly synthetic", () => {
  const resources = Array.from({ length: 12 }, (_, index) => ({
    name: `https://example.com/app-${index}.js`,
    initiatorType: "script",
    transferSize: 20_000,
    renderBlockingStatus: index < 3 ? "blocking" : null
  }));
  const browser = {
    runs: [{
      pageData: page({ resources }),
      responses: resources.map((resource) => ({
        url: resource.name,
        type: "script",
        headers: { "content-type": "text/javascript", "cache-control": "no-cache" }
      }))
    }]
  };
  const result = performanceAudit({ browser, http: { ok: true }, url: "https://example.com/" });
  assert.ok(result.findings.some((finding) => finding.ruleId === "performance.lcp-above-lab-threshold"));
  assert.ok(result.findings.some((finding) => finding.ruleId === "performance.cls-above-lab-threshold"));
  assert.ok(result.findings.some((finding) => finding.ruleId === "performance.render-blocking-resources"));
  assert.match(result.caveat, /Synthetic lab/);
  assert.equal(result.metrics.lcpMs.median, 3000);
});

test("a fast run does not invent performance findings", () => {
  const browser = {
    runs: [{
      pageData: page({ lcp: 500, cls: 0, resources: [], blocking: 0, longTasks: 0 }),
      responses: []
    }]
  };
  const result = performanceAudit({ browser, http: { ok: true }, url: "https://example.com/" });
  assert.equal(result.findings.length, 0);
  assert.equal(result.checks.find((check) => check.id === "performance.speed-index").status, "skipped");
});
