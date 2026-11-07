import { createFinding } from "../core/findings.js";
import { formatBytes, hostLabel, summarizeNumber } from "../core/util.js";

const TEXT_TYPES = new Set(["document", "script", "stylesheet", "fetch", "xmlhttprequest"]);

function metricRun(run, targetUrl) {
  const page = run.pageData;
  if (!page) return null;
  const resources = page.resources || [];
  const navigation = page.navigation || {};
  const totalTransfer = (navigation.transferSize || 0) +
    resources.reduce((sum, resource) => sum + (resource.transferSize || 0), 0);
  const interactions = page.perf?.interactions || [];
  return {
    lcp: page.perf?.lcp || null,
    fcp: page.paint?.["first-contentful-paint"] || null,
    cls: Number.isFinite(page.perf?.cls) ? page.perf.cls : null,
    ttfb: navigation.ttfb ?? null,
    load: navigation.load ?? null,
    inpObservation: interactions.length
      ? Math.max(...interactions.map((interaction) => interaction.duration))
      : null,
    longTaskCount: page.perf?.longTasks?.length || 0,
    requestCount: resources.length + (navigation.transferSize !== undefined ? 1 : 0),
    totalTransfer,
    imageBytes: resources.filter((resource) => resource.initiatorType === "img").reduce((sum, resource) => sum + (resource.transferSize || 0), 0),
    scriptBytes: resources.filter((resource) => resource.initiatorType === "script").reduce((sum, resource) => sum + (resource.transferSize || 0), 0),
    styleBytes: resources.filter((resource) => ["css", "link"].includes(resource.initiatorType)).reduce((sum, resource) => sum + (resource.transferSize || 0), 0),
    fontBytes: resources.filter((resource) => ["font", "css"].includes(resource.initiatorType)).reduce((sum, resource) => sum + (resource.transferSize || 0), 0),
    thirdPartyCount: resources.filter((resource) => hostLabel(resource.name) !== hostLabel(targetUrl)).length,
    renderBlocking: resources.filter((resource) => resource.renderBlockingStatus === "blocking").length,
    duplicateResources: [...new Set(resources.map((resource) => resource.name))].filter((name) => resources.filter((resource) => resource.name === name).length > 1).length
  };
}

export function performanceAudit({ browser, http, url }) {
  const findings = [];
  const checks = [];
  const skipped = [
    {
      check: "speed-index",
      reason: "Speed Index requires a filmstrip/Lighthouse capture; this build does not invent a value."
    },
    {
      check: "field-core-web-vitals",
      reason: "This is one or more synthetic lab runs, not 75th-percentile field data from CrUX or RUM."
    }
  ];
  if (!browser?.runs?.length) {
    return { findings, checks: [{ id: "performance", status: "skipped", reason: "browser run failed" }], skipped, metrics: null };
  }

  const runs = browser.runs.map((run) => metricRun(run, url)).filter(Boolean);
  if (!runs.length) {
    return { findings, checks: [{ id: "performance", status: "skipped", reason: "no page timing data" }], skipped, metrics: null };
  }
  const firstPage = browser.runs.find((run) => run.pageData)?.pageData;
  const metrics = {
    lcpMs: summarizeNumber(runs.map((run) => run.lcp)),
    fcpMs: summarizeNumber(runs.map((run) => run.fcp)),
    cls: summarizeNumber(runs.map((run) => run.cls)),
    ttfbMs: summarizeNumber(runs.map((run) => run.ttfb)),
    loadMs: summarizeNumber(runs.map((run) => run.load)),
    inpObservationMs: summarizeNumber(runs.map((run) => run.inpObservation)),
    longTasks: summarizeNumber(runs.map((run) => run.longTaskCount)),
    requests: summarizeNumber(runs.map((run) => run.requestCount)),
    transferBytes: summarizeNumber(runs.map((run) => run.totalTransfer)),
    imageBytes: summarizeNumber(runs.map((run) => run.imageBytes)),
    scriptBytes: summarizeNumber(runs.map((run) => run.scriptBytes)),
    styleBytes: summarizeNumber(runs.map((run) => run.styleBytes)),
    fontBytes: summarizeNumber(runs.map((run) => run.fontBytes)),
    renderBlocking: summarizeNumber(runs.map((run) => run.renderBlocking)),
    duplicateResources: summarizeNumber(runs.map((run) => run.duplicateResources)),
    runs: runs.map((run, index) => ({ run: index + 1, ...run })),
    caveat: "All values are synthetic lab observations from a local Chrome run. They are not field Core Web Vitals."
  };
  const value = (key) => metrics[key]?.median;
  const lcp = value("lcpMs");
  const cls = value("cls");
  const ttfb = value("ttfbMs");
  const longTasks = value("longTasks");
  const requests = value("requests");
  const transfer = value("transferBytes");

  checks.push(
    { id: "performance.lcp", status: lcp === null ? "unavailable" : "observed", value: lcp, unit: "ms" },
    { id: "performance.cls", status: cls === null ? "unavailable" : "observed", value: cls, unit: "score" },
    { id: "performance.inp", status: metrics.inpObservationMs ? "observed-lab-proxy" : "unavailable", value: metrics.inpObservationMs?.median ?? null, unit: "ms" },
    { id: "performance.fcp", status: metrics.fcpMs ? "observed" : "unavailable", value: metrics.fcpMs?.median ?? null, unit: "ms" },
    { id: "performance.ttfb", status: ttfb === null ? "unavailable" : "observed", value: ttfb, unit: "ms" },
    { id: "performance.speed-index", status: "skipped" }
  );

  if (lcp !== null && lcp > 2500) {
    findings.push(createFinding({
      ruleId: "lcp-above-lab-threshold",
      category: "performance",
      title: "Largest Contentful Paint is above the good lab threshold",
      description: `The median lab LCP was ${Math.round(lcp)} ms across ${runs.length} run(s). The 2.5 s Core Web Vitals threshold is a field-data target; exceeding it in one lab run is a signal, not proof of field failure.`,
      severity: lcp > 4000 ? "high" : "medium",
      confidence: "medium",
      evidence: JSON.stringify(metrics.lcpMs),
      url,
      element: firstPage?.perf?.lcpElement ? JSON.stringify(firstPage.perf.lcpElement) : null,
      detection: "Synthetic Chrome PerformanceObserver timing",
      reference: "https://web.dev/articles/lcp",
      remediation: "Reduce server response time, remove render-blocking resources and optimize the largest image or text block. Re-run the same viewport and repeat count after the change.",
      impact: "The main content becomes visible later for users on slower devices and networks.",
      verification: "Repeat the lab scan and compare the median; confirm with real-user monitoring before claiming field compliance."
    }));
  }
  if (cls !== null && cls > 0.1) {
    findings.push(createFinding({
      ruleId: "cls-above-lab-threshold",
      category: "performance",
      title: "Cumulative Layout Shift exceeds the good threshold",
      description: `The median lab CLS was ${cls.toFixed(3)}. This is a synthetic observation and excludes shifts after the observation window.`,
      severity: cls > 0.25 ? "high" : "medium",
      confidence: "medium",
      evidence: JSON.stringify(metrics.cls),
      url,
      detection: "PerformanceObserver layout-shift entries without recent input",
      reference: "https://web.dev/articles/cls",
      remediation: "Reserve dimensions for images, embeds and ads; avoid inserting content above existing content; use font-display correctly.",
      impact: "Content moves while users are reading or tapping, causing misclicks and frustration.",
      verification: "Re-run the scan and inspect layout-shift entries; field verification still needs RUM."
    }));
  }
  if (ttfb !== null && ttfb > 800) {
    findings.push(createFinding({
      ruleId: "slow-ttfb",
      category: "performance",
      title: "Time to First Byte is slow in the lab",
      description: `The median navigation responseStart was ${Math.round(ttfb)} ms. A single localhost or office scan cannot separate server, DNS, network and cache effects.`,
      severity: ttfb > 1800 ? "high" : "medium",
      confidence: "medium",
      evidence: JSON.stringify(metrics.ttfbMs),
      url,
      detection: "Navigation Timing responseStart",
      reference: "https://web.dev/articles/ttfb",
      remediation: "Measure origin latency, cacheability and server processing independently; avoid treating this single synthetic value as a hosting verdict.",
      impact: "Every dependent resource starts later when the first byte is delayed.",
      verification: "Repeat from more than one network vantage point and compare server timing."
    }));
  }
  if (longTasks !== null && longTasks > 5) {
    findings.push(createFinding({
      ruleId: "many-long-tasks",
      category: "performance",
      title: "The page produced multiple long tasks",
      description: `${longTasks} long tasks over 50 ms were observed in the median run. Long tasks can delay input handling; they are not the same metric as INP.`,
      severity: "medium",
      confidence: "medium",
      evidence: JSON.stringify(metrics.longTasks),
      url,
      detection: "PerformanceObserver longtask entries",
      reference: "https://web.dev/articles/tbt",
      remediation: "Split or defer large JavaScript work, reduce third-party scripts and measure interaction latency before changing architecture.",
      impact: "The main thread may be unresponsive during loading and interaction.",
      verification: "Profile the page and repeat with user-like interactions; field INP requires real users."
    }));
  }
  if (transfer !== null && transfer > 3 * 1024 * 1024) {
    findings.push(createFinding({
      ruleId: "large-transfer",
      category: "performance",
      title: "The lab page transferred a large amount of data",
      description: `The median transferred size was ${formatBytes(transfer)} across ${runs.length} run(s). Transfer sizes can be zero or incomplete for cross-origin resources without Timing-Allow-Origin.`,
      severity: "low",
      confidence: "medium",
      evidence: JSON.stringify(metrics.transferBytes),
      url,
      detection: "PerformanceResourceTiming transferSize",
      reference: "https://web.dev/articles/total-byte-weight",
      remediation: "Measure the largest resources, compress text, use appropriately sized images and remove unused dependencies. Compare wire bytes, not only source bytes.",
      impact: "Larger transfers consume more bandwidth and can delay loading on constrained connections.",
      verification: "Compare resource-level transfer sizes before and after a change, then verify with a throttled profile."
    }));
  }
  if (requests !== null && requests > 100) {
    findings.push(createFinding({
      ruleId: "many-requests",
      category: "performance",
      title: "The page issued many requests",
      description: `${requests} requests were counted in the median run. Request count alone is not a defect; HTTP/2, caching and criticality matter.`,
      severity: "low",
      confidence: "high",
      evidence: JSON.stringify(metrics.requests),
      url,
      detection: "PerformanceResourceTiming count plus the navigation request",
      reference: "https://web.dev/articles/resource-loading",
      remediation: "Remove unused resources, consolidate where it does not hurt caching, and prioritize critical requests.",
      impact: "Many requests increase connection and parsing overhead, especially on high-latency networks.",
      verification: "Compare the request list and transfer sizes before and after; verify cache behavior."
    }));
  }
  if (longTasks !== null && longTasks > 0) {
    checks.push({ id: "performance.long-tasks", status: "observed", value: longTasks, unit: "count" });
  }
  if (firstPage) {
    const blocking = firstPage.resources
      .filter((resource) => resource.renderBlockingStatus === "blocking")
      .map((resource) => resource.name);
    if (blocking.length > 2) {
      findings.push(createFinding({
        ruleId: "render-blocking-resources",
        category: "performance",
        title: "Several resources are reported as render-blocking",
        description: `${blocking.length} resources reported renderBlockingStatus=blocking. Browser support for this field varies; the resource list is the evidence.`,
        severity: "medium",
        confidence: "medium",
        evidence: blocking.slice(0, 20).join("\n"),
        url,
        detection: "PerformanceResourceTiming renderBlockingStatus",
        reference: "https://developer.chrome.com/docs/lighthouse/performance/render-blocking-resources/",
        remediation: "Inline critical CSS, defer non-critical scripts and load non-critical styles without blocking first render.",
        impact: "The browser may delay first paint while fetching or parsing these resources.",
        verification: "Re-run the scan and inspect the waterfall; confirm visual correctness after deferral."
      }));
    }
    const uncompressed = firstPage.resources.filter((resource) => {
      const response = browser.runs[0].responses.find((item) => item.url === resource.name);
      const type = response?.type || resource.initiatorType;
      const encoding = response?.headers?.["content-encoding"];
      return TEXT_TYPES.has(type) && resource.transferSize > 10 * 1024 && !encoding;
    });
    if (uncompressed.length) {
      findings.push(createFinding({
        ruleId: "text-resources-without-compression",
        category: "performance",
        title: "Some large text resources were served without content encoding",
        description: `${uncompressed.length} text resource(s) over 10 KiB had no Content-Encoding header in the observed response. Check server/CDN behavior before changing the build.`,
        severity: "medium",
        confidence: "high",
        evidence: uncompressed.slice(0, 12).map((resource) => resource.name).join("\n"),
        url,
        detection: "Response headers matched to PerformanceResourceTiming entries",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding",
        remediation: "Enable Brotli or gzip for HTML, CSS, JavaScript and JSON at the server or CDN. Do not compress already-compressed images.",
        impact: "Uncompressed text can be several times larger on the wire.",
        verification: "Request the same resources with curl/browser devtools and confirm Content-Encoding and Vary."
      }));
    }
    const cacheIssues = firstPage.resources.filter((resource) => {
      const response = browser.runs[0].responses.find((item) => item.url === resource.name);
      if (!response) return false;
      const control = String(response.headers?.["cache-control"] || "").toLowerCase();
      return !control || control.includes("no-store") || control.includes("max-age=0");
    });
    if (cacheIssues.length > 3) {
      findings.push(createFinding({
        ruleId: "limited-static-caching",
        category: "performance",
        title: "Several static resources have no useful cache policy",
        description: `${cacheIssues.length} observed responses had no cache-control, no-store or max-age=0. HTML often needs revalidation; this finding should be reviewed per resource type.`,
        severity: "low",
        confidence: "medium",
        evidence: cacheIssues.slice(0, 12).map((resource) => resource.name).join("\n"),
        url,
        detection: "Observed response Cache-Control headers",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        remediation: "Use immutable long-lived caching for hashed static assets and revalidation for HTML; confirm CDN behavior.",
        impact: "Repeat visitors may re-download resources unnecessarily.",
        verification: "Inspect response headers for each static asset and compare repeat-load transfer sizes."
      }));
    }
    const thirdParty = firstPage.resources.filter((resource) => {
      try {
        return new URL(resource.name).origin !== new URL(url).origin;
      } catch {
        return false;
      }
    });
    if (thirdParty.length) {
      checks.push({ id: "performance.third-party-resources", status: "observed", value: thirdParty.length, unit: "count" });
    }
  }
  return {
    findings,
    checks,
    skipped,
    metrics,
    caveat: "Synthetic lab measurements only. LCP/CLS thresholds describe field 75th-percentile targets; this report does not claim field compliance."
  };
}
