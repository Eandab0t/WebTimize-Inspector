import os from "node:os";
import { randomUUID } from "node:crypto";
import { performanceAudit } from "../audits/performance.js";
import { accessibilityAudit } from "../audits/accessibility.js";
import { seoAudit } from "../audits/seo.js";
import { securityAudit } from "../audits/security.js";
import { reliabilityAudit } from "../audits/reliability.js";
import { privacyAudit } from "../audits/privacy.js";
import { inspectHttp } from "./http-audit.js";
import { auditBrowser } from "./browser.js";
import { sortFindings, summarizeCategories, countFindings } from "./findings.js";
import { UrlPolicy } from "./url-policy.js";
import { parseViewport } from "./util.js";
import { VERSION, REPORT_SCHEMA_VERSION } from "./meta.js";

export const CATEGORY_NAMES = ["performance", "accessibility", "seo", "security", "reliability", "privacy"];

function normalizeCategories(value) {
  if (!value || value === "all") return new Set(CATEGORY_NAMES);
  const values = Array.isArray(value) ? value : String(value).split(",");
  const selected = values.map((item) => item.trim()).filter(Boolean);
  const unknown = selected.filter((item) => !CATEGORY_NAMES.includes(item));
  if (unknown.length) throw new Error(`unknown categories: ${unknown.join(", ")}`);
  return new Set(selected);
}

function categoryResult(name, selected) {
  if (!selected.has(name)) {
    return {
      status: "not-selected",
      findings: [],
      checks: [],
      skipped: [{ check: name, reason: "category was not selected" }]
    };
  }
  return { status: "ok", findings: [], checks: [], skipped: [] };
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}

function limitationsFor(browserError) {
  const limitations = [
    "Synthetic lab measurements are not field Core Web Vitals and do not represent the 75th percentile of real users.",
    "Automated axe checks cannot establish WCAG 2.2 conformance; keyboard, screen-reader and manual interaction checks remain required.",
    "Only the installed Chrome engine and the requested viewport(s) were exercised; other browsers and physical devices are unverified.",
    "Passive HTTP header and TLS observations are not a penetration test.",
    "Privacy observations are indicators for review, not legal conclusions.",
    "Only one page/URL and a bounded sample of internal links were checked unless a crawl was explicitly configured.",
    "Resource timings for cross-origin resources may be incomplete without Timing-Allow-Origin."
  ];
  if (browserError) limitations.push(`Browser audit unavailable: ${browserError}`);
  return limitations;
}

function linksFromHtml(body, baseUrl) {
  const links = [];
  const text = body ? body.toString("utf8") : "";
  for (const match of text.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    const href = (match[1] || match[2] || match[3] || "").replaceAll("&amp;", "&").trim();
    if (!href || href.startsWith("#") || /^(javascript|mailto|tel|data):/i.test(href)) continue;
    try {
      links.push({ href: new URL(href, baseUrl).href, text: "" });
    } catch {
      // Malformed links are ignored; the browser remains the richer source.
    }
  }
  return links;
}

export async function runScan(input = {}) {
  if (input.signal?.aborted) throw new Error("scan cancelled");
  const selected = normalizeCategories(input.categories);
  const viewport = parseViewport(input.viewport || "1440x900");
  const config = {
    categories: [...selected],
    viewport,
    runs: Math.max(1, Math.min(5, Number(input.runs) || 1)),
    timeoutMs: Math.max(1_000, Math.min(120_000, Number(input.timeoutMs) || 30_000)),
    maxRequests: Math.max(10, Math.min(1_000, Number(input.maxRequests) || 200)),
    maxBytes: Math.max(64 * 1024, Math.min(50 * 1024 * 1024, Number(input.maxBytes) || 5 * 1024 * 1024)),
    maxLinks: Math.max(0, Math.min(100, Number(input.maxLinks) || 20)),
    allowPrivate: Boolean(input.allowPrivate),
    headless: true,
    serviceWorkers: "blocked",
    networkProfile: "unthrottled local connection; no simulated throttling",
    cpuThrottling: 1,
    device: "desktop local Chrome",
    browser: "local Chrome via playwright-core"
  };
  const startedAt = new Date().toISOString();
  const started = Date.now();
  const onProgress = typeof input.onProgress === "function" ? input.onProgress : () => {};
  const policy = new UrlPolicy({ allowPrivate: config.allowPrivate });
  const scanId = randomUUID();

  onProgress({ phase: "validation", message: "Validating target and DNS" });
  const targetUrl = policy.parse(input.url).href;
  await policy.resolve(targetUrl);
  if (input.signal?.aborted) throw new Error("scan cancelled");

  onProgress({ phase: "http", message: "Inspecting HTTP headers, TLS, robots and sitemap" });
  const http = await inspectHttp(targetUrl, policy, {
    timeoutMs: config.timeoutMs,
    maxBytes: config.maxBytes
  });
  if (input.signal?.aborted) throw new Error("scan cancelled");

  let browser = null;
  let browserError = null;
  if (selected.has("performance") || selected.has("accessibility") || selected.has("seo") ||
      selected.has("reliability") || selected.has("privacy")) {
    onProgress({ phase: "browser", message: "Launching local Chrome" });
    try {
      browser = await auditBrowser({
        url: targetUrl,
        policy,
        viewport,
        timeoutMs: config.timeoutMs,
        maxRequests: config.maxRequests,
        maxBytes: config.maxBytes,
        runs: config.runs,
        screenshotPath: input.screenshotPath || null,
        onProgress,
        signal: input.signal || null
      });
    } catch (error) {
      if (input.signal?.aborted) throw new Error("scan cancelled");
      browserError = String(error.message || error);
    }
  }

  const results = Object.fromEntries(CATEGORY_NAMES.map((name) => [name, categoryResult(name, selected)]));
  if (selected.has("performance")) Object.assign(results.performance, performanceAudit({ browser, http, url: targetUrl }));
  if (selected.has("accessibility")) Object.assign(results.accessibility, accessibilityAudit({ browser, url: targetUrl }));
  if (selected.has("seo")) {
    Object.assign(results.seo, await seoAudit({
      browser, http, url: targetUrl, policy,
      maxLinks: config.maxLinks,
      maxBytes: config.maxBytes,
      timeoutMs: Math.min(config.timeoutMs, 15_000)
    }));
  }
  if (selected.has("security")) Object.assign(results.security, securityAudit({ browser, http, url: targetUrl }));
  if (selected.has("reliability")) Object.assign(results.reliability, reliabilityAudit({ browser, http, url: targetUrl }));
  if (selected.has("privacy")) Object.assign(results.privacy, privacyAudit({ browser, http, url: targetUrl }));

  if (browserError) {
    for (const name of ["performance", "accessibility", "reliability", "privacy"]) {
      if (selected.has(name)) {
        results[name].status = "skipped";
        results[name].skipped = [...(results[name].skipped || []), { check: "browser", reason: browserError }];
      }
    }
  }
  if (!http.ok) {
    results.reliability.status = "partial";
    results.reliability.skipped = [...(results.reliability.skipped || []), { check: "http", reason: http.error?.message || "HTTP request failed" }];
  }

  const allFindings = dedupe(sortFindings(CATEGORY_NAMES.flatMap((name) => results[name].findings || [])));
  const firstPage = browser?.runs?.find((run) => run.pageData)?.pageData || null;
  const fallbackLinks = firstPage ? [] : linksFromHtml(http.body, http.finalUrl || targetUrl);
  const pageLinks = firstPage?.links || fallbackLinks;
  const completedAt = new Date().toISOString();
  const status = !http.ok && !browser ? "failed" : (browserError || !http.ok ? "partial" : "complete");
  const categories = Object.fromEntries(CATEGORY_NAMES.map((name) => [name, {
    status: results[name].status,
    findings: results[name].findings || [],
    checks: results[name].checks || [],
    skipped: results[name].skipped || [],
    caveat: results[name].caveat || null,
    ...(name === "performance" ? { metrics: results[name].metrics || null } : {}),
    ...(name === "seo" ? { linksChecked: results[name].linksChecked, linksDiscovered: results[name].linksDiscovered } : {}),
    ...(name === "privacy" ? { origins: results[name].origins || [], cookieCount: results[name].cookieCount || 0, thirdPartyCookieCount: results[name].thirdPartyCookieCount || 0 } : {})
  }]));

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: "webtim-inspector", version: VERSION },
    scanId,
    status,
    startedAt,
    completedAt,
    durationMs: Date.now() - started,
    target: {
      requestedUrl: targetUrl,
      finalUrl: http.finalUrl || null,
      scope: "single-page",
      allowPrivate: config.allowPrivate
    },
    page: (firstPage || http.ok) ? {
      finalUrl: http.finalUrl || targetUrl,
      canonical: firstPage?.canonical || null,
      links: pageLinks.slice(0, 250).map((link) => ({ href: link.href, text: link.text })),
      linkSource: firstPage ? "browser" : "html",
      requests: (browser?.runs || []).reduce((total, run) => total + (run.requestCount || 0), 0),
      transferBytes: (browser?.runs || []).reduce((total, run) => total + (run.transferBytes || 0), 0)
    } : null,
    configuration: config,
    environment: {
      node: process.version,
      platform: process.platform,
      release: os.release(),
      browser: browser?.browser || null,
      networkBoundary: browser?.networkBoundary || null,
      browserError,
      chromeOnly: true
    },
    summary: {
      findings: countFindings(allFindings),
      total: allFindings.length,
      categories: summarizeCategories(categories)
    },
    categories,
    findings: allFindings,
    evidence: {
      screenshot: browser?.runs?.find((run) => run.screenshot)?.screenshot || null,
      rawBrowserArtifactsIncluded: false
    },
    limitations: limitationsFor(browserError),
    http: http.ok ? {
      status: http.status,
      durationMs: http.durationMs,
      redirects: http.redirects,
      headers: http.headers,
      cookies: http.cookies,
      tls: http.tls,
      robots: http.robots ? { url: http.robots.url, status: http.robots.status, error: http.robots.error } : null,
      sitemap: http.sitemap ? { url: http.sitemap.url, status: http.sitemap.status, error: http.sitemap.error } : null
    } : { error: http.error },
    runs: browser?.runs?.map((run) => ({
      run: run.run,
      navigationError: run.navigationError,
      pageErrors: run.pageErrors,
      failedRequests: run.failedRequests,
      blockedRequests: run.blockedRequests,
      consoleMessages: run.consoleMessages,
      axe: run.axe ? { available: run.axe.available, violations: run.axe.violations?.length || 0, incomplete: run.axe.incomplete?.length || 0, error: run.axe.error } : null,
      screenshot: run.screenshot
    })) || []
  };
}
