import os from "node:os";
import { randomUUID } from "node:crypto";
import { CATEGORY_NAMES, runScan } from "../core/scanner.js";
import { UrlPolicy, requestSafe } from "../core/url-policy.js";
import { fetchRobots, robotsDecision } from "./robots.js";
import { countFindings, sortFindings, summarizeCategories, SEVERITY_ORDER } from "../core/findings.js";
import { VERSION, REPORT_SCHEMA_VERSION } from "../core/meta.js";
import { sleep } from "../core/util.js";

export const DEFAULT_CRAWL = {
  maxPages: 25,
  maxDepth: 2,
  maxConcurrency: 2,
  pagePacingMs: 250,
  maxDurationMs: 120_000,
  maxTotalRequests: 2_000,
  maxTotalBytes: 50 * 1024 * 1024,
  maxSitemapFiles: 5,
  maxSitemapUrls: 500,
  maxSitemapBytes: 1024 * 1024
};

function bounded(value, fallback, min, max) {
  const number = Number(value);
  return Math.max(min, Math.min(max, Number.isFinite(number) ? number : fallback));
}

export function crawlOptions(input = {}) {
  return {
    maxPages: bounded(input.maxPages, DEFAULT_CRAWL.maxPages, 1, 100),
    maxDepth: bounded(input.maxDepth, DEFAULT_CRAWL.maxDepth, 0, 10),
    maxConcurrency: bounded(input.maxConcurrency, DEFAULT_CRAWL.maxConcurrency, 1, 4),
    pagePacingMs: bounded(input.pagePacingMs, DEFAULT_CRAWL.pagePacingMs, 0, 5_000),
    maxDurationMs: bounded(input.maxDurationMs, DEFAULT_CRAWL.maxDurationMs, 5_000, 15 * 60_000),
    maxTotalRequests: bounded(input.maxTotalRequests, DEFAULT_CRAWL.maxTotalRequests, 1, 100_000),
    maxTotalBytes: bounded(input.maxTotalBytes, DEFAULT_CRAWL.maxTotalBytes, 64 * 1024, 500 * 1024 * 1024),
    maxSitemapFiles: bounded(input.maxSitemapFiles, DEFAULT_CRAWL.maxSitemapFiles, 1, 20),
    maxSitemapUrls: bounded(input.maxSitemapUrls, DEFAULT_CRAWL.maxSitemapUrls, 1, 5_000),
    maxSitemapBytes: bounded(input.maxSitemapBytes, DEFAULT_CRAWL.maxSitemapBytes, 64 * 1024, 5 * 1024 * 1024)
  };
}

function selectedCategories(value) {
  if (!value || value === "all") return new Set(CATEGORY_NAMES);
  const values = Array.isArray(value) ? value : String(value).split(",");
  const selected = values.map((item) => item.trim()).filter(Boolean);
  const unknown = selected.filter((item) => !CATEGORY_NAMES.includes(item));
  if (unknown.length) throw new Error(`unknown categories: ${unknown.join(", ")}`);
  return new Set(selected);
}

export function normalizeCrawlUrl(raw, base = undefined) {
  try {
    const url = new URL(raw, base);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.port === "0") return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function sameOrigin(left, right) {
  try {
    return new URL(left).origin === new URL(right).origin;
  } catch {
    return false;
  }
}

function decodeXml(value) {
  try {
    return value
      .replaceAll("&amp;", "&")
      .replaceAll("&lt;", "<")
      .replaceAll("&gt;", ">")
      .replaceAll("&quot;", "\"")
      .replaceAll("&#39;", "'")
      .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
      .replace(/&#(\d+);/g, (_, number) => String.fromCodePoint(Number(number)));
  } catch {
    return value;
  }
}

export function parseSitemap(text) {
  const xml = String(text || "");
  const locations = [...xml.matchAll(/<loc\b[^>]*>([\s\S]*?)<\/loc>/gi)]
    .map((match) => decodeXml(match[1].replace(/<[^>]+>/g, "").trim()))
    .filter(Boolean);
  return {
    index: /<sitemapindex\b/i.test(xml),
    locations
  };
}

async function fetchSitemaps({ robots, origin, policy, options, timeoutMs, onProgress }) {
  const files = [];
  const urls = [];
  const errors = [];
  const seenFiles = new Set();
  const seenUrls = new Set();
  const initial = robots.sitemaps
    .map((value) => normalizeCrawlUrl(value, origin))
    .filter((value) => value && sameOrigin(value, origin));
  if (!initial.length && robots.status !== "disallowed") initial.push(new URL("/sitemap.xml", origin).href);
  const queue = initial.slice();
  let truncated = false;
  while (queue.length && files.length < options.maxSitemapFiles) {
    const url = queue.shift();
    if (seenFiles.has(url)) continue;
    seenFiles.add(url);
    onProgress({ phase: "sitemap", message: `Reading ${url}` });
    let response;
    try {
      response = await requestSafe(url, {
        policy,
        timeoutMs,
        maxBytes: options.maxSitemapBytes,
        headers: { "user-agent": "webtim-inspector", "accept-encoding": "identity" }
      });
    } catch (error) {
      files.push({ url, status: null, error: error.message });
      errors.push({ url, error: error.message });
      continue;
    }
    if (response.status < 200 || response.status >= 300) {
      files.push({ url, status: response.status, error: `HTTP ${response.status}` });
      errors.push({ url, error: `HTTP ${response.status}` });
      continue;
    }
    if (!sameOrigin(response.url, origin)) {
      files.push({ url, finalUrl: response.url, status: response.status, error: "redirected outside the crawl origin" });
      errors.push({ url, error: "redirected outside the crawl origin" });
      continue;
    }
    const parsed = parseSitemap(response.body.toString("utf8"));
    files.push({ url, finalUrl: response.url, status: response.status, entries: parsed.locations.length, index: parsed.index });
    if (parsed.index) {
      for (const entry of parsed.locations) {
        const next = normalizeCrawlUrl(entry, response.url);
        if (next && sameOrigin(next, origin) && !seenFiles.has(next) && queue.length + files.length < options.maxSitemapFiles) queue.push(next);
        else truncated = true;
      }
      continue;
    }
    for (const entry of parsed.locations) {
      const next = normalizeCrawlUrl(entry, response.url);
      if (!next || seenUrls.has(next)) continue;
      if (urls.length >= options.maxSitemapUrls) {
        truncated = true;
        break;
      }
      seenUrls.add(next);
      urls.push(next);
    }
  }
  if (queue.length) truncated = true;
  return {
    status: files.length ? (errors.length ? "partial" : "parsed") : "unavailable",
    files,
    urls,
    errors,
    truncated
  };
}

function aggregateFindings(pages) {
  const groups = new Map();
  for (const page of pages) {
    for (const finding of page.findings || []) {
      const key = [finding.ruleId, finding.title, finding.severity].join("\n");
      if (!groups.has(key)) {
        groups.set(key, {
          ...finding,
          occurrences: 0,
          affectedPages: []
        });
      }
      const group = groups.get(key);
      group.occurrences += 1;
      if (!group.affectedPages.includes(page.url)) group.affectedPages.push(page.url);
      if (!group.evidence && finding.evidence) group.evidence = finding.evidence;
    }
  }
  return sortFindings([...groups.values()].map((finding) => ({
    ...finding,
    pageCount: finding.affectedPages.length
  })));
}

function pageResult(candidate, state, extra = {}) {
  return {
    url: candidate.url,
    depth: candidate.depth,
    source: candidate.source,
    state,
    finalUrl: extra.finalUrl || null,
    httpStatus: extra.httpStatus ?? null,
    reportStatus: extra.reportStatus || null,
    error: extra.error || null,
    durationMs: extra.durationMs || 0,
    requests: extra.requests || 0,
    bytes: extra.bytes || 0,
    findings: extra.findings || [],
    summary: extra.summary || { findings: countFindings([]), total: 0 },
    categories: extra.categories || null,
    environment: extra.environment || null,
    links: extra.links || [],
    canonical: extra.canonical || null
  };
}

async function inspectPage(candidate, context) {
  const started = Date.now();
  const decision = robotsDecision(context.robots, candidate.url);
  if (!decision.allowed) {
    return pageResult(candidate, "robots-skipped", { error: "disallowed by robots.txt" });
  }
  if (context.budgetExhausted()) {
    return pageResult(candidate, "limit-skipped", { error: "crawl request or byte budget exhausted" });
  }
  const remainingRequests = Math.max(10, context.options.maxTotalRequests - context.spentRequests);
  const remainingBytes = Math.max(64 * 1024, context.options.maxTotalBytes - context.spentBytes);
  try {
    const report = await runScan({
      url: candidate.url,
      categories: context.categories,
      viewport: context.viewport,
      runs: context.runs,
      timeoutMs: Math.max(1_000, Math.min(context.timeoutMs, context.deadline - Date.now())),
      maxRequests: Math.min(context.maxRequests, remainingRequests),
      maxBytes: Math.min(context.maxBytes, remainingBytes),
      maxLinks: context.maxLinks,
      allowPrivate: context.allowPrivate,
      signal: context.signal
    });
    const finalUrl = report.target?.finalUrl || null;
    const redirected = finalUrl && normalizeCrawlUrl(finalUrl) !== candidate.url;
    const httpFailed = report.http?.status >= 400;
    const timedOut = ["TIMEOUT", "ETIMEDOUT"].includes(report.http?.error?.code) ||
      /timeout/i.test(report.environment?.browserError || "") || /timeout/i.test(report.http?.error?.message || "");
    const state = timedOut ? "timed-out"
      : report.status === "failed" || httpFailed ? "failed"
        : redirected ? "redirected"
          : report.status === "partial" ? "inconclusive" : "completed";
    return pageResult(candidate, state, {
      finalUrl,
      httpStatus: report.http?.status ?? null,
      reportStatus: report.status,
      durationMs: Date.now() - started,
      requests: report.page?.requests || 0,
      bytes: report.page?.transferBytes || 0,
      findings: report.findings || [],
      summary: report.summary,
      categories: report.categories,
      environment: report.environment,
      links: report.page?.links || [],
      canonical: report.page?.canonical || null
    });
  } catch (error) {
    const cancelled = context.signal?.aborted;
    const state = cancelled ? "cancelled" : /timeout/i.test(error.message) ? "timed-out" : error.name === "UrlPolicyError" ? "blocked" : "failed";
    return pageResult(candidate, state, { error: error.message, durationMs: Date.now() - started });
  }
}

export async function crawlSite(input = {}) {
  const options = crawlOptions(input);
  const selectedCategoriesSet = selectedCategories(input.categories);
  const policy = new UrlPolicy({ allowPrivate: Boolean(input.allowPrivate) });
  const startedAt = new Date().toISOString();
  const started = Date.now();
  const scanId = randomUUID();
  const onProgress = typeof input.onProgress === "function" ? input.onProgress : () => {};
  const startUrl = policy.parse(input.url).href;
  await policy.resolve(startUrl);
  const origin = new URL(startUrl).origin;
  const context = {
    options,
    policy,
    categories: [...selectedCategoriesSet],
    viewport: input.viewport,
    runs: Math.max(1, Math.min(5, Number(input.runs) || 1)),
    timeoutMs: Math.max(1_000, Math.min(120_000, Number(input.timeoutMs) || 30_000)),
    maxRequests: Math.max(10, Math.min(1_000, Number(input.maxRequests) || 200)),
    maxBytes: Math.max(64 * 1024, Math.min(50 * 1024 * 1024, Number(input.maxBytes) || 5 * 1024 * 1024)),
    maxLinks: Math.max(0, Math.min(100, Number(input.maxLinks) || 20)),
    allowPrivate: Boolean(input.allowPrivate),
    signal: input.signal || null,
    deadline: started + options.maxDurationMs,
    nextPageStart: 0,
    spentRequests: 0,
    spentBytes: 0,
    budgetExhausted() {
      return this.spentRequests >= this.options.maxTotalRequests || this.spentBytes >= this.options.maxTotalBytes;
    },
    async pace() {
      const wait = this.nextPageStart - Date.now();
      this.nextPageStart = Math.max(Date.now(), this.nextPageStart) + this.options.pagePacingMs;
      if (wait > 0) await sleep(wait);
    }
  };

  onProgress({ phase: "crawl", message: "Reading robots.txt" });
  const robots = await fetchRobots(origin, policy, { timeoutMs: context.timeoutMs });
  context.robots = robots;
  const sitemap = await fetchSitemaps({ robots, origin, policy, options, timeoutMs: context.timeoutMs, onProgress });
  const seen = new Map();
  const candidates = [];
  const skipped = [];
  const addCandidate = (raw, depth, source) => {
    const url = normalizeCrawlUrl(raw, startUrl);
    if (!url || !sameOrigin(url, startUrl) || seen.has(url)) return;
    seen.set(url, { depth, source });
    if (depth > options.maxDepth) {
      skipped.push({ url, depth, state: "limit-skipped", reason: "maximum depth" });
      return;
    }
    candidates.push({ url, depth, source });
  };
  addCandidate(startUrl, 0, "start");
  for (const url of sitemap.urls) addCandidate(url, 1, "sitemap");

  const pages = [];
  let inFlight = 0;
  let timedOut = false;
  const take = () => {
    if (input.signal?.aborted) return null;
    if (Date.now() >= context.deadline) {
      timedOut = true;
      return null;
    }
    if (context.budgetExhausted()) return null;
    candidates.sort((left, right) => left.depth - right.depth || left.url.localeCompare(right.url));
    while (candidates.length) {
      if (pages.length + inFlight >= options.maxPages) {
        skipped.push(...candidates.splice(0).map((candidate) => ({
          url: candidate.url, depth: candidate.depth, state: "limit-skipped", reason: "maximum page count"
        })));
        return null;
      }
      const candidate = candidates.shift();
      if (candidate.depth > options.maxDepth) {
        skipped.push({ url: candidate.url, depth: candidate.depth, state: "limit-skipped", reason: "maximum depth" });
        continue;
      }
      return candidate;
    }
    return null;
  };
  const worker = async () => {
    while (true) {
      const candidate = take();
      if (!candidate) return;
      inFlight += 1;
      await context.pace();
      const result = await inspectPage(candidate, context);
      inFlight -= 1;
      pages.push(result);
      context.spentRequests += result.requests;
      context.spentBytes += result.bytes;
      const finalUrl = normalizeCrawlUrl(result.finalUrl, startUrl);
      if (finalUrl && sameOrigin(finalUrl, startUrl) && !seen.has(finalUrl)) {
        seen.set(finalUrl, { depth: candidate.depth, source: "redirect" });
      }
      for (const link of result.links || []) addCandidate(link.href, candidate.depth + 1, "link");
      if (result.canonical) addCandidate(result.canonical, candidate.depth + 1, "canonical");
      const auditedSoFar = pages.filter((page) => ["completed", "redirected", "inconclusive"].includes(page.state)).length;
      const skippedSoFar = skipped.length + pages.filter((page) => ["robots-skipped", "limit-skipped"].includes(page.state)).length;
      onProgress({
        phase: "crawl",
        message: `Audited ${auditedSoFar} page(s)`,
        discovered: seen.size,
        audited: auditedSoFar,
        attempted: pages.length,
        skipped: skippedSoFar,
        failed: pages.filter((page) => page.state === "failed").length
      });
    }
  };
  await Promise.all(Array.from({ length: options.maxConcurrency }, () => worker()));
  if (Date.now() > context.deadline) timedOut = true;
  for (const candidate of candidates.splice(0)) {
    skipped.push({
      url: candidate.url,
      depth: candidate.depth,
      state: input.signal?.aborted ? "cancelled" : "limit-skipped",
      reason: timedOut ? "time limit" : input.signal?.aborted ? "cancelled" : context.budgetExhausted() ? "request/byte budget" : "crawl stopped"
    });
  }
  pages.sort((left, right) => left.depth - right.depth || left.url.localeCompare(right.url));
  const audited = pages.filter((page) => ["completed", "redirected", "inconclusive"].includes(page.state));
  const allFindings = aggregateFindings(audited);
  const selected = selectedCategoriesSet;
  const categories = Object.fromEntries(CATEGORY_NAMES.map((name) => [name, {
    status: selected.has(name) ? (audited.length ? "ok" : "skipped") : "not-selected",
    findings: allFindings.filter((finding) => finding.category === name),
    checks: [],
    skipped: selected.has(name) ? [] : [{ check: name, reason: "category was not selected" }]
  }]));
  for (const name of CATEGORY_NAMES) {
    if (selected.has(name) && !audited.length) {
      categories[name].skipped.push({ check: name, reason: "no pages were audited" });
    }
  }
  const crawlPages = {
    discovered: seen.size,
    attempted: pages.length,
    audited: audited.length,
    redirected: pages.filter((page) => page.state === "redirected").length,
    robotsSkipped: pages.filter((page) => page.state === "robots-skipped").length,
    limitSkipped: pages.filter((page) => page.state === "limit-skipped").length,
    timedOut: pages.filter((page) => page.state === "timed-out").length,
    failed: pages.filter((page) => page.state === "failed").length,
    blocked: pages.filter((page) => page.state === "blocked").length,
    inconclusive: pages.filter((page) => page.state === "inconclusive").length,
    cancelled: pages.filter((page) => page.state === "cancelled").length,
    skipped: skipped.length + pages.filter((page) => ["robots-skipped", "limit-skipped"].includes(page.state)).length,
    maxPages: options.maxPages,
    maxDepth: options.maxDepth,
    maxConcurrency: options.maxConcurrency,
    maxDurationMs: options.maxDurationMs
  };
  const startPage = pages.find((page) => page.url === startUrl);
  const finalOrigin = startPage?.finalUrl ? new URL(startPage.finalUrl).origin : origin;
  const partial = pages.some((page) => ["failed", "inconclusive", "timed-out", "blocked", "cancelled"].includes(page.state));
  const cancelled = Boolean(input.signal?.aborted) || timedOut;
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: "webtim-inspector", version: VERSION },
    scanId,
    status: cancelled || partial || !audited.length ? "partial" : "complete",
    startedAt,
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    target: {
      requestedUrl: startUrl,
      finalUrl: startPage?.finalUrl || startUrl,
      finalOrigin,
      scope: "site",
      allowPrivate: context.allowPrivate
    },
    configuration: {
      ...options,
      categories: [...selected],
      viewport: input.viewport || "1440x900",
      runs: context.runs,
      timeoutMs: context.timeoutMs,
      maxRequests: context.maxRequests,
      maxBytes: context.maxBytes,
      maxLinks: context.maxLinks,
      allowPrivate: context.allowPrivate,
      networkProfile: "unthrottled local connection; no simulated throttling",
      cpuThrottling: 1,
      device: "desktop local Chrome",
      browser: "local Chrome via playwright-core"
    },
    environment: {
      node: process.version,
      platform: process.platform,
      release: os.release(),
      browser: pages.find((page) => page.environment?.browser)?.environment.browser || null,
      browserError: null,
      chromeOnly: true
    },
    crawl: {
      startUrl,
      finalOrigin,
      robots: {
        url: robots.url,
        finalUrl: robots.finalUrl,
        status: robots.status,
        httpStatus: robots.httpStatus,
        error: robots.error,
        sitemaps: robots.sitemaps
      },
      sitemap,
      pages,
      skipped,
      timedOut,
      cancelled: Boolean(input.signal?.aborted),
      coverage: crawlPages,
      limits: options
    },
    summary: {
      findings: countFindings(allFindings),
      total: allFindings.length,
      categories: summarizeCategories(categories),
      pages: crawlPages,
      mostCommon: allFindings
        .slice()
        .sort((left, right) => right.pageCount - left.pageCount || SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity))
        .slice(0, 10)
        .map((finding) => ({
          ruleId: finding.ruleId,
          title: finding.title,
          severity: finding.severity,
          pageCount: finding.pageCount
        }))
    },
    categories,
    findings: allFindings,
    evidence: { screenshot: null, rawBrowserArtifactsIncluded: false },
    limitations: [
      `This site scan covered at most ${options.maxPages} pages, depth ${options.maxDepth}; it is not a complete-site audit.`,
      "Robots.txt is a crawler convention, not authorization or a network-security control.",
      "Sitemap entries are discovery candidates; page, depth, time, robots and URL-policy limits still apply.",
      "Pages not reached because of a crawl limit are reported as skipped, not as passing.",
      "Synthetic lab measurements are not field Core Web Vitals; automated axe checks do not certify WCAG 2.2.",
      "Only the installed Chrome engine and one viewport were exercised.",
      "Browser traffic is validated through a loopback proxy; HTTP and CONNECT destinations are checked before connection."
    ]
  };
}
