import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { sleep } from "./util.js";
import { startValidatingProxy } from "./proxy.js";

const CHROME_CANDIDATES = [
  process.env.INSPECTOR_CHROME_PATH,
  process.env.PLAYWRIGHT_CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
].filter(Boolean);

export function findChrome() {
  const executable = CHROME_CANDIDATES.find((candidate) => fs.existsSync(candidate));
  if (!executable) {
    throw new Error(
      "Chrome was not found. Install Google Chrome or set INSPECTOR_CHROME_PATH to its executable."
    );
  }
  return executable;
}

const INIT_PERFORMANCE = () => {
  const state = { lcp: 0, lcpElement: null, cls: 0, longTasks: [], interactions: [] };
  const observe = (type, callback) => {
    try {
      new PerformanceObserver((list) => callback(list.getEntries())).observe({ type, buffered: true });
    } catch {
      // A browser without this entry type still produces the other metrics.
    }
  };
  observe("largest-contentful-paint", (entries) => {
    const entry = entries[entries.length - 1];
    if (entry) {
      state.lcp = entry.startTime;
      state.lcpElement = entry.element ? {
        tag: entry.element.tagName,
        id: entry.element.id || null,
        className: typeof entry.element.className === "string" ? entry.element.className : null
      } : null;
    }
  });
  observe("layout-shift", (entries) => {
    for (const entry of entries) {
      if (!entry.hadRecentInput) state.cls += entry.value;
    }
  });
  observe("longtask", (entries) => {
    for (const entry of entries) state.longTasks.push({ start: entry.startTime, duration: entry.duration });
  });
  observe("event", (entries) => {
    for (const entry of entries) {
      if (["pointerdown", "pointerup", "click", "keydown", "keyup"].includes(entry.name)) {
        state.interactions.push({
          name: entry.name,
          start: entry.startTime,
          duration: entry.duration,
          processingStart: entry.processingStart,
          processingEnd: entry.processingEnd
        });
      }
    }
  });
  Object.defineProperty(window, "__webtimPerf", { value: state, configurable: true });
};

const READ_PAGE = () => {
  const text = (element) => (element?.textContent || "").trim().replace(/\s+/g, " ");
  const meta = (selector) => document.querySelector(selector)?.getAttribute("content") || null;
  const navigation = performance.getEntriesByType("navigation")[0];
  const paint = Object.fromEntries(performance.getEntriesByType("paint").map((entry) => [entry.name, entry.startTime]));
  const resources = performance.getEntriesByType("resource").map((entry) => ({
    name: entry.name,
    initiatorType: entry.initiatorType,
    startTime: entry.startTime,
    duration: entry.duration,
    transferSize: entry.transferSize || 0,
    encodedBodySize: entry.encodedBodySize || 0,
    decodedBodySize: entry.decodedBodySize || 0,
    responseEnd: entry.responseEnd || 0,
    renderBlockingStatus: entry.renderBlockingStatus || null
  }));
  const resourceOrigins = [...new Set(resources.map((entry) => {
    try { return new URL(entry.name).origin; } catch { return ""; }
  }).filter(Boolean))];
  return {
    title: document.title || "",
    lang: document.documentElement.lang || "",
    meta: {
      description: meta('meta[name="description"]'),
      viewport: meta('meta[name="viewport"]'),
      robots: meta('meta[name="robots"]'),
      generator: meta('meta[name="generator"]'),
      ogTitle: meta('meta[property="og:title"]'),
      ogDescription: meta('meta[property="og:description"]'),
      ogImage: meta('meta[property="og:image"]')
    },
    canonical: document.querySelector('link[rel="canonical"]')?.href || null,
    headings: [...document.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((element) => ({
      level: Number(element.tagName.slice(1)),
      text: text(element).slice(0, 160),
      selector: element.id ? `#${CSS.escape(element.id)}` : element.tagName.toLowerCase()
    })),
    images: [...document.images].map((image) => ({
      src: image.currentSrc || image.src,
      alt: image.getAttribute("alt"),
      width: image.naturalWidth,
      height: image.naturalHeight,
      complete: image.complete,
      selector: image.id ? `#${CSS.escape(image.id)}` : "img"
    })),
    links: [...document.querySelectorAll("a[href]")].map((link) => ({
      href: link.href,
      text: text(link).slice(0, 100),
      rel: link.rel || ""
    })),
    forms: [...document.forms].map((form) => ({
      action: form.action,
      method: form.method,
      controls: [...form.elements].map((control) => ({
        tag: control.tagName.toLowerCase(),
        type: control.type || "",
        name: control.name || "",
        id: control.id || "",
        label: control.labels?.length
          ? [...control.labels].map((label) => text(label)).join(" ")
          : control.getAttribute("aria-label") || ""
      }))
    })),
    scripts: [...document.scripts].map((script) => ({
      src: script.src || null,
      module: script.type === "module",
      async: script.async,
      defer: script.defer,
      inline: !script.src
    })),
    structuredData: [...document.querySelectorAll('script[type="application/ld+json"]')].map((script) => {
      try { return JSON.parse(script.textContent); } catch { return { parseError: true }; }
    }),
    navigation: navigation ? {
      ttfb: navigation.responseStart,
      domContentLoaded: navigation.domContentLoadedEventEnd,
      load: navigation.loadEventEnd,
      transferSize: navigation.transferSize || 0,
      encodedBodySize: navigation.encodedBodySize || 0,
      decodedBodySize: navigation.decodedBodySize || 0
    } : null,
    paint,
    resources,
    resourceOrigins,
    perf: window.__webtimPerf || { lcp: 0, cls: 0, longTasks: [], interactions: [] },
    textLength: (document.body?.innerText || "").length,
    htmlBytes: new Blob([document.documentElement.outerHTML]).size,
    viewport: {
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      clientHeight: document.documentElement.clientHeight,
      scrollHeight: document.documentElement.scrollHeight
    }
  };
};

export async function auditBrowser({
  url,
  policy,
  viewport,
  timeoutMs = 30_000,
  maxRequests = 200,
  maxBytes = 5 * 1024 * 1024,
  runs = 1,
  screenshotPath = null,
  onProgress = () => {},
  signal = null
}) {
  const executablePath = findChrome();
  const validationProxy = await startValidatingProxy({ policy, timeoutMs, maxBytes });
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      executablePath,
      proxy: { server: validationProxy.url },
      // Chrome otherwise bypasses proxies for loopback, including local fixtures.
      args: ["--proxy-bypass-list=<-loopback>", "--disable-quic"]
    });
  } catch (error) {
    await validationProxy.close().catch(() => {});
    throw error;
  }
  const browserVersion = browser.version();
  const runResults = [];
  const stop = () => browser?.close().catch(() => {});
  if (signal?.aborted) stop();
  signal?.addEventListener("abort", stop, { once: true });
  try {
    for (let run = 1; run <= runs; run += 1) {
      if (signal?.aborted) throw new Error("scan cancelled");
      onProgress({ phase: "browser", run, total: runs });
      const context = await browser.newContext({
        viewport,
        deviceScaleFactor: 1,
        colorScheme: "light",
        serviceWorkers: "block",
        acceptDownloads: false
      });
      const page = await context.newPage();
      const consoleMessages = [];
      const pageErrors = [];
      const failedRequests = [];
      const responses = new Map();
      const blockedRequests = [];
      let requestCount = 0;

      await context.route("**/*", async (route) => {
        const request = route.request();
        requestCount += 1;
        if (requestCount > maxRequests) {
          blockedRequests.push({ url: request.url(), reason: "request limit reached" });
          await route.abort("blockedbyclient").catch(() => {});
          return;
        }
        if (!/^https?:/i.test(request.url())) {
          await route.continue().catch(() => {});
          return;
        }
        try {
          await policy.resolve(request.url());
        } catch (error) {
          blockedRequests.push({ url: request.url(), reason: error.message });
          await route.abort("blockedbyclient").catch(() => {});
          return;
        }
        const contentLength = Number(request.headers()["content-length"] || 0);
        if (contentLength > maxBytes) {
          blockedRequests.push({ url: request.url(), reason: "response size limit reached" });
          await route.abort("blockedbyclient").catch(() => {});
          return;
        }
        await route.continue().catch(() => {});
      });

      page.on("console", (message) => {
        if (["error", "warning"].includes(message.type())) {
          consoleMessages.push({ type: message.type(), text: message.text().slice(0, 500) });
        }
      });
      page.on("pageerror", (error) => pageErrors.push(String(error.message || error).slice(0, 500)));
      page.on("requestfailed", (request) => {
        failedRequests.push({
          url: request.url(),
          type: request.resourceType(),
          error: request.failure()?.errorText || "request failed"
        });
      });
      page.on("response", async (response) => {
        try {
          responses.set(response.url(), {
            status: response.status(),
            headers: await response.headers(),
            type: response.request().resourceType()
          });
        } catch {
          // The page or response was closed while reading headers.
        }
      });
      page.on("websocket", (socket) => {
        policy.resolve(socket.url()).catch((error) => {
          blockedRequests.push({ url: socket.url(), reason: error.message });
          socket.close({ code: 1008, reason: "blocked by Inspector policy" }).catch(() => {});
        });
      });

      await page.addInitScript(INIT_PERFORMANCE);
      await page.setDefaultTimeout(timeoutMs);
      let navigationError = null;
      try {
        await page.goto(url, { waitUntil: "load", timeout: timeoutMs });
        await page.waitForLoadState("networkidle", { timeout: Math.min(5_000, timeoutMs) }).catch(() => {});
        await sleep(750);
      } catch (error) {
        navigationError = String(error.message || error);
      }

      let pageData = null;
      try {
        pageData = await page.evaluate(READ_PAGE);
      } catch (error) {
        navigationError = navigationError || String(error.message || error);
      }

      let axe = { available: false, violations: [], incomplete: [], error: null };
      try {
        const axePath = fileURLToPath(new URL("../../node_modules/axe-core/axe.min.js", import.meta.url));
        await page.addScriptTag({ path: axePath });
        axe = await page.evaluate(async (tags) => {
          if (!window.axe) return { available: false, violations: [], incomplete: [], error: "axe did not load" };
          const result = await window.axe.run(document, {
            runOnly: { type: "tag", values: tags },
            resultTypes: ["violations", "incomplete"]
          });
          return {
            available: true,
            violations: result.violations.map((item) => ({
              id: item.id,
              impact: item.impact,
              help: item.help,
              description: item.description,
              helpUrl: item.helpUrl,
              tags: item.tags,
              nodes: item.nodes.slice(0, 20).map((node) => ({
                target: node.target,
                html: node.html?.slice(0, 500) || "",
                failureSummary: node.failureSummary || ""
              })),
              nodeCount: item.nodes.length
            })),
            incomplete: result.incomplete.map((item) => ({
              id: item.id,
              impact: item.impact,
              help: item.help,
              nodeCount: item.nodes.length
            })),
            error: null
          };
        }, ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa", "best-practice"]);
      } catch (error) {
        axe = { available: false, violations: [], incomplete: [], error: String(error.message || error) };
      }

      let cookies = [];
      try {
        cookies = (await context.cookies()).map((cookie) => ({
          name: cookie.name,
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: cookie.sameSite,
          expires: cookie.expires
        }));
      } catch {
        // Cookie access can fail when the context closes during a timeout.
      }

      let screenshot = null;
      if (screenshotPath && run === 1) {
        try {
          fs.mkdirSync(path.dirname(screenshotPath), { recursive: true });
          await page.screenshot({ path: screenshotPath, fullPage: true });
          screenshot = screenshotPath;
        } catch (error) {
          screenshot = `screenshot failed: ${error.message}`;
        }
      }

      runResults.push({
        run,
        navigationError,
        pageData,
        axe,
        consoleMessages,
        pageErrors,
        failedRequests,
        blockedRequests,
        requestCount,
        transferBytes: (pageData?.resources || []).reduce((total, resource) => total + (resource.transferSize || 0), 0),
        cookies,
        responses: [...responses.entries()].map(([resourceUrl, value]) => ({ url: resourceUrl, ...value })),
        screenshot
      });
      await context.close();
    }
  } finally {
    signal?.removeEventListener("abort", stop);
    await browser.close().catch(() => {});
    await validationProxy.close().catch(() => {});
  }
  return {
    browser: {
      name: "Chromium",
      version: browserVersion,
      executablePath
    },
    viewport,
    networkBoundary: {
      mode: "validating-proxy",
      proxy: "loopback",
      ...validationProxy.stats
    },
    runs: runResults
  };
}
