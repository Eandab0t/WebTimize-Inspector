import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { runScan } from "../core/scanner.js";
import { crawlSite } from "../crawl/crawl.js";
import { renderHtml, compareReports, renderComparisonHtml } from "../report/report.js";
import { createStaticServer } from "../core/local-server.js";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const PUBLIC = path.join(ROOT, "public");
const REPORTS = path.join(ROOT, "__development", "reports");
const EVIDENCE = path.join(ROOT, "__development", "experiments", "dashboard-evidence");
const TOKEN = randomUUID().replaceAll("-", "");
const HTML = (await fs.readFile(path.join(PUBLIC, "index.html"), "utf8")).replaceAll("__TOKEN__", TOKEN);
const CSS = await fs.readFile(path.join(PUBLIC, "style.css"), "utf8");
const APP = await fs.readFile(path.join(PUBLIC, "app.js"), "utf8");
const LOGO = await fs.readFile(path.join(PUBLIC, "webtimize-logo.png"));
const jobs = new Map();
const reports = new Map();
let activeJob = null;

function securityHeaders(response, contentType) {
  response.setHeader("content-type", contentType);
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
}

function sendJson(response, status, value) {
  securityHeaders(response, "application/json; charset=utf-8");
  response.writeHead(status);
  response.end(JSON.stringify(value));
}

function sendText(response, status, value, contentType = "text/plain; charset=utf-8") {
  securityHeaders(response, contentType);
  response.writeHead(status);
  response.end(value);
}

function sameOrigin(request) {
  const origin = request.headers.origin;
  const host = request.headers.host;
  return Boolean(origin && host && origin === `http://${host}`);
}

function authorized(request) {
  if (request.headers["x-inspector-token"] !== TOKEN) return false;
  // Browsers omit Origin on same-origin GET requests. Mutations must still be
  // explicitly same-origin; read-only API responses are not CORS-readable by
  // other origins and still require the per-process token.
  return request.method === "GET" || sameOrigin(request);
}

async function readJson(request) {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) throw new Error("request body is too large");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("request body must be valid JSON");
  }
}

async function saveReport(report) {
  await fs.mkdir(REPORTS, { recursive: true });
  await fs.writeFile(path.join(REPORTS, `${report.scanId}.json`), `${JSON.stringify(report, null, 2)}\n`);
  reports.set(report.scanId, report);
}

async function executeJob(job, payload, onDone) {
  let fixture = null;
  try {
    let url = payload.url;
    if (payload.localDir) {
      const directory = path.resolve(payload.localDir);
      const stat = await fs.stat(directory);
      if (!stat.isDirectory()) throw new Error("localDir is not a directory");
      fixture = await createStaticServer(directory);
      url = fixture.url;
    }
    job.progress = 10;
    job.message = "Validating target";
    const common = {
      url,
      categories: payload.categories,
      viewport: payload.viewport,
      runs: payload.runs,
      maxLinks: payload.maxLinks,
      allowPrivate: Boolean(payload.localDir),
      signal: job.controller.signal,
      onProgress: (event) => {
        const phases = { validation: 12, http: 24, browser: 46, sitemap: 35 };
        if (event.phase === "crawl") {
          const maxPages = Math.max(1, Number(payload.maxPages) || 25);
          job.progress = Math.max(job.progress, Math.min(90, 10 + Math.round(((event.audited || 0) / maxPages) * 80)));
          job.coverage = {
            discovered: event.discovered || 0,
            audited: event.audited || 0,
            attempted: event.attempted || 0,
            skipped: event.skipped || 0,
            failed: event.failed || 0
          };
        } else {
          job.progress = Math.max(job.progress, phases[event.phase] || job.progress);
        }
        job.message = event.message || `${event.phase}${event.run ? ` (run ${event.run}/${event.total})` : ""}`;
      }
    };
    const report = payload.crawl ? await crawlSite({
      ...common,
      maxPages: payload.maxPages,
      maxDepth: payload.maxDepth,
      maxConcurrency: payload.maxConcurrency,
      maxDurationMs: payload.maxDurationMs,
      maxTotalRequests: payload.maxTotalRequests,
      maxTotalBytes: payload.maxTotalBytes
    }) : await runScan({ ...common, screenshotPath: path.join(EVIDENCE, `${job.id}.png`) });
    job.progress = 95;
    job.message = "Writing report";
    await saveReport(report);
    job.status = job.controller.signal.aborted ? "cancelled" : "done";
    job.progress = 100;
    job.message = job.status === "cancelled" ? "Scan cancelled; partial report saved" : "Scan complete";
    job.reportId = report.scanId;
    onDone(report);
  } catch (error) {
    job.status = job.controller.signal.aborted ? "cancelled" : "error";
    job.error = error.message;
    job.message = job.controller.signal.aborted ? "Scan cancelled" : error.message;
  } finally {
    if (fixture) await fixture.close().catch(() => {});
  }
}

function jobView(job) {
  return {
    id: job.id, status: job.status, progress: job.progress, message: job.message,
    error: job.error || null, reportId: job.reportId || null, startedAt: job.startedAt,
    kind: job.kind || "scan", coverage: job.coverage || null
  };
}

function reportView(report) {
  return {
    scanId: report.scanId,
    startedAt: report.startedAt,
    status: report.status,
    url: report.target?.requestedUrl || report.target?.finalUrl || null,
    target: report.target,
    total: report.findings?.length || 0,
    summary: report.summary
  };
}

function history() {
  return [...reports.values()].sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt))).map(reportView);
}

export async function startDashboard({ port = 4173 } = {}) {
  await fs.mkdir(EVIDENCE, { recursive: true }).catch(() => {});
  const server = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, "http://127.0.0.1");
    const pathname = requestUrl.pathname;
    try {
      if (request.method === "GET" && pathname === "/") {
        sendText(response, 200, HTML, "text/html; charset=utf-8");
        return;
      }
      if (request.method === "GET" && pathname === "/style.css") {
        sendText(response, 200, CSS, "text/css; charset=utf-8");
        return;
      }
      if (request.method === "GET" && pathname === "/app.js") {
        sendText(response, 200, APP, "text/javascript; charset=utf-8");
        return;
      }
      if (request.method === "GET" && pathname === "/webtimize-logo.png") {
        securityHeaders(response, "image/png");
        response.writeHead(200);
        response.end(LOGO);
        return;
      }
      if (request.method === "GET" && pathname === "/favicon.ico") {
        response.writeHead(204);
        response.end();
        return;
      }
      if (pathname.startsWith("/api/") && !authorized(request)) {
        sendJson(response, 403, { error: "same-origin authenticated request required" });
        return;
      }
      if (request.method === "GET" && pathname === "/api/health") {
        sendJson(response, 200, { ok: true, activeJob: activeJob?.id || null });
        return;
      }
      if (request.method === "GET" && pathname === "/api/scans") {
        sendJson(response, 200, { scans: history() });
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/api/scans/")) {
        const id = decodeURIComponent(pathname.slice("/api/scans/".length));
        const job = jobs.get(id);
        if (!job) {
          sendJson(response, 404, { error: "scan not found" });
          return;
        }
        sendJson(response, 200, { job: jobView(job), report: job.reportId ? reports.get(job.reportId) : null });
        return;
      }
      if (request.method === "POST" && pathname === "/api/scan") {
        if (activeJob) {
          sendJson(response, 429, { error: "another scan is running; wait for it to finish" });
          return;
        }
        const payload = await readJson(request);
        if (!payload.url && !payload.localDir) throw new Error("url or localDir is required");
        if (payload.url && payload.localDir) throw new Error("use either url or localDir");
        const job = {
          id: randomUUID(), status: "running", progress: 5, message: "Queued",
          error: null, reportId: null, startedAt: new Date().toISOString(),
          kind: payload.crawl ? "crawl" : "scan", controller: new AbortController()
        };
        jobs.set(job.id, job);
        activeJob = job;
        const done = () => { activeJob = null; };
        executeJob(job, payload, done).finally(done);
        sendJson(response, 202, { id: job.id, job: jobView(job) });
        return;
      }
      if (request.method === "POST" && pathname.startsWith("/api/scans/") && pathname.endsWith("/cancel")) {
        const id = decodeURIComponent(pathname.slice("/api/scans/".length, -7));
        const job = jobs.get(id);
        if (!job) {
          sendJson(response, 404, { error: "scan not found" });
          return;
        }
        if (job.status === "running") {
          job.message = "Cancelling…";
          job.controller.abort();
        }
        sendJson(response, 202, { job: jobView(job) });
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/api/report/")) {
        const rest = decodeURIComponent(pathname.slice("/api/report/".length));
        const html = rest.endsWith(".html");
        const id = html ? rest.slice(0, -5) : rest;
        const report = reports.get(id);
        if (!report) {
          sendJson(response, 404, { error: "report not found" });
          return;
        }
        if (html) {
          sendText(response, 200, renderHtml(report), "text/html; charset=utf-8");
        } else {
          response.setHeader("content-disposition", `attachment; filename="webtim-inspector-${id}.json"`);
          sendJson(response, 200, report);
        }
        return;
      }
      if (request.method === "GET" && pathname === "/api/compare") {
        const before = reports.get(requestUrl.searchParams.get("before") || "");
        const after = reports.get(requestUrl.searchParams.get("after") || "");
        if (!before || !after) {
          sendJson(response, 404, { error: "both reports must exist" });
          return;
        }
        sendJson(response, 200, compareReports(before, after));
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/api/evidence/")) {
        const file = decodeURIComponent(pathname.slice("/api/evidence/".length));
        if (!/^[a-f0-9-]+\.png$/i.test(file)) {
          sendJson(response, 400, { error: "invalid evidence path" });
          return;
        }
        const target = path.join(EVIDENCE, file);
        try {
          const body = await fs.readFile(target);
          securityHeaders(response, "image/png");
          response.writeHead(200);
          response.end(body);
        } catch {
          sendJson(response, 404, { error: "evidence not found" });
        }
        return;
      }
      sendJson(response, 404, { error: "not found" });
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      console.log(`WebTimize Inspector dashboard: http://127.0.0.1:${address.port}`);
      console.log("Loopback only. Press Ctrl+C to stop.");
      resolve({ server, url: `http://127.0.0.1:${address.port}`, port: address.port, token: TOKEN });
    });
  });
}
