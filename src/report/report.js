import { SEVERITY_ORDER } from "../core/findings.js";
import { escapeHtml, formatBytes } from "../core/util.js";

const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Information"
};

const REPORT_CSS = `
:root {
  color-scheme: light;
  --canvas:#f4f1ea; --surface:#fffdf8; --ink:#2a1d15; --muted:#6b6a70;
  --line:#d8d3c8; --brown:#3e291c; --accent:#8a4a1a; --sand:#d9cbb6;
  --danger:#9b3226; --warning:#8a5a00; --success:#2f6b4f; --info:#315c87;
  --danger-soft:#f7e8e4; --warning-soft:#f6edd9; --success-soft:#e6f0ea;
  --info-soft:#e8eef5; --neutral-soft:#eee9df;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,"Liberation Mono",monospace;
  --sans:"Segoe UI",system-ui,-apple-system,sans-serif;
  --edge:2px solid var(--ink); --drop:4px 4px 0 var(--ink);
}
@media (prefers-color-scheme:dark) {
  :root { color-scheme:dark; --canvas:#17110d; --surface:#241a13; --ink:#f4f1ea;
    --muted:#a9a8ae; --line:#4a3a2c; --accent:#e0b98c; --sand:#cbb69a;
    --danger:#e79a90; --warning:#f0c27a; --success:#8fc9aa; --info:#a7c5e8;
    --danger-soft:#3a211d; --warning-soft:#352a17; --success-soft:#1d3027;
    --info-soft:#1d2938; --neutral-soft:#30251c; --edge:2px solid #4a3a2c;
    --drop:4px 4px 0 #0d0906; }
}
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); background-color:var(--canvas);
  background-image:linear-gradient(to right,color-mix(in srgb,var(--ink) 5%,transparent) 1px,transparent 1px),
    linear-gradient(to bottom,color-mix(in srgb,var(--ink) 5%,transparent) 1px,transparent 1px);
  background-size:48px 48px; font:14.5px/1.55 var(--sans); }
a { color:var(--accent); text-underline-offset:3px; overflow-wrap:anywhere; }
main { max-width:1040px; margin:0 auto; padding:34px 20px 64px; }
header { padding:22px; margin-bottom:20px; background:var(--brown); color:#f4f1ea; border:var(--edge); box-shadow:var(--drop); }
header .eyebrow { margin:0 0 3px; color:var(--sand); font:700 10px/1.4 var(--mono); letter-spacing:.14em; text-transform:uppercase; }
h1 { margin:0 0 8px; color:#f4f1ea; font-size:clamp(1.8rem,4vw,2.6rem); line-height:1.08; letter-spacing:-.03em; }
h2 { margin:0 0 10px; font-size:1.25rem; letter-spacing:-.02em; }
h3 { margin:0 0 7px; font-size:1.02rem; }
code,pre { font-family:var(--mono); font-size:.86em; }
pre { overflow:auto; padding:11px; background:var(--canvas); border:1px solid var(--line); border-radius:1px; }
.url { overflow-wrap:anywhere; color:var(--sand); }
header p { margin:4px 0; color:var(--sand); font-size:12.5px; }
.status,.badge,.pill { display:inline-flex; padding:3px 7px; border:1.5px solid currentColor; border-radius:1px;
  background:transparent; font:700 9.5px/1.4 var(--mono); letter-spacing:.07em; text-transform:uppercase; }
.status { margin-bottom:10px; color:var(--sand); }
.panel,.category { background:var(--surface); border:var(--edge); border-radius:2px; padding:20px; margin:16px 0; box-shadow:var(--drop); }
.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(105px,1fr)); gap:9px; margin:18px 0 22px; }
.summary div { padding:10px 12px; background:var(--surface); border:1.5px solid var(--ink); border-radius:1px; }
.summary strong { display:block; font-size:1.5rem; line-height:1.1; }
.summary div { color:var(--muted); font:700 9.5px/1.4 var(--mono); letter-spacing:.07em; text-transform:uppercase; }
.finding { padding:16px 0; border-top:1px dashed var(--line); }
.finding:first-of-type { border-top:0; }
.finding-head { display:flex; align-items:center; gap:9px; margin-bottom:6px; }
.pill { background:var(--neutral-soft); color:var(--muted); }
.severity-critical .pill,.severity-high .pill { background:var(--danger-soft); color:var(--danger); }
.severity-medium .pill { background:var(--warning-soft); color:var(--warning); }
.severity-low .pill { background:var(--info-soft); color:var(--info); }
.confidence,.badge,.caveat,.empty { color:var(--muted); font-size:.83rem; }
.category-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:8px; }
.badge { border-color:var(--line); }
dl { display:grid; grid-template-columns:120px minmax(0,1fr); gap:4px 12px; font-size:.88rem; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
details { margin-top:11px; }
li { margin:4px 0; }
table { width:100%; border-collapse:collapse; font-size:.88rem; }
th,td { text-align:left; vertical-align:top; border-bottom:1px dashed var(--line); padding:7px 8px; }
td { overflow-wrap:anywhere; }
table { table-layout:fixed; }
th { color:var(--muted); font:700 9.5px/1.4 var(--mono); letter-spacing:.05em; text-transform:uppercase; }
footer { color:var(--muted); font-size:.78rem; margin-top:26px; }
@media (max-width:600px) { main{padding:18px 12px 48px;} header{padding:17px;} .panel,.category{padding:14px;} dl{grid-template-columns:1fr;} }
@media (prefers-color-scheme:dark) { .status { color:var(--sand); } }
`;

function pageIdentity(value) {
  try {
    const url = new URL(value);
    return `${url.pathname}${url.search}`;
  } catch {
    return String(value || "");
  }
}

function findingCard(finding) {
  const element = finding.element ? `<div><strong>Element:</strong> <code>${escapeHtml(finding.element)}</code></div>` : "";
  const evidence = finding.evidence ? `<pre class="evidence">${escapeHtml(finding.evidence)}</pre>` : "";
  const affected = finding.affectedPages?.length
    ? `<p><strong>Affects ${finding.affectedPages.length} page(s):</strong></p><ul>${finding.affectedPages.map((page) => `<li><a href="${escapeHtml(page)}" rel="noreferrer">${escapeHtml(page)}</a></li>`).join("")}</ul>`
    : "";
  const reference = finding.reference
    ? `<div><strong>Reference:</strong> <a href="${escapeHtml(finding.reference)}" rel="noreferrer">${escapeHtml(finding.reference)}</a></div>`
    : "";
  return `<article class="finding severity-${finding.severity}">
    <div class="finding-head"><span class="pill">${escapeHtml(SEVERITY_LABELS[finding.severity] || finding.severity)}</span>
      <span class="confidence">${escapeHtml(finding.confidence)} confidence</span></div>
    <h3>${escapeHtml(finding.title)}</h3>
    <p>${escapeHtml(finding.description)}</p>
    ${element}
    ${evidence}
    ${affected}
    <dl>
      <dt>Rule</dt><dd><code>${escapeHtml(finding.ruleId)}</code></dd>
      <dt>Detection</dt><dd>${escapeHtml(finding.detection)}</dd>
      <dt>Why it matters</dt><dd>${escapeHtml(finding.impact)}</dd>
      <dt>Fix</dt><dd>${escapeHtml(finding.remediation)}</dd>
      <dt>Verify</dt><dd>${escapeHtml(finding.verification)}</dd>
    </dl>
    ${reference}
  </article>`;
}

function categorySection(name, category) {
  const findings = category.findings || [];
  const checks = category.checks || [];
  const skipped = category.skipped || [];
  const count = findings.length;
  const cards = findings.length
    ? findings.map(findingCard).join("")
    : `<p class="empty">No findings in this category for this scan.</p>`;
  const skippedHtml = skipped.length
    ? `<details><summary>${skipped.length} skipped or limited check(s)</summary><ul>${skipped.map((item) => `<li><strong>${escapeHtml(item.check)}:</strong> ${escapeHtml(item.reason)}</li>`).join("")}</ul></details>`
    : "";
  const checksHtml = checks.length
    ? `<details><summary>${checks.length} check(s)</summary><ul>${checks.map((item) => `<li><code>${escapeHtml(item.id)}</code> — ${escapeHtml(item.status)}${item.value !== undefined ? ` (${escapeHtml(item.value)}${item.unit ? ` ${escapeHtml(item.unit)}` : ""})` : ""}${item.reason ? `: ${escapeHtml(item.reason)}` : ""}</li>`).join("")}</ul></details>`
    : "";
  return `<section class="category" id="category-${escapeHtml(name)}">
    <div class="category-head"><h2>${escapeHtml(name[0].toUpperCase() + name.slice(1))}</h2><span class="badge">${count} finding${count === 1 ? "" : "s"}</span></div>
    ${category.caveat ? `<p class="caveat">${escapeHtml(category.caveat)}</p>` : ""}
    ${cards}
    ${checksHtml}
    ${skippedHtml}
  </section>`;
}

function siteSection(report) {
  const crawl = report.crawl;
  if (!crawl) return "";
  const pages = crawl.pages || [];
  const coverage = crawl.coverage || {};
  const rows = pages.map((page) => `<tr><td><a href="${escapeHtml(page.url)}" rel="noreferrer">${escapeHtml(page.url)}</a></td><td>${escapeHtml(page.state)}</td><td>${page.depth}</td><td>${(page.findings || []).length}</td></tr>`).join("");
  const common = (report.summary?.mostCommon || []).slice(0, 5)
    .map((finding) => `<li>${escapeHtml(finding.title)} — ${finding.pageCount} page(s)</li>`).join("");
  return `<section class="panel"><h2>Site crawl</h2>
    <p><strong>Discovered:</strong> ${coverage.discovered || 0} · <strong>Audited:</strong> ${coverage.audited || 0} · <strong>Skipped:</strong> ${coverage.skipped || 0} · <strong>Failed:</strong> ${coverage.failed || 0}</p>
    <p><strong>Robots:</strong> ${escapeHtml(crawl.robots?.status || "unknown")} ${crawl.robots?.error ? `(${escapeHtml(crawl.robots.error)})` : ""} · <strong>Sitemap:</strong> ${escapeHtml(crawl.sitemap?.status || "unknown")}</p>
    <p class="caveat">Limits: ${coverage.maxPages || "?"} pages, depth ${coverage.maxDepth || 0}, ${coverage.maxConcurrency || "?"} concurrent. This is bounded coverage, not a complete-site claim.</p>
    ${common ? `<details><summary>Most common issues</summary><ul>${common}</ul></details>` : ""}
    <details><summary>Page results (${pages.length})</summary><table><thead><tr><th>URL</th><th>State</th><th>Depth</th><th>Findings</th></tr></thead><tbody>${rows || "<tr><td colspan=\"4\">No pages were audited.</td></tr>"}</tbody></table></details>
  </section>`;
}

export function renderHtml(report) {
  const title = `WebTimize Inspector — ${report.target?.requestedUrl || "scan"}`;
  const counts = report.summary?.findings || {};
  const categories = Object.entries(report.categories || {});
  const metrics = report.categories?.performance?.metrics;
  const metricHtml = metrics ? `<section class="panel"><h2>Performance observations</h2>
    <p class="caveat">${escapeHtml(metrics.caveat)}</p>
    <table><thead><tr><th>Metric</th><th>Median</th><th>Min</th><th>Max</th><th>Runs</th></tr></thead><tbody>
    ${[
      ["LCP", "lcpMs", "ms"], ["FCP", "fcpMs", "ms"], ["CLS", "cls", ""],
      ["TTFB", "ttfbMs", "ms"], ["Load", "loadMs", "ms"], ["Long tasks", "longTasks", ""],
      ["Requests", "requests", ""], ["Transfer", "transferBytes", "bytes"]
    ].map(([label, key, unit]) => {
      const value = metrics[key];
      if (!value) return `<tr><td>${label}</td><td colspan="4">unavailable</td></tr>`;
      const show = (number) => unit === "bytes" ? formatBytes(number) : `${Math.round(number * 1000) / 1000}${unit ? ` ${unit}` : ""}`;
      return `<tr><td>${label}</td><td>${show(value.median)}</td><td>${show(value.min)}</td><td>${show(value.max)}</td><td>${value.count}</td></tr>`;
    }).join("")}
    </tbody></table></section>` : "";
  const skipped = (report.limitations || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const viewport = report.configuration?.viewport;
  const viewportText = typeof viewport === "string"
    ? viewport.replace("x", "×")
    : `${viewport?.width || "?"}×${viewport?.height || "?"}`;
  const json = JSON.stringify(report).replaceAll("<", "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
${REPORT_CSS}
</style>
</head>
<body><main>
<header>
<p class="eyebrow">WebTimize report</p>
<h1>Inspector</h1>
<p class="url">${escapeHtml(report.target?.requestedUrl || "")}</p>
<p>Scanned ${escapeHtml(report.startedAt)} · ${escapeHtml(report.tool?.name || "webtim-inspector")} ${escapeHtml(report.tool?.version || "")}</p>
<div><span class="status">${escapeHtml(report.status)}</span></div>
</header>
<section class="summary">
<div><strong>${report.summary?.total || 0}</strong>findings</div>
${SEVERITY_ORDER.map((severity) => `<div><strong>${counts[severity] || 0}</strong>${escapeHtml(SEVERITY_LABELS[severity])}</div>`).join("")}
</section>
<section class="panel"><h2>Scan configuration</h2>
<p><strong>Final URL:</strong> <span class="url">${escapeHtml(report.target?.finalUrl || "unavailable")}</span></p>
<p><strong>Viewport:</strong> ${escapeHtml(viewportText)} · <strong>Runs:</strong> ${escapeHtml(report.configuration?.runs || 0)} · <strong>Browser:</strong> ${escapeHtml(report.environment?.browser?.version || report.environment?.browserError || "unavailable")}</p>
<p class="caveat">The scan ran locally. It did not upload page content or require an account. Synthetic lab results are not field data.</p>
</section>
${metricHtml}
${siteSection(report)}
${categories.map(([name, category]) => categorySection(name, category)).join("")}
<section class="panel"><h2>Limitations</h2><ul>${skipped || "<li>None recorded.</li>"}</ul></section>
<footer>Generated by WebTimize Inspector ${escapeHtml(report.tool?.version || "")}. No claim of WCAG conformance, security certification or search-engine ranking is made.</footer>
<script type="application/json" id="webtim-report">${json}</script>
</main></body></html>`;
}

export function renderCli(report) {
  const lines = [
    `WebTimize Inspector ${report.tool?.version || ""}`,
    `Target: ${report.target?.requestedUrl || ""}`,
    `Status: ${report.status}`,
    `Findings: ${report.summary?.total || 0} (${SEVERITY_ORDER.map((severity) => `${severity}:${report.summary?.findings?.[severity] || 0}`).join(", ")})`,
    ""
  ];
  if (report.crawl) {
    const coverage = report.crawl.coverage || {};
    lines.push(`Crawl: discovered ${coverage.discovered || 0}, audited ${coverage.audited || 0}, skipped ${coverage.skipped || 0}, failed ${coverage.failed || 0}`);
    lines.push(`Robots: ${report.crawl.robots?.status || "unknown"} · Sitemap: ${report.crawl.sitemap?.status || "unknown"}`);
    for (const page of report.crawl.pages || []) {
      lines.push(`  [${page.state}] ${page.url} — ${(page.findings || []).length} finding(s)`);
    }
    lines.push("");
  }
  for (const [name, category] of Object.entries(report.categories || {})) {
    lines.push(`${name}: ${category.findings?.length || 0} finding(s), ${category.checks?.length || 0} check(s)`);
    for (const finding of (category.findings || []).slice(0, 10)) {
      lines.push(`  [${finding.severity}] ${finding.title} (${finding.ruleId})`);
    }
    if ((category.findings || []).length > 10) lines.push(`  … ${category.findings.length - 10} more`);
  }
  lines.push("", "This is a synthetic lab scan and a screening result, not a conformance or security certification.");
  return lines.join("\n");
}

export function compareReports(before, after) {
  if (!before?.findings || !after?.findings) throw new Error("both files must be WebTimize Inspector reports");
  const beforeIds = new Map(before.findings.map((finding) => [finding.id, finding]));
  const afterIds = new Map(after.findings.map((finding) => [finding.id, finding]));
  const added = after.findings.filter((finding) => !beforeIds.has(finding.id));
  const absent = before.findings.filter((finding) => !afterIds.has(finding.id));
  const persistent = after.findings.filter((finding) => beforeIds.has(finding.id));
  const site = Boolean(before.crawl && after.crawl);
  const beforePages = new Set((before.crawl?.pages || []).map((page) => pageIdentity(page.url)));
  const afterPages = new Set((after.crawl?.pages || []).map((page) => pageIdentity(page.url)));
  const resolved = site
    ? absent.filter((finding) => !(finding.affectedPages || []).length || finding.affectedPages.some((page) => afterPages.has(pageIdentity(page))))
    : absent;
  const unscannedFindings = site
    ? absent.filter((finding) => (finding.affectedPages || []).length && finding.affectedPages.every((page) => !afterPages.has(pageIdentity(page))))
    : [];
  const newlyAffected = site ? after.findings
    .map((finding) => ({ ...finding, pages: (finding.affectedPages || []).filter((page) => !beforePages.has(pageIdentity(page))) }))
    .filter((finding) => finding.pages.length) : [];
  const noLongerAffected = site ? before.findings
    .map((finding) => ({ ...finding, pages: (finding.affectedPages || []).filter((page) => !afterPages.has(pageIdentity(page))) }))
    .filter((finding) => finding.pages.length) : [];
  const notScanned = site ? (before.crawl?.pages || [])
    .filter((page) => !afterPages.has(pageIdentity(page.url)))
    .map((page) => page.url) : [];
  const metricDelta = {};
  for (const key of ["lcpMs", "cls", "ttfbMs", "requests", "transferBytes", "longTasks"]) {
    const oldValue = before.categories?.performance?.metrics?.[key]?.median;
    const newValue = after.categories?.performance?.metrics?.[key]?.median;
    if (Number.isFinite(oldValue) && Number.isFinite(newValue)) metricDelta[key] = newValue - oldValue;
  }
  return {
    before: { scanId: before.scanId, target: before.target?.requestedUrl, startedAt: before.startedAt, total: before.findings.length },
    after: { scanId: after.scanId, target: after.target?.requestedUrl, startedAt: after.startedAt, total: after.findings.length },
    added,
    resolved,
    persistent,
    ...(site ? { newlyAffected, noLongerAffected, notScanned, unscannedFindings } : {}),
    metricDelta,
    caveat: site
      ? "A finding disappears only when its fingerprint changes; pages absent from the second crawl are listed separately and are not treated as fixed."
      : "A finding disappears only when its fingerprint changes; resolved means absent from the second report, not independently verified as fixed."
  };
}

export function renderComparisonHtml(comparison) {
  const list = (findings) => findings.length
    ? `<ul>${findings.map((finding) => `<li><span class="pill">${escapeHtml(finding.severity)}</span> ${escapeHtml(finding.title)} <code>${escapeHtml(finding.ruleId)}</code></li>`).join("")}</ul>`
    : "<p>None.</p>";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WebTimize comparison</title>
<style>${REPORT_CSS}
main { max-width:900px; }
h2 { margin-top:26px; }
.pill { margin-right:5px; }
</style></head><body><main>
<header><p class="eyebrow">WebTimize report</p><h1>Inspector comparison</h1></header>
<p><strong>Before:</strong> ${escapeHtml(comparison.before.target || "")} (${comparison.before.total} findings)<br>
<strong>After:</strong> ${escapeHtml(comparison.after.target || "")} (${comparison.after.total} findings)</p>
<p class="caveat">${escapeHtml(comparison.caveat)}</p>
<h2>New findings (${comparison.added.length})</h2>${list(comparison.added)}
<h2>Absent from the second report (${comparison.resolved.length})</h2>${list(comparison.resolved)}
<h2>Still present (${comparison.persistent.length})</h2>${list(comparison.persistent)}
${comparison.newlyAffected ? `<h2>Newly affected pages (${comparison.newlyAffected.length})</h2>${list(comparison.newlyAffected)}` : ""}
${comparison.noLongerAffected ? `<h2>No-longer-affected pages (${comparison.noLongerAffected.length})</h2>${list(comparison.noLongerAffected)}` : ""}
${comparison.notScanned ? `<h2>Pages not scanned in the later run (${comparison.notScanned.length})</h2><ul>${comparison.notScanned.map((page) => `<li>${escapeHtml(page)}</li>`).join("")}</ul>` : ""}
${comparison.unscannedFindings ? `<h2>Findings on unscanned pages (${comparison.unscannedFindings.length})</h2>${list(comparison.unscannedFindings)}` : ""}
<h2>Performance median deltas</h2><pre>${escapeHtml(JSON.stringify(comparison.metricDelta, null, 2))}</pre>
</main></body></html>`;
}
