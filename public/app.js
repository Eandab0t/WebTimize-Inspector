const token = document.body.dataset.token;
const state = { activeJob: null, report: null, history: [], filter: "all", category: "all" };

const $ = (selector) => document.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const severityLabels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Information" };

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", "x-inspector-token": token, ...(options.headers || {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function setText(selector, text) {
  const node = $(selector);
  if (node) node.textContent = text;
}

function showError(message) {
  setText("#form-error", message);
}

function setJobState(state, label) {
  const badge = $("#job-state");
  if (!badge) return;
  badge.textContent = label;
  badge.className = `badge ${state}`;
}

function renderSummary(report) {
  const summary = $("#summary");
  summary.replaceChildren();
  const counts = report.summary?.findings || {};
  const values = [
    ["Total", report.summary?.total || 0],
    ["Critical", counts.critical || 0],
    ["High", counts.high || 0],
    ["Medium", counts.medium || 0],
    ["Low", counts.low || 0],
    ["Info", counts.informational || 0]
  ];
  for (const [label, value] of values) {
    const box = el("div");
    box.append(el("strong", "", String(value)), el("span", "", label));
    summary.append(box);
  }
}

function renderCategories(report) {
  const container = $("#categories");
  container.replaceChildren();
  for (const [name, category] of Object.entries(report.categories || {})) {
    const row = el("div", "category-row");
    row.append(el("strong", "", name));
    const skip = category.skipped?.length ? ` · ${category.skipped.length} limited` : "";
    row.append(el("span", "", `${category.findings?.length || 0} findings${skip}`));
    container.append(row);
  }
}

function renderMetrics(report) {
  const container = $("#metrics");
  container.replaceChildren();
  const metrics = report.categories?.performance?.metrics;
  setText("#metric-caveat", metrics?.caveat || "Performance was not selected or no browser data was available.");
  if (!metrics) return;
  const table = el("table", "metrics-table");
  const head = el("tr");
  for (const value of ["Metric", "Median", "Min", "Max"]) head.append(el("th", "", value));
  table.append(head);
  const rows = [
    ["LCP", metrics.lcpMs, " ms"], ["FCP", metrics.fcpMs, " ms"], ["CLS", metrics.cls, ""],
    ["TTFB", metrics.ttfbMs, " ms"], ["Long tasks", metrics.longTasks, ""], ["Requests", metrics.requests, ""]
  ];
  for (const [label, metric, unit] of rows) {
    const row = el("tr");
    row.append(el("td", "", label));
    if (!metric) {
      const unavailable = el("td", "", "unavailable");
      unavailable.colSpan = 3;
      row.append(unavailable);
    } else {
      row.append(el("td", "", `${Math.round(metric.median * 1000) / 1000}${unit}`));
      row.append(el("td", "", `${Math.round(metric.min * 1000) / 1000}${unit}`));
      row.append(el("td", "", `${Math.round(metric.max * 1000) / 1000}${unit}`));
    }
    table.append(row);
  }
  container.append(table);
}

function findingNode(finding) {
  const article = el("article", `finding severity-${finding.severity}`);
  const head = el("div", "finding-head");
  head.append(el("span", "pill", severityLabels[finding.severity] || finding.severity));
  head.append(el("span", "confidence", `${finding.confidence} confidence`));
  article.append(head, el("h3", "", finding.title), el("p", "", finding.description));
  if (finding.element) {
    const element = el("p", "muted", "Element: ");
    element.append(el("code", "", finding.element));
    article.append(element);
  }
  if (finding.evidence) article.append(el("pre", "evidence", finding.evidence));
  if (finding.affectedPages?.length) {
    article.append(el("p", "muted", `Affects ${finding.affectedPages.length} page(s):`));
    const pages = el("ul");
    for (const page of finding.affectedPages.slice(0, 20)) pages.append(el("li", "", page));
    article.append(pages);
  }
  const details = el("dl");
  for (const [term, value] of [
    ["Rule", finding.ruleId], ["Detection", finding.detection],
    ["Why it matters", finding.impact], ["How to fix", finding.remediation],
    ["How to verify", finding.verification]
  ]) {
    details.append(el("dt", "", term), el("dd", "", value));
  }
  article.append(details);
  if (finding.reference) {
    const link = el("a", "", "Reference documentation");
    link.href = finding.reference;
    link.rel = "noreferrer";
    article.append(link);
  }
  return article;
}

function renderFindings(report) {
  const container = $("#findings");
  container.replaceChildren();
  const findings = (report.findings || []).filter((finding) =>
    (state.filter === "all" || finding.severity === state.filter) &&
    (state.category === "all" || finding.category === state.category));
  if (!findings.length) {
    container.append(el("p", "muted", state.filter === "all" && state.category === "all" ? "No findings in this scan." : "No findings match these filters."));
    return;
  }
  const grouped = Object.groupBy ? Object.groupBy(findings, (finding) => finding.category) : null;
  if (grouped) {
    for (const [category, items] of Object.entries(grouped)) {
      container.append(el("h3", "", category));
      items.forEach((finding) => container.append(findingNode(finding)));
    }
  } else {
    findings.forEach((finding) => container.append(findingNode(finding)));
  }
}

function renderCategoryFilter(report) {
  const select = $("#category-filter");
  select.replaceChildren(new Option("All categories", "all"));
  for (const name of Object.keys(report.categories || {})) select.append(new Option(name, name));
  if (![...select.options].some((option) => option.value === state.category)) state.category = "all";
  select.value = state.category;
}

function renderHistory() {
  const container = $("#history");
  container.replaceChildren();
  if (!state.history.length) {
    container.append(el("p", "muted", "No scans yet."));
    return;
  }
  for (const item of state.history.slice().reverse()) {
    const row = el("div", "history-row");
    const label = el("div");
    label.append(el("strong", "", item.url || "local project"));
    label.append(el("div", "muted", `${item.status} · ${item.total} findings · ${new Date(item.startedAt).toLocaleString()}`));
    const open = el("button", "ghost", "Open");
    open.type = "button";
    open.addEventListener("click", () => loadReport(item.scanId));
    row.append(label, open);
    container.append(row);
  }
  for (const select of [$("#before"), $("#after")]) {
    const previous = select.value;
    select.replaceChildren();
    for (const item of state.history.slice().reverse()) {
      const option = el("option", "", `${item.url || "local"} — ${new Date(item.startedAt).toLocaleString()}`);
      option.value = item.scanId;
      select.append(option);
    }
    if (previous) select.value = previous;
  }
}

function renderSite(report) {
  const panel = $("#site-panel");
  const coverage = $("#site-coverage");
  const pages = $("#site-pages");
  if (!report.crawl) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const c = report.crawl.coverage || {};
  coverage.replaceChildren();
  const summary = el("p", "", `Discovered ${c.discovered || 0} · audited ${c.audited || 0} · skipped ${c.skipped || 0} · failed ${c.failed || 0} · limit ${c.maxPages || "?"} pages / depth ${c.maxDepth ?? "?"} / ${c.maxConcurrency || "?"} concurrent`);
  coverage.append(summary);
  const meta = el("p", "caveat", `Robots: ${report.crawl.robots?.status || "unknown"} · Sitemap: ${report.crawl.sitemap?.status || "unknown"}. This is bounded coverage, not a complete-site claim.`);
  coverage.append(meta);
  pages.replaceChildren();
  const table = el("table", "metrics-table");
  const head = el("tr");
  for (const label of ["Page", "State", "Depth", "Findings"]) head.append(el("th", "", label));
  table.append(head);
  for (const page of report.crawl.pages || []) {
    const row = el("tr");
    const cell = el("td");
    const details = el("details");
    details.append(el("summary", "", page.url));
    if (page.error) details.append(el("p", "error", page.error));
    for (const finding of page.findings || []) {
      details.append(el("p", "muted", `[${finding.severity}] ${finding.title}`));
    }
    cell.append(details);
    row.append(cell, el("td", "", page.state), el("td", "", String(page.depth)), el("td", "", String((page.findings || []).length)));
    table.append(row);
  }
  pages.append(table);
}

function showReport(report) {
  state.report = report;
  $("#result-panel").classList.remove("hidden");
  setText("#result-url", report.target?.requestedUrl || report.target?.finalUrl || "");
  const resultState = $("#result-status");
  resultState.textContent = report.status || "complete";
  resultState.className = `badge ${report.status || "complete"}`;
  setText("#result-meta", `${report.status} · ${report.findings?.length || 0} findings · ${new Date(report.startedAt).toLocaleString()} · ${report.environment?.browser?.version || "browser unavailable"}`);
  $("#json-link").href = `/api/report/${encodeURIComponent(report.scanId)}`;
  $("#html-link").href = `/api/report/${encodeURIComponent(report.scanId)}.html`;
  renderSummary(report);
  renderCategories(report);
  renderCategoryFilter(report);
  renderMetrics(report);
  renderSite(report);
  renderFindings(report);
  const limitations = $("#limitations");
  limitations.replaceChildren();
  for (const item of report.limitations || []) limitations.append(el("li", "", item));
  if (!(report.limitations || []).length) limitations.append(el("li", "", "None recorded."));
}

async function loadReport(id) {
  try {
    const body = await api(`/api/scans/${encodeURIComponent(id)}`);
    if (body.report) showReport(body.report);
  } catch (error) {
    showError(error.message);
  }
}

async function refreshHistory() {
  try {
    const body = await api("/api/scans");
    state.history = body.scans || [];
    renderHistory();
  } catch {
    // The dashboard may be shutting down; the scan result remains usable.
  }
}

function setProgress(value, text) {
  $("#progress-bar").style.width = `${Math.min(100, Math.max(5, value))}%`;
  $("#progress").setAttribute("aria-valuenow", String(Math.round(Math.min(100, Math.max(0, value)))));
  setText("#job-detail", text);
}

function renderJobCoverage(coverage) {
  if (!coverage) {
    setText("#job-coverage", "");
    return;
  }
  setText("#job-coverage", `Discovered ${coverage.discovered || 0} · completed ${coverage.audited || 0} · skipped ${coverage.skipped || 0} · failed ${coverage.failed || 0}`);
}

async function pollJob(id) {
  const body = await api(`/api/scans/${encodeURIComponent(id)}`);
  if (body.job?.status === "running") {
    setJobState("running", "Running");
    setProgress(body.job.progress || 15, body.job.message || "Scanning…");
    renderJobCoverage(body.job.coverage);
    setTimeout(() => pollJob(id).catch((error) => showError(error.message)), 600);
    return;
  }
  if (["done", "cancelled"].includes(body.job?.status) && body.report) {
    setProgress(100, body.job.status === "cancelled" ? "Scan cancelled; partial report saved" : "Scan complete");
    setJobState(body.job.status === "cancelled" ? "cancelled" : "complete", body.job.status === "cancelled" ? "Cancelled" : "Complete");
    setText("#job-title", body.job.status === "cancelled" ? "Scan cancelled" : "Scan complete");
    $("#cancel").disabled = true;
    setTimeout(() => $("#job-panel").classList.add("hidden"), 1000);
    showReport(body.report);
    await refreshHistory();
    return;
  }
  throw new Error(body.job?.error || "The scan did not return a report.");
}

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const button = event.submitter || $("#scan-form button[type=submit]");
  button.disabled = true;
  const payload = {
    url: $("#url").value.trim() || null,
    localDir: $("#local-dir").value.trim() || null,
    viewport: $("#viewport").value,
    runs: Number($("#runs").value),
    maxLinks: Number($("#max-links").value),
    crawl: $("#crawl").checked,
    maxPages: Number($("#max-pages").value),
    maxDepth: Number($("#max-depth").value),
    maxConcurrency: 2,
    categories: [...document.querySelectorAll('input[name="category"]:checked')].map((input) => input.value),
    allowPrivate: Boolean($("#local-dir").value.trim())
  };
  if (!payload.url && !payload.localDir) {
    showError("Enter a URL or select a local project directory.");
    button.disabled = false;
    return;
  }
  if (!payload.categories.length) {
    showError("Select at least one audit category.");
    button.disabled = false;
    return;
  }
  try {
    const body = await api("/api/scan", { method: "POST", body: JSON.stringify(payload) });
    state.activeJob = body.id;
    $("#job-panel").classList.remove("hidden");
    $("#result-panel").classList.add("hidden");
    setText("#job-title", "Scanning…");
    setProgress(5, "Validating target");
    setJobState("running", "Running");
    $("#cancel").disabled = false;
    renderJobCoverage(null);
    pollJob(body.id).catch((error) => {
      showError(error.message);
      setText("#job-detail", error.message);
      setText("#job-title", "Scan failed");
      setJobState("failed", "Failed");
    });
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#cancel").addEventListener("click", async () => {
  if (!state.activeJob) return;
  try {
    await api(`/api/scans/${encodeURIComponent(state.activeJob)}/cancel`, { method: "POST", body: "{}" });
    setText("#job-detail", "Cancelling…");
  } catch (error) {
    showError(error.message);
  }
});

async function downloadReport(pathname, filename) {
  try {
    const response = await fetch(pathname, { headers: { "x-inspector-token": token } });
    if (!response.ok) throw new Error(`Download failed (${response.status})`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    showError(error.message);
  }
}

$("#json-link").addEventListener("click", (event) => {
  event.preventDefault();
  if (state.report) downloadReport(`/api/report/${encodeURIComponent(state.report.scanId)}`, `webtim-inspector-${state.report.scanId}.json`);
});
$("#html-link").addEventListener("click", (event) => {
  event.preventDefault();
  if (state.report) downloadReport(`/api/report/${encodeURIComponent(state.report.scanId)}.html`, `webtim-inspector-${state.report.scanId}.html`);
});

$("#clear").addEventListener("click", () => {
  $("#scan-form").reset();
  $("#result-panel").classList.add("hidden");
  $("#job-panel").classList.add("hidden");
  showError("");
});

$("#filters").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-severity]");
  if (!button || !state.report) return;
  state.filter = button.dataset.severity;
  for (const item of $("#filters").querySelectorAll("button")) item.classList.toggle("active", item === button);
  for (const item of $("#filters").querySelectorAll("button")) item.setAttribute("aria-pressed", String(item === button));
  renderFindings(state.report);
});

$("#category-filter").addEventListener("change", (event) => {
  state.category = event.target.value;
  if (state.report) renderFindings(state.report);
});

$("#compare").addEventListener("click", async () => {
  const before = $("#before").value;
  const after = $("#after").value;
  const container = $("#comparison");
  container.replaceChildren();
  if (!before || !after || before === after) {
    container.append(el("p", "error", "Choose two different scans."));
    return;
  }
  try {
    const result = await api(`/api/compare?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`);
    container.append(el("h3", "", `${result.added.length} new · ${result.resolved.length} absent · ${result.persistent.length} persistent`));
    container.append(el("p", "caveat", result.caveat));
    for (const [label, items] of [["New", result.added], ["Absent", result.resolved]]) {
      if (!items.length) continue;
      container.append(el("h4", "", label));
      const list = el("ul");
      for (const finding of items) list.append(el("li", "", `[${finding.severity}] ${finding.title} (${finding.ruleId})`));
      container.append(list);
    }
    for (const [label, items] of [["Newly affected", result.newlyAffected], ["No longer affected", result.noLongerAffected]]) {
      if (!items?.length) continue;
      container.append(el("h4", "", label));
      const list = el("ul");
      for (const finding of items) list.append(el("li", "", `[${finding.severity}] ${finding.title} — ${(finding.pages || []).length} page(s)`));
      container.append(list);
    }
    if (result.notScanned?.length) container.append(el("p", "caveat", `${result.notScanned.length} page(s) were not scanned in the later run and are not treated as resolved.`));
    if (result.unscannedFindings?.length) {
      container.append(el("h4", "", "Findings on unscanned pages"));
      const list = el("ul");
      for (const finding of result.unscannedFindings) list.append(el("li", "", `[${finding.severity}] ${finding.title} (${finding.ruleId})`));
      container.append(list);
    }
  } catch (error) {
    container.append(el("p", "error", error.message));
  }
});

const filterBar = el("div");
for (const severity of ["all", "critical", "high", "medium", "low", "informational"]) {
  const button = el("button", severity === "all" ? "active" : "", severity === "all" ? "All" : severityLabels[severity]);
  button.type = "button";
  button.dataset.severity = severity;
  button.setAttribute("aria-pressed", String(severity === "all"));
  filterBar.append(button);
}
$("#filters").replaceChildren(...filterBar.children);

refreshHistory();
