import { createFinding } from "../core/findings.js";

function add(findings, input) {
  findings.push(createFinding({ category: "reliability", ...input }));
}

function expectedType(url) {
  try {
    const path = new URL(url).pathname.toLowerCase();
    if (path.endsWith(".css")) return "text/css";
    if (path.endsWith(".js") || path.endsWith(".mjs")) return "javascript";
    if (/\.(png|jpe?g|gif|webp|avif|svg|ico)$/.test(path)) return "image/";
    if (/\.(woff2?|ttf|otf)$/.test(path)) return "font/";
    if (path.endsWith(".json")) return "application/json";
    if (path.endsWith(".html") || path.endsWith("/")) return "text/html";
  } catch {
    return null;
  }
  return null;
}

export function reliabilityAudit({ browser, http, url }) {
  const findings = [];
  const checks = [];
  const skipped = [
    { check: "cross-browser-engine", reason: "Only the locally installed Chrome engine was exercised; this is not Firefox, Safari or WebKit compatibility evidence." },
    { check: "interaction-regression", reason: "The scan loads the page but does not exercise every form, navigation path or game control." }
  ];
  const run = browser?.runs?.[0];
  if (!run) {
    return { findings, checks: [{ id: "reliability.browser", status: "failed" }], skipped };
  }
  const page = run.pageData;
  if (run.navigationError) {
    add(findings, {
      ruleId: "navigation-failed",
      title: "The page did not finish loading",
      description: `The browser navigation reported: ${run.navigationError}`,
      severity: "critical",
      confidence: "high",
      evidence: run.navigationError,
      url,
      detection: "Playwright navigation error",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status",
      remediation: "Check DNS, TLS, redirects, server errors and client-side blockers; retry from a separate client.",
      impact: "Users may see an error or a blank page.",
      verification: "Retry the URL in a clean browser profile and inspect the network panel."
    });
  }
  if (!page) {
    checks.push({ id: "reliability.dom", status: "failed", reason: "page DOM was unavailable" });
    return { findings, checks, skipped };
  }

  checks.push(
    { id: "reliability.page-errors", status: "observed", value: run.pageErrors.length, unit: "exceptions" },
    { id: "reliability.failed-requests", status: "observed", value: run.failedRequests.length, unit: "requests" },
    { id: "reliability.console-errors", status: "observed", value: run.consoleMessages.length, unit: "messages" }
  );

  for (const error of run.pageErrors) {
    add(findings, {
      ruleId: "javascript-exception",
      title: "A JavaScript exception occurred during page load",
      description: "An uncaught exception was reported by the browser. The message is evidence; the affected user flow still needs a manual check.",
      severity: "high",
      confidence: "high",
      evidence: error,
      url,
      detection: "Browser pageerror event",
      reference: "https://developer.mozilla.org/en-US/docs/Web/API/Window/error_event",
      remediation: "Fix the failing script and verify the feature it controls. Do not suppress the exception without understanding it.",
      impact: "A script-driven feature may be broken or partially initialized.",
      verification: "Reload with devtools open, reproduce the action and confirm no exception remains."
    });
  }

  for (const request of run.failedRequests) {
    if (request.url.startsWith("data:") || request.url.startsWith("blob:")) continue;
    add(findings, {
      ruleId: "failed-request",
      title: "A browser request failed",
      description: `${request.type} request failed with ${request.error}.`,
      severity: request.type === "document" ? "critical" : "medium",
      confidence: "high",
      evidence: request.url,
      url: request.url,
      element: request.type,
      detection: "Browser requestfailed event",
      reference: "https://developer.mozilla.org/en-US/docs/Web/API/PerformanceResourceTiming",
      remediation: "Check the URL, server status, TLS, CORS and policy blocking; confirm the resource is required.",
      impact: "The affected resource or feature may be missing.",
      verification: "Request the URL directly and inspect the browser network panel."
    });
  }

  for (const blocked of run.blockedRequests || []) {
    add(findings, {
      ruleId: "blocked-by-policy",
      title: "A browser request was blocked by Inspector policy",
      description: `The request was blocked: ${blocked.reason}. This may be a prohibited private destination or a configured resource limit.`,
      severity: "high",
      confidence: "high",
      evidence: blocked.url,
      url: blocked.url,
      detection: "Playwright request interception",
      reference: "https://owasp.org/www-project-web-security-testing-guide/",
      remediation: "Inspect the URL and remaining request budget. Do not relax the scanner policy without understanding the destination.",
      impact: "The page may be incomplete because a request was intentionally blocked.",
      verification: "Review the requested origin and re-run with a safe, separately authorized configuration if appropriate."
    });
  }

  const errors = (run.responses || []).filter((response) => response.status >= 400);
  for (const response of errors) {
    const severity = response.url === url || response.type === "document" ? "critical" : "medium";
    add(findings, {
      ruleId: "http-error-response",
      title: "A resource returned an HTTP error",
      description: `${response.type} responded with HTTP ${response.status}.`,
      severity,
      confidence: "high",
      evidence: response.url,
      url: response.url,
      element: response.type,
      detection: "Browser response status",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status",
      remediation: "Fix the resource path or server route; if the resource is optional, remove the broken reference.",
      impact: "The page may display a gap, fallback or failed feature.",
      verification: "Request the resource again and confirm its status and content type."
    });
  }

  const brokenImages = (page.images || []).filter((image) => image.complete && (image.width === 0 || image.height === 0));
  for (const image of brokenImages) {
    add(findings, {
      ruleId: "broken-image",
      title: "An image loaded with zero dimensions",
      description: "The browser reported a complete image with no intrinsic width or height. This usually indicates a failed or invalid image response.",
      severity: "medium",
      confidence: "high",
      evidence: image.src,
      url: image.src,
      element: image.selector,
      detection: "DOM image naturalWidth/naturalHeight",
      reference: "https://developer.mozilla.org/en-US/docs/Web/API/HTMLImageElement/naturalWidth",
      remediation: "Fix the image URL, format or response; keep a valid fallback and explicit dimensions.",
      impact: "Users may see an empty image slot and layout may shift.",
      verification: "Open the image URL directly and confirm the rendered natural dimensions."
    });
  }

  const mimeMismatches = [];
  for (const resource of page.resources || []) {
    const response = (run.responses || []).find((item) => item.url === resource.name);
    const expected = expectedType(resource.name);
    const actual = response?.headers?.["content-type"] || "";
    if (expected && actual && !actual.toLowerCase().includes(expected)) {
      mimeMismatches.push({ url: resource.name, expected, actual });
    }
  }
  for (const mismatch of mimeMismatches) {
    add(findings, {
      ruleId: "mime-mismatch",
      title: "A resource content type does not match its extension",
      description: `Expected ${mismatch.expected}, received ${mismatch.actual}. MIME sniffing behavior varies; verify the server configuration.`,
      severity: "low",
      confidence: "medium",
      evidence: mismatch.url,
      url: mismatch.url,
      detection: "Resource extension and response Content-Type",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type",
      remediation: "Serve the correct Content-Type and set X-Content-Type-Options: nosniff after testing.",
      impact: "A browser may refuse or mis-handle the resource.",
      verification: "Request the resource and inspect its headers in a separate client."
    });
  }

  if (page.viewport && page.viewport.scrollWidth > page.viewport.clientWidth + 1) {
    add(findings, {
      ruleId: "horizontal-overflow",
      title: "The page has horizontal overflow at the tested viewport",
      description: `The document scroll width (${page.viewport.scrollWidth}px) exceeds the client width (${page.viewport.clientWidth}px) at the requested viewport. This may be intentional or site-level.`,
      severity: "low",
      confidence: "medium",
      evidence: JSON.stringify(page.viewport),
      url,
      detection: "DOM documentElement scrollWidth/clientWidth",
      reference: "https://developer.mozilla.org/en-US/docs/Web/CSS/overflow",
      remediation: "Inspect the widest element at this viewport and constrain or wrap it; do not hide overflow without checking focusable content.",
      impact: "Mobile and narrow-window users may need to pan horizontally.",
      verification: "Repeat at more than one viewport and inspect the offending element's computed widths."
    });
  }

  if (http?.redirects?.length) {
    checks.push({ id: "reliability.redirects", status: "observed", value: http.redirects.length, unit: "hops" });
    if (http.redirects.length > 2) {
      add(findings, {
        ruleId: "long-redirect-chain",
        title: "The redirect chain has multiple hops",
        description: `${http.redirects.length} redirects were followed before the final response.`,
        severity: "low",
        confidence: "high",
        evidence: http.redirects.map((redirect) => `${redirect.status} ${redirect.url} -> ${redirect.location}`).join("\n"),
        url,
        detection: "Controlled HTTP redirect chain",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
        remediation: "Collapse unnecessary redirects and point the canonical URL directly at the final destination.",
        impact: "Each hop adds latency and another opportunity for an error.",
        verification: "Follow the chain with curl -IL and confirm a single intentional redirect."
      });
    }
  }

  return { findings, checks, skipped, caveat: "This is one Chrome lab load at one viewport. It is not proof of cross-browser compatibility or complete interaction reliability." };
}
