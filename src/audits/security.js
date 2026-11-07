import { createFinding } from "../core/findings.js";

function add(findings, input) {
  findings.push(createFinding({ category: "security", ...input }));
}

function header(headers, name) {
  return headers?.[name.toLowerCase()] ?? null;
}

export function securityAudit({ http, browser, url }) {
  const findings = [];
  const checks = [];
  const skipped = [
    { check: "penetration-testing", reason: "Inspector performs passive configuration checks only; it does not test for exploitable vulnerabilities." },
    { check: "authentication and authorization", reason: "No credentials are supplied and no protected workflow is exercised." },
    { check: "third-party infrastructure", reason: "CDN, WAF and origin behavior cannot be fully separated from this response." }
  ];
  if (!http?.ok) {
    add(findings, {
      ruleId: "target-unreachable",
      title: "The target could not be inspected over HTTP",
      description: `The controlled request failed: ${http?.error?.message || "unknown error"}. This is not evidence that the site is insecure.`,
      severity: "medium",
      confidence: "high",
      evidence: http?.error?.code || "unknown error",
      url,
      detection: "Controlled HTTP request",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
      remediation: "Confirm the URL, DNS, TLS and server availability, then run the scan again.",
      impact: "No security headers or TLS configuration can be assessed.",
      verification: "Repeat the request from the scanner and from a separate client."
    });
    return { findings, checks: [{ id: "security.http", status: "failed" }], skipped };
  }

  const headers = http.headers || {};
  const finalUrl = http.finalUrl || url;
  const isHttps = new URL(finalUrl).protocol === "https:";
  checks.push(
    { id: "security.https", status: isHttps ? "observed" : "not-https" },
    { id: "security.headers", status: "observed", value: Object.keys(headers).length, unit: "headers" }
  );

  if (!isHttps) {
    add(findings, {
      ruleId: "no-https",
      title: "The audited URL is served over HTTP",
      description: "The final response used http, so transport encryption and certificate validity could not be verified. A redirect from HTTP to HTTPS is a separate observation.",
      severity: "high",
      confidence: "high",
      evidence: finalUrl,
      url: finalUrl,
      detection: "Final response URL scheme",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
      remediation: "Serve all public pages over HTTPS, redirect HTTP requests and enable HSTS after the HTTPS deployment is stable.",
      impact: "Traffic can be read or modified in transit.",
      verification: "Request the HTTP URL and confirm a permanent redirect to the HTTPS URL."
    });
  } else if (http.tls) {
    checks.push({ id: "security.tls", status: http.tls.authorized ? "observed-valid" : "observed-invalid" });
    if (!http.tls.authorized || http.tls.authorizationError) {
      add(findings, {
        ruleId: "invalid-tls",
        title: "The TLS connection was not trusted",
        description: `Node reported: ${http.tls.authorizationError || "certificate chain was not authorized"}. This may be an expired, self-signed or misconfigured certificate.`,
        severity: "high",
        confidence: "high",
        evidence: JSON.stringify(http.tls),
        url: finalUrl,
        detection: "TLS peer certificate validation",
        reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        remediation: "Install a valid certificate chain, renew before expiry and verify the hostname and intermediate certificates.",
        impact: "Browsers may warn or refuse to connect.",
        verification: "Use a browser and an independent TLS checker; confirm the certificate chain and expiry."
      });
    }
    const validTo = http.tls.validTo ? Date.parse(http.tls.validTo) : NaN;
    if (Number.isFinite(validTo) && validTo < Date.now()) {
      add(findings, {
        ruleId: "expired-tls",
        title: "The TLS certificate is expired",
        description: `The peer certificate reports validTo=${http.tls.validTo}.`,
        severity: "high",
        confidence: "high",
        evidence: JSON.stringify(http.tls),
        url: finalUrl,
        detection: "TLS peer certificate dates",
        reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        remediation: "Renew the certificate and deploy the full chain before expiry.",
        impact: "Browsers may block the site or show a security warning.",
        verification: "Reconnect and confirm the new certificate's dates."
      });
    }
  } else {
    checks.push({ id: "security.tls", status: "unavailable" });
    skipped.push({ check: "tls-certificate", reason: "TLS peer certificate details were not exposed by this connection." });
  }

  if (!header(headers, "strict-transport-security")) {
    add(findings, {
      ruleId: "missing-hsts",
      title: "Strict-Transport-Security is missing",
      description: isHttps
        ? "The HTTPS response did not include HSTS. HSTS tells compatible browsers to use HTTPS for future requests; it is a configuration observation, not proof of a compromise."
        : "HSTS is only meaningful once the site is served over HTTPS.",
      severity: isHttps ? "low" : "informational",
      confidence: "high",
      evidence: "Strict-Transport-Security header absent",
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
      remediation: "After confirming every subdomain supports HTTPS, send HSTS with a deliberate max-age; start with a short max-age and test.",
      impact: "A browser may make an initial insecure request before upgrading.",
      verification: "Inspect the production response and test a fresh browser profile after the change."
    });
  }

  const csp = header(headers, "content-security-policy");
  if (!csp) {
    add(findings, {
      ruleId: "missing-csp",
      title: "Content-Security-Policy is missing",
      description: "No CSP header was observed. CSP can reduce some injection impact, but a missing CSP alone does not prove a site is vulnerable.",
      severity: "medium",
      confidence: "high",
      evidence: "Content-Security-Policy header absent",
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
      remediation: "Define a policy that fits the site's actual script, style, image and connection requirements; test in report-only mode first.",
      impact: "There is less browser-enforced containment if an injection flaw exists.",
      verification: "Deploy in report-only mode, inspect violations, then enforce and test critical user journeys."
    });
  } else {
    checks.push({ id: "security.csp", status: "observed" });
    if (/unsafe-inline|unsafe-eval/i.test(csp)) {
      add(findings, {
        ruleId: "csp-unsafe-directives",
        title: "The Content-Security-Policy contains broad unsafe directives",
        description: "The policy contains 'unsafe-inline' or 'unsafe-eval'. Context matters: some frameworks require these, but they reduce the protection CSP can provide.",
        severity: "low",
        confidence: "high",
        evidence: csp,
        url: finalUrl,
        detection: "Response header inspection",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        remediation: "Replace unsafe inline/eval usage with nonces, hashes or external files where feasible; verify the site after each change.",
        impact: "An injected script may be more likely to execute.",
        verification: "Review CSP reports and repeat the site's critical flows after tightening."
      });
    }
  }

  if (!header(headers, "x-content-type-options")) {
    add(findings, {
      ruleId: "missing-nosniff",
      title: "X-Content-Type-Options is missing",
      description: "The response did not include X-Content-Type-Options: nosniff. This is a low-cost hardening header.",
      severity: "low",
      confidence: "high",
      evidence: "X-Content-Type-Options header absent",
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
      remediation: "Send X-Content-Type-Options: nosniff for all responses and ensure correct Content-Type values.",
      impact: "Some browsers may sniff content in ways that expand the attack surface.",
      verification: "Inspect the response header for a text, script and image resource."
    });
  }

  if (!header(headers, "referrer-policy")) {
    add(findings, {
      ruleId: "missing-referrer-policy",
      title: "Referrer-Policy is missing",
      description: "No Referrer-Policy was observed. The browser default may still be safe, but explicit policy is easier to audit.",
      severity: "low",
      confidence: "high",
      evidence: "Referrer-Policy header absent",
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
      remediation: "Choose a policy such as strict-origin-when-cross-origin and verify analytics and authentication flows.",
      impact: "Sensitive URL paths may be sent in Referer headers when navigating to another origin.",
      verification: "Inspect requests to a controlled external endpoint after deployment."
    });
  }

  if (!header(headers, "permissions-policy")) {
    add(findings, {
      ruleId: "missing-permissions-policy",
      title: "Permissions-Policy is missing",
      description: "No Permissions-Policy was observed. This header can restrict powerful browser features; omission is an informational hardening observation.",
      severity: "informational",
      confidence: "high",
      evidence: "Permissions-Policy header absent",
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
      remediation: "Disable features the site does not use after confirming that embedded content does not require them.",
      impact: "Unused browser capabilities remain available to page code and embedded frames.",
      verification: "Test camera, microphone, geolocation and other feature-dependent flows after applying the policy."
    });
  }

  for (const cookie of http.cookies || []) {
    if (isHttps && !cookie.secure) {
      add(findings, {
        ruleId: "cookie-without-secure",
        title: "A cookie is missing the Secure attribute",
        description: `Cookie ${cookie.name} was set by the HTTPS response without Secure. Cookie values are never included in this report.`,
        severity: "medium",
        confidence: "high",
        evidence: `Set-Cookie name=${cookie.name}; Secure absent`,
        url: finalUrl,
        detection: "Set-Cookie attribute parsing",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        remediation: "Set Secure on authentication and state-changing cookies, then test the full login flow over HTTPS.",
        impact: "The browser could send the cookie over an insecure connection if one is available.",
        verification: "Inspect the Set-Cookie response and browser cookie storage over HTTPS and HTTP."
      });
    }
    if (!cookie.httpOnly) {
      add(findings, {
        ruleId: "cookie-without-httponly",
        title: "A cookie is accessible to JavaScript",
        description: `Cookie ${cookie.name} was not marked HttpOnly. This is not automatically a vulnerability, but session cookies usually should be HttpOnly.`,
        severity: "low",
        confidence: "high",
        evidence: `Set-Cookie name=${cookie.name}; HttpOnly absent`,
        url: finalUrl,
        detection: "Set-Cookie attribute parsing",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        remediation: "Mark cookies HttpOnly unless client-side code demonstrably needs to read them.",
        impact: "A script injection could read the cookie.",
        verification: "Inspect document.cookie behavior and the cookie's attributes after the change."
      });
    }
    if (!cookie.sameSite) {
      add(findings, {
        ruleId: "cookie-without-samesite",
        title: "A cookie has no SameSite attribute",
        description: `Cookie ${cookie.name} had no SameSite attribute. Browser defaults vary; explicit configuration is easier to reason about.`,
        severity: "low",
        confidence: "high",
        evidence: `Set-Cookie name=${cookie.name}; SameSite absent`,
        url: finalUrl,
        detection: "Set-Cookie attribute parsing",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
        remediation: "Choose Lax or Strict unless a verified cross-site flow requires None; pair None with Secure.",
        impact: "Cross-site requests may carry the cookie in ways the site did not intend.",
        verification: "Test cross-site navigation and authentication flows after setting SameSite."
      });
    }
  }

  const mixed = (browser?.runs?.[0]?.pageData?.resources || []).filter((resource) => {
    try {
      return isHttps && new URL(resource.name).protocol === "http:";
    } catch {
      return false;
    }
  });
  if (mixed.length) {
    add(findings, {
      ruleId: "mixed-content",
      title: "The page requested insecure subresources",
      description: `${mixed.length} HTTP resource(s) were requested by an HTTPS page. Modern browsers may block or upgrade some of these requests.`,
      severity: "high",
      confidence: "high",
      evidence: mixed.slice(0, 20).map((resource) => resource.name).join("\n"),
      url: finalUrl,
      detection: "Browser performance resource URLs",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
      remediation: "Load every subresource over HTTPS and update hard-coded HTTP URLs.",
      impact: "Resources may be blocked, tampered with, or weaken the page's security.",
      verification: "Reload the page with devtools and confirm no HTTP requests are made."
    });
  }

  const server = header(headers, "server");
  const poweredBy = header(headers, "x-powered-by");
  if (server || poweredBy) {
    add(findings, {
      ruleId: "technology-disclosure",
      title: "Response headers disclose server technology",
      description: "The response advertises server or framework details. This is an informational fingerprinting observation, not a vulnerability by itself.",
      severity: "informational",
      confidence: "high",
      evidence: [server ? `Server: ${server}` : "", poweredBy ? `X-Powered-By: ${poweredBy}` : ""].filter(Boolean).join("\n"),
      url: finalUrl,
      detection: "Response header inspection",
      reference: "https://owasp.org/www-project-secure-headers/",
      remediation: "Remove unnecessary version/product headers where the server supports it; do not trade away required diagnostics.",
      impact: "Attackers may learn which software to target.",
      verification: "Inspect the response headers after changing server configuration."
    });
  }

  const redirectToHttp = (http.redirects || []).find((redirect) => {
    try {
      return new URL(redirect.location).protocol === "http:" && isHttps;
    } catch {
      return false;
    }
  });
  if (redirectToHttp) {
    add(findings, {
      ruleId: "redirect-to-http",
      title: "A redirect points from HTTPS to HTTP",
      description: "A redirect chain included an HTTPS-to-HTTP hop.",
      severity: "high",
      confidence: "high",
      evidence: `${redirectToHttp.url} -> ${redirectToHttp.location}`,
      url: finalUrl,
      detection: "Redirect chain inspection",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
      remediation: "Keep redirects on HTTPS and update the destination URL.",
      impact: "Subsequent requests may be unencrypted.",
      verification: "Follow the redirect chain and confirm every hop uses HTTPS."
    });
  }

  return { findings, checks, skipped, caveat: "Passive header and TLS observations are not a penetration test and cannot establish that a site is secure." };
}
