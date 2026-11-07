import { createFinding } from "../core/findings.js";
import { hostLabel } from "../core/util.js";

const TRACKING_PATTERNS = [
  /google-analytics|googletagmanager|gtag|doubleclick|facebook\.net|connect\.facebook|hotjar|segment\.(io|com)|mixpanel|amplitude|fullstory|clarity\.ms|matomo|plausible|umami/i
];

function add(findings, input) {
  findings.push(createFinding({ category: "privacy", ...input }));
}

export function privacyAudit({ browser, http, url }) {
  const findings = [];
  const checks = [];
  const skipped = [
    { check: "legal-compliance", reason: "Observed resources and cookies do not establish compliance with privacy law; consent, purpose and jurisdiction require manual review." },
    { check: "third-party iframe contents", reason: "Cross-origin frame contents are not inspected." },
    { check: "server-side tracking", reason: "Server-side and offline data flows are outside this browser/HTTP scan." }
  ];
  const run = browser?.runs?.[0];
  const page = run?.pageData;
  if (!page) {
    return { findings, checks: [{ id: "privacy.observations", status: "skipped", reason: "browser page data unavailable" }], skipped };
  }
  const targetHost = hostLabel(url);
  const resources = page.resources || [];
  const thirdParty = resources.filter((resource) => {
    try {
      return hostLabel(resource.name) !== targetHost;
    } catch {
      return false;
    }
  });
  const origins = [...new Set(thirdParty.map((resource) => {
    try { return new URL(resource.name).origin; } catch { return ""; }
  }).filter(Boolean))];
  const externalScripts = thirdParty.filter((resource) => resource.initiatorType === "script");
  const externalFonts = thirdParty.filter((resource) => resource.initiatorType === "font" || /\.(woff2?|ttf|otf)(\?|$)/i.test(resource.name));
  const tracking = thirdParty.filter((resource) => TRACKING_PATTERNS.some((pattern) => pattern.test(resource.name)));
  const cookies = run.cookies || [];
  const thirdPartyCookies = cookies.filter((cookie) => {
    const domain = String(cookie.domain || "").replace(/^\./, "").toLowerCase();
    return domain && !domain.endsWith(targetHost) && domain !== targetHost;
  });

  checks.push(
    { id: "privacy.third-party-origins", status: "observed", value: origins.length, unit: "origins" },
    { id: "privacy.third-party-cookies", status: "observed", value: thirdPartyCookies.length, unit: "cookies" },
    { id: "privacy.external-scripts", status: "observed", value: externalScripts.length, unit: "scripts" }
  );

  if (origins.length) {
    add(findings, {
      ruleId: "third-party-connections",
      title: "The page connects to third-party origins",
      description: `${origins.length} external origin(s) were observed. This is an indicator for review, not a conclusion that the site violates privacy law.`,
      severity: "informational",
      confidence: "high",
      evidence: origins.slice(0, 30).join("\n"),
      url,
      detection: "Browser performance resource origins",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Privacy",
      remediation: "Review whether each external dependency is necessary, what data it receives and whether it has a documented purpose and retention policy.",
      impact: "Third-party code and requests expand the site's data and supply-chain surface.",
      verification: "Match each origin to an owner and inspect the request payloads in a controlled test."
    });
  }

  if (externalScripts.length) {
    add(findings, {
      ruleId: "external-scripts",
      title: "The page loads scripts from other origins",
      description: `${externalScripts.length} external script request(s) were observed. Scripts have broad page privileges and should be reviewed deliberately.`,
      severity: "low",
      confidence: "high",
      evidence: [...new Set(externalScripts.map((resource) => resource.name))].slice(0, 30).join("\n"),
      url,
      detection: "Performance resource initiatorType=script",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
      remediation: "Remove unused scripts, pin versions where practical and consider Subresource Integrity for static third-party files when compatible.",
      impact: "A compromised third-party script may access page data or alter behavior.",
      verification: "Review the script owner, versioning and integrity policy; test with the script blocked."
    });
  }

  if (externalFonts.length) {
    add(findings, {
      ruleId: "external-fonts",
      title: "Fonts are loaded from another origin",
      description: `${externalFonts.length} external font-like resource(s) were observed. This may be intentional but creates an additional connection and may expose visitor metadata to the font host.`,
      severity: "informational",
      confidence: "medium",
      evidence: [...new Set(externalFonts.map((resource) => resource.name))].slice(0, 20).join("\n"),
      url,
      detection: "Performance resource initiatorType/font extension",
      reference: "https://developer.mozilla.org/en-US/docs/Learn_web_development/Core/Text_styling/Web_fonts",
      remediation: "Self-host fonts when licensing allows, or document the external font provider and its privacy terms.",
      impact: "Another origin can observe font requests and potentially fingerprint visitors.",
      verification: "Inspect the font request chain and the provider's documented data handling."
    });
  }

  if (tracking.length) {
    add(findings, {
      ruleId: "tracking-pattern",
      title: "Requests match common analytics or tracking patterns",
      description: `${tracking.length} request URL(s) matched a conservative pattern list. This is a potential indicator only; vendor names, self-hosting and consent behavior must be reviewed manually.`,
      severity: "low",
      confidence: "low",
      evidence: [...new Set(tracking.map((resource) => resource.name))].slice(0, 20).join("\n"),
      url,
      detection: "URL pattern observation",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Privacy",
      remediation: "Document the tool's purpose, data collected, retention and consent behavior. Remove it if it is not required.",
      impact: "Visitor behavior may be collected or shared with another party.",
      verification: "Inspect the request, its initiating script and the provider's configuration; do not rely on the URL pattern alone."
    });
  }

  if (thirdPartyCookies.length) {
    add(findings, {
      ruleId: "third-party-cookies",
      title: "Cookies from third-party domains were observed",
      description: `${thirdPartyCookies.length} cookie(s) had a domain outside the target host. Cookie values are intentionally omitted from this report.`,
      severity: "medium",
      confidence: "high",
      evidence: thirdPartyCookies.map((cookie) => `${cookie.name} (${cookie.domain})`).join("\n"),
      url,
      detection: "Isolated browser context cookie store",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Privacy/Privacy_or_currency",
      remediation: "Review the setting origin, purpose, SameSite/Secure attributes and consent requirements; remove unnecessary third-party cookies.",
      impact: "Third-party cookies can support cross-site tracking and may be restricted by browsers.",
      verification: "Inspect the cookie in an isolated profile, then test the affected workflow with third-party cookies blocked."
    });
  }

  return {
    findings,
    checks,
    skipped,
    origins,
    cookieCount: cookies.length,
    thirdPartyCookieCount: thirdPartyCookies.length,
    caveat: "Privacy findings are observations and review prompts, not legal advice or proof of non-compliance."
  };
}
