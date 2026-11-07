import { createHash } from "node:crypto";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
export const CONFIDENCE_ORDER = ["high", "medium", "low"];

export class FindingError extends Error {
  constructor(message) {
    super(message);
    this.name = "FindingError";
  }
}

export function createFinding(input) {
  const {
    ruleId,
    category,
    title,
    description,
    severity,
    confidence = "medium",
    evidence = "",
    url = "",
    element = "",
    detection = "observed",
    reference = "",
    remediation = "",
    impact = "",
    verification = "Observed during this scan",
    tool = "webtim-inspector",
    ruleVersion = null,
    firstDetected = new Date().toISOString()
  } = input;

  if (!ruleId || !category || !title || !description) {
    throw new FindingError("finding requires ruleId, category, title and description");
  }
  if (!SEVERITY_ORDER.includes(severity)) {
    throw new FindingError(`unknown severity: ${severity}`);
  }
  if (!CONFIDENCE_ORDER.includes(confidence)) {
    throw new FindingError(`unknown confidence: ${confidence}`);
  }

  // The origin is deliberately excluded: local project scans use an ephemeral
  // loopback port, and a deployment can move hosts without changing the issue.
  const fingerprint = createHash("sha256")
    .update([ruleId, category, element, title].join("\n"))
    .digest("hex")
    .slice(0, 12);

  return {
    id: fingerprint,
    ruleId: `${category}.${ruleId}`,
    category,
    title,
    description,
    severity,
    confidence,
    evidence,
    url: url || null,
    element: element || null,
    detection,
    reference: reference || null,
    remediation,
    impact,
    verification,
    ruleVersion,
    firstDetected,
    tool
  };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const severity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severity) return severity;
    return a.ruleId.localeCompare(b.ruleId) || a.id.localeCompare(b.id);
  });
}

export function countFindings(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

export function summarizeCategories(categories) {
  return Object.fromEntries(
    Object.entries(categories).map(([name, category]) => [
      name,
      {
        status: category.status,
        findings: countFindings(category.findings),
        checks: category.checks,
        skipped: category.skipped
      }
    ])
  );
}
