import { createFinding } from "../core/findings.js";

const REMEDIATION = {
  "image-alt": "Add a concise alt attribute, or mark a decorative image with alt=\"\" and ensure it is not the only accessible name for a control.",
  "input-image-alt": "Give the image input an alt value that names its action.",
  "object-alt": "Provide a text alternative for the object, or replace it with accessible markup.",
  "label": "Associate every form control with a visible label using for/id, wrapping label, aria-label or aria-labelledby.",
  "select-name": "Give the select an accessible name with a label or ARIA.",
  "button-name": "Put visible text in the button or give it an aria-label/aria-labelledby.",
  "link-name": "Give the link text that describes its destination; add an accessible name if it is icon-only.",
  "color-contrast": "Raise foreground/background contrast to at least 4.5:1 for normal text and 3:1 for large text.",
  "heading-order": "Use heading levels that reflect the document outline instead of choosing levels for appearance.",
  "html-has-lang": "Add a valid lang attribute to the html element.",
  "html-lang-valid": "Use a valid BCP 47 language tag.",
  "aria-allowed-attr": "Remove ARIA attributes that are not permitted on the element's role.",
  "aria-required-attr": "Add the ARIA attributes required by the element's role.",
  "aria-valid-attr": "Correct misspelled or unsupported ARIA attributes.",
  "aria-valid-attr-value": "Correct invalid ARIA attribute values.",
  "aria-hidden-focus": "Never place focusable controls inside aria-hidden content.",
  "duplicate-id": "Make element IDs unique.",
  "frame-title": "Give each iframe a descriptive title.",
  "landmark-one-main": "Provide one main landmark for the primary content.",
  "region": "Place page content inside meaningful landmarks such as header, nav, main and footer.",
  "form-field-multiple-labels": "Use one clear labelling method per form control.",
  "target-size": "Increase the target area or spacing so controls meet the WCAG 2.2 target-size minimum.",
  "focus-order-semantics": "Use native controls or an appropriate role so focus behavior is understandable.",
  "scrollable-region-focusable": "Make scrollable regions keyboard reachable and visibly focusable."
};

function severityFor(impact) {
  if (impact === "critical") return "high";
  if (impact === "serious") return "medium";
  if (impact === "moderate") return "low";
  return "informational";
}

function wcagReferences(tags = []) {
  return tags.filter((tag) => /^wcag\d/.test(tag)).join(", ") || null;
}

function remediationFor(id) {
  return REMEDIATION[id] || "Review the axe rule documentation and fix the underlying markup or interaction, then re-run the audit.";
}

export function accessibilityAudit({ browser, url }) {
  const findings = [];
  const checks = [];
  const skipped = [
    { check: "keyboard-only traversal", reason: "Automated axe results cannot prove complete keyboard operation; perform a manual keyboard pass." },
    { check: "screen-reader output", reason: "No screen reader was driven by this scan." },
    { check: "focus visibility and focus order", reason: "Axe can flag some patterns but does not establish complete focus usability." },
    { check: "form error and instruction quality", reason: "Validation behavior needs a manual interaction test." },
    { check: "WCAG conformance", reason: "Automated testing finds only a subset of WCAG failures and cannot certify conformance." }
  ];
  const axeRuns = browser?.runs?.filter((run) => run.axe?.available) || [];
  if (!axeRuns.length) {
    const error = browser?.runs?.[0]?.axe?.error || "axe-core did not run";
    checks.push({ id: "accessibility.axe", status: "skipped", reason: error });
    return { findings, checks, skipped, manualChecks: skipped.map((item) => item.check) };
  }

  const violations = new Map();
  const incomplete = new Map();
  for (const run of axeRuns) {
    for (const violation of run.axe.violations) {
      const key = violation.id;
      const current = violations.get(key) || { ...violation, nodeCount: 0, runs: 0 };
      current.nodeCount = Math.max(current.nodeCount, violation.nodeCount);
      current.runs += 1;
      violations.set(key, current);
    }
    for (const item of run.axe.incomplete) {
      const current = incomplete.get(item.id) || { ...item, nodeCount: 0 };
      current.nodeCount = Math.max(current.nodeCount, item.nodeCount);
      incomplete.set(item.id, current);
    }
  }

  checks.push(
    { id: "accessibility.axe", status: "observed", value: violations.size, unit: "rule types" },
    { id: "accessibility.manual-review", status: "manual-required", value: skipped.length, unit: "checks" }
  );

  for (const violation of violations.values()) {
    for (const node of violation.nodes) {
      findings.push(createFinding({
        ruleId: violation.id,
        category: "accessibility",
        title: violation.help,
        description: `${violation.description} Axe reported this as ${violation.impact || "unrated"}; ${violation.nodeCount} node(s) matched in the run.`,
        severity: severityFor(violation.impact),
        confidence: "high",
        evidence: `${node.target?.join(" ") || "unknown target"}\n${node.html || ""}\n${node.failureSummary || ""}`.trim(),
        url,
        element: node.target?.join(" ") || null,
        detection: `axe-core ${violation.id}`,
        ruleVersion: "axe-core 4.14.0",
        reference: violation.helpUrl || wcagReferences(violation.tags),
        remediation: remediationFor(violation.id),
        impact: "People using assistive technology or non-pointer input may be unable to understand or operate this content.",
        verification: "Fix the markup and re-run the same axe rules; complete the manual keyboard and screen-reader checks before claiming WCAG conformance."
      }));
    }
  }

  for (const item of incomplete.values()) {
    findings.push(createFinding({
      ruleId: `${item.id}-needs-review`,
      category: "accessibility",
      title: `Manual review: ${item.help}`,
      description: `axe could not determine the result automatically for ${item.nodeCount} node(s). This is a review prompt, not a confirmed failure.`,
      severity: "informational",
      confidence: "low",
      evidence: `${item.nodeCount} node(s) marked incomplete`,
      url,
      detection: "axe-core incomplete result",
      ruleVersion: "axe-core 4.14.0",
      reference: "https://github.com/dequelabs/axe-core",
      remediation: "Inspect the affected element in a browser with keyboard and assistive-technology checks.",
      impact: "There may be an accessibility problem that automation cannot determine.",
      verification: "Complete a manual review and record the result."
    }));
  }

  return {
    findings,
    checks,
    skipped,
    manualChecks: skipped.map((item) => item.check),
    caveat: "Automated accessibility results are a screening aid. They do not establish WCAG 2.2 conformance."
  };
}
