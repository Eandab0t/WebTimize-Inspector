# Inspector report format

Reports are local JSON documents with a schema version. The CLI's `--json` and `--html` options use
the same report object; the HTML report embeds a copy of the JSON for reproducibility.

## Top level

```json
{
  "schemaVersion": 1,
  "tool": { "name": "webtim-inspector", "version": "0.1.0" },
  "scanId": "uuid",
  "status": "complete",
  "startedAt": "2026-11-07T20:00:00.000Z",
  "completedAt": "2026-11-07T20:00:02.000Z",
  "durationMs": 2000,
  "target": {
    "requestedUrl": "https://example.com/",
    "finalUrl": "https://example.com/",
    "scope": "single-page",
    "allowPrivate": false
  },
  "configuration": {
    "categories": ["performance", "accessibility", "seo", "security", "reliability", "privacy"],
    "viewport": { "width": 1440, "height": 900 },
    "runs": 1,
    "timeoutMs": 30000,
    "maxRequests": 200,
    "maxBytes": 5242880,
    "maxLinks": 20,
    "networkProfile": "unthrottled local connection; no simulated throttling",
    "cpuThrottling": 1,
    "device": "desktop local Chrome"
  },
  "environment": {
    "node": "v24.19.0",
    "platform": "win32",
    "release": "10.0.26200",
    "browser": {
      "name": "Chromium",
      "version": "157.0.8103.39",
      "executablePath": "..."
    },
    "browserError": null,
    "chromeOnly": true
  },
  "summary": {
    "findings": { "critical": 0, "high": 1, "medium": 2, "low": 0, "informational": 1 },
    "total": 4,
    "categories": {}
  },
  "categories": {},
  "findings": [],
  "evidence": { "screenshot": "evidence/page.png", "rawBrowserArtifactsIncluded": false },
  "limitations": [],
  "http": {},
  "runs": []
}
```

## Finding shape

```json
{
  "id": "a-stable-fingerprint",
  "ruleId": "accessibility.image-alt",
  "category": "accessibility",
  "title": "Images must have alternative text",
  "description": "Each image should have a text alternative.",
  "severity": "high",
  "confidence": "high",
  "evidence": "img#hero\n<img id=\"hero\" src=\"hero.png\">",
  "url": "https://example.com/",
  "element": "img#hero",
  "detection": "axe-core image-alt",
  "reference": "https://dequeuniversity.com/rules/axe/4.14/image-alt",
  "remediation": "Add a meaningful alt attribute or ...",
  "impact": "People using screen readers cannot identify the image.",
  "verification": "Re-run the same axe rule and complete a manual review.",
  "ruleVersion": "axe-core 4.14.0",
  "firstDetected": "2026-11-07T20:00:00.000Z",
  "tool": "webtim-inspector"
}
```

`id` is a SHA-256 fingerprint of rule/category/element/title and is used for comparisons. The URL/origin
is deliberately excluded: local-project scans use an ephemeral loopback port, and a site can move hosts
without changing the underlying observation. `ruleId` is the stable rule identity and is usually the
better field for filtering. The same rule can have multiple instances with different fingerprints.

## Site report shape

A crawl adds `target.scope: "site"`, `target.finalOrigin`, and a `crawl` object while keeping the
same category and finding fields:

```json
{
  "target": { "requestedUrl": "https://example.com/", "scope": "site", "finalOrigin": "https://example.com" },
  "crawl": {
    "startUrl": "https://example.com/",
    "finalOrigin": "https://example.com",
    "robots": { "url": "https://example.com/robots.txt", "status": "parsed", "httpStatus": 200, "sitemaps": [] },
    "sitemap": { "status": "parsed", "files": [], "urls": [], "errors": [], "truncated": false },
    "pages": [],
    "skipped": [],
    "coverage": { "discovered": 1, "attempted": 1, "audited": 1, "failed": 0, "maxPages": 25, "maxDepth": 2 },
    "limits": { "maxPages": 25, "maxDepth": 2, "maxConcurrency": 2, "maxDurationMs": 120000 },
    "timedOut": false,
    "cancelled": false
  }
}
```

Each `crawl.pages` entry retains the page URL, depth, discovery source, final URL, HTTP status,
requests/bytes, duration, page state, findings, category results and browser environment. `state` is
one of `completed`, `redirected`, `robots-skipped`, `limit-skipped`, `timed-out`, `failed`,
`blocked`, `inconclusive` or `cancelled`. `crawl.skipped` contains candidates that were not started,
with a reason such as maximum depth, page count, time or budget.

Top-level site findings are aggregates. They retain the first observation's description, severity,
confidence and evidence, and add:

- `occurrences`: total matching page findings;
- `affectedPages`: distinct page URLs;
- `pageCount`: number of distinct affected pages.

Aggregation key: `ruleId` + `title` + `severity`. Failed, blocked, timed-out, robots-skipped and
limit-skipped pages do not contribute findings. `summary.mostCommon` lists the aggregates with the
widest page coverage. There is still no website score.

## Severity and confidence

| Severity | Meaning |
| --- | --- |
| critical | A page/document load or core behavior failed, or a similarly severe observed failure |
| high | A serious observed failure or security/accessibility issue with broad impact |
| medium | A meaningful issue needing correction or deeper review |
| low | Hardening or quality issue with limited direct impact |
| informational | Context, optional metadata or a review indicator |

`confidence` is `high`, `medium` or `low` and is independent of severity. For example, a
tracking-pattern URL match is low confidence, not automatically a legal or security violation.

## Categories

Each category contains:

- `status`: `ok`, `partial`, `skipped`, `failed` or `not-selected`;
- `findings`: normalized findings;
- `checks`: executed/observed checks and their values;
- `skipped`: checks that could not run or were deliberately omitted;
- `caveat`: category-specific interpretation;
- category-specific metrics/origins/link counts.

A skipped check is never converted into a pass. `summary.categories` contains counts, not a score.

## No universal score

Inspector does not produce a 0–100 website grade. Category counts help navigate the report; findings
and their evidence are authoritative. This avoids weighting arbitrary checks, treating unavailable
data as a pass, and hiding a critical finding inside an attractive aggregate score.

## HTML

`renderHtml(report)` produces one self-contained HTML file with inline CSS, escaped text, a findings
list, category checks/skipped checks, limitations and an embedded JSON copy. Site reports also show
crawl coverage, robots/sitemap status, page results, most common issues and affected-page lists. It
loads no external script or stylesheet. Screenshot files are referenced as local paths rather than
embedded, so they are not silently uploaded or inlined into shared reports.

## Comparison

`inspector compare before.json after.json` compares finding fingerprints and reports:

- added (new in the second report);
- absent (not present in the second report);
- persistent (present in both);
- median metric deltas where both reports contain performance metrics.

When both reports have `crawl` data, comparison also reports:

- newly affected pages: pages in the later crawl that were not in the earlier page set;
- no-longer-affected pages: earlier affected pages absent from the later page set;
- pages not scanned in the later run;
- findings that remain only on unscanned pages (`unscannedFindings`).

Page identity for these lists is path + query, so an ephemeral local-project port change does not make
every page look new. A finding is never marked resolved solely because its page was not scanned.

Absence is not independent proof that a fix worked. Re-run the scan and verify the actual behavior.

## Versioning

- `schemaVersion` increments on a breaking shape change.
- Tool and axe versions are recorded with findings where applicable.
- Unknown manifest schema versions are rejected rather than guessed.
- Timestamps and `scanId` are intentionally not deterministic; the measured data and finding order
  are deterministic for the same observations.
