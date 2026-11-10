# Changelog

## Unreleased — suite visual system

### Added

- **Licensing**: MIT `LICENSE`, package metadata and updated third-party notices. The license is
  included in the npm package file list.

### Changed

- Rebuilt the dashboard's presentation around the WebTimize suite tokens: brown logo masthead,
  cream grid-paper canvas, hard-edged plates, numbered sections, monospace labels and suite status
  colours. The existing scan, crawl, filter, cancellation, comparison and export behavior is
  unchanged.
- The canvas now uses Live's exact `#f4f1ea` light token and 48 px grid, rather than a nearby
  approximation, so the paper surface matches the extension options page.
- HTML and comparison reports now share the dashboard's report CSS instead of a separate visual
  language. Report headings, severity plates, borders and dark-mode colours follow the suite.
- Dashboard job/result states are now explicit (`RUNNING`, `COMPLETE`, `PARTIAL`, `FAILED`,
  `CANCELLED`); the progress bar exposes `role="progressbar"`, filters expose `aria-pressed`, and
  the primary controls have a visible keyboard focus ring.
- The dashboard serves the 256 px WebTimize logo from `public/webtimize-logo.png`; its SHA-256
  matches `Marketing/assets/webtimize-logo-256.png`.

### Fixed

- **Dashboard entry point**: `src/cli.js` now imports `./ui/dashboard.js`. A new end-to-end CLI regression test starts `dashboard --port 0`, verifies the loopback health endpoint and closes the child process.
- Narrow crawl results no longer overflow horizontally: long page URLs and evidence text wrap, and
  the page-coverage table uses a fixed layout. The 390 px result view measured a 12 px overflow
  before the fix and 0 px after.
- Report evidence links now wrap instead of widening the document. The 390 px report measured a
  50 px overflow before this fix and 0 px after. The report also renders the crawler's string
  viewport (`1440x900`) as `1440×900` instead of `?×?`.

### Verified

- 40/40 tests pass, including the dashboard entry-point regression.
- Real Chrome captures at 1440, 1024, 768 and 390 px cover the idle dashboard, running crawl,
  completed crawl, expanded page evidence, comparison, report, error, partial/cancelled, dark mode
  and keyboard focus. All four dashboard widths and the 1440/390 report captures report zero
  horizontal overflow.
  Curated evidence is under `evidence/visual-after/`; the original before set is preserved in
  `evidence/visual-before/`.

## Unreleased — bounded site crawl

### Added

- `crawl` CLI command and `crawl: true` dashboard mode with an exact-origin, bounded page crawl.
- RFC-style robots.txt parsing and bounded sitemap discovery, including sitemap indexes and
  redirect/error handling.
- Page states for completed, redirected, robots-skipped, limit-skipped, timed-out, failed, blocked,
  inconclusive and cancelled pages.
- Aggregate site findings with affected page lists, site coverage totals and bounded-crawl limits.
- Site report HTML/JSON rendering and site-aware comparison that does not treat unscanned pages as
  resolved.
- Dashboard crawl configuration, live coverage, page details, severity/category filters and
  cancellation.
- A loopback validating HTTP/CONNECT proxy for browser traffic, with page-start pacing and total
  request/byte budgets.
- Crawl, proxy, timeout, cancellation and site-comparison tests.

### Changed

- The browser network boundary now sends HTTP and HTTPS browser traffic through Inspector's
  validating proxy rather than allowing Chrome to resolve the destination independently.

### Fixed

- Site comparisons treat an ephemeral local port change as the same page path; unaffected findings
  are no longer reported as newly affected and no longer affected on every local re-run.

## 0.1.0 — 2026-11-07

### Added

- Local-first Inspector CLI with URL and local-directory scanning.
- Playwright-core adapter that launches the installed Chrome and blocks prohibited browser requests.
- Custom HTTP client with connection-time DNS validation, explicit redirect checks, response-size
  limits and timeouts.
- Performance observations from browser PerformanceObserver/Navigation/Resource timing.
- axe-core 4.14.0 accessibility screening with WCAG mapping and manual-review flags.
- SEO, passive security configuration, reliability and privacy observations.
- Stable finding fingerprints, severity and confidence separation, evidence, remediation and
  verification fields.
- Deterministic JSON report plus standalone escaped HTML report.
- Report comparison by new, absent and persistent findings.
- Loopback-only dashboard with local-project scan, progress, filter, export and comparison UI.
- Dashboard per-process token and same-origin mutation checks.
- Compressor manifest verification by served bytes, SHA-256, MIME type, encoding and caching.
- Controlled local fixture covering accessibility, performance, SEO, security, reliability and
  browser-level SSRF cases.
- 22 automated tests, including real Chrome fixture scans.

### Fixed

- Dashboard history entries now expose the report id, so **Open** and **Compare** work instead of
  sending `undefined`; history also labels URL scans with their target URL rather than always saying
  “local project”.
- Finding fingerprints no longer include the origin, so repeated local-project scans on a new
  ephemeral loopback port compare as persistent rather than all-new/all-absent. Deployment host
  changes are treated the same way.
- Raw dashboard screenshots are written under ignored `__development/experiments/dashboard-evidence/`; only
  curated screenshots remain in `evidence/`.

### Deferred

- Lighthouse adapter and Speed Index measurements.
- CrUX or other field-data provider.
- Cross-origin or authenticated crawl expansion; JavaScript-only navigation discovery.
- Live extension test automation.
- Firefox/WebKit execution.
- Any automatic modification of a scanned website.
