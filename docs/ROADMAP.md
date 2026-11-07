# Inspector roadmap

## 0.1.0 — MVP

Delivered:

- local CLI and dashboard;
- URL validation and SSRF controls;
- installed-Chrome automation with isolated contexts;
- performance observations from browser APIs;
- axe-core accessibility screening;
- SEO, passive security, reliability and privacy observations;
- JSON and standalone HTML reports;
- report comparison;
- Compressor manifest verification;
- controlled fixture and 22 tests, including real Chrome scans.

## 0.2.0 — bounded site crawl (implemented)

Delivered:

- exact-origin crawl CLI and dashboard mode with page, depth, concurrency, time, request and byte
  limits plus page-start pacing;
- robots.txt and bounded sitemap discovery;
- per-page states and partial-failure isolation;
- aggregate site findings with affected-page lists and site-aware comparison;
- cancellation, coverage totals and bounded-crawl limitations;
- loopback validating HTTP/CONNECT proxy for browser traffic.

Remaining crawl work is deliberately deferred: cross-origin or authenticated expansion, discovery
through JavaScript-only navigation, and larger crawl orchestration.

## Next: highest-value work

### 1. Lighthouse adapter (optional, explicit)

Add a separate `--lighthouse` mode only after defining a single browser/network boundary, throttling
configuration and report provenance. It should provide Speed Index and trace-based metrics without
presenting them as field data. Keep the native browser observations as the default.

### 2. Field data (optional CrUX)

Add an opt-in adapter that requires the user's key, clearly labels field vs lab data and never sends
the target page content. The core scan must remain useful with no key.

### 3. Live comparison mode

Implement the documented isolated-extension workflow with a temporary profile, baseline/modified/
restored screenshots, console/network checks and an explicit "supported profile" label. Do not touch
a user's real browser profile.

### 4. Additional browser engines

Add Firefox/WebKit only if the browser adapters can provide equivalent URL enforcement, evidence and
failure states. Do not claim cross-browser compatibility from code inspection.

### 5. Broader accessibility workflow

Add keyboard/focus traversal and review queues, but preserve the manual-review boundary. Automated
results still cannot certify WCAG conformance.

## Later / explicitly deferred

- Historical dashboards and budgets.
- Authenticated site scans (requires a separate credential threat model).
- Hosted scanning.
- Automatic site or build modification.
- More security checks that require active probing.
- Mobile device/network throttling matrices.
- Full web-vitals field integration without a privacy review.

## Acceptance rules for every future feature

1. Every finding originates from an observation with evidence.
2. Every network feature runs through the same URL policy or documents a stronger replacement.
3. A skipped/unavailable check is never counted as a pass.
4. Report schema changes are versioned.
5. Browser claims come from real browser runs, not source inspection.
6. No account, key or cloud dependency becomes mandatory for the core scan.
