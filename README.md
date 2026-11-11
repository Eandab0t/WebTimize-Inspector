# WebTimize Inspector

Local-first website auditing and diagnostics for the WebTimize suite.

Inspector scans one URL, an explicitly selected local project directory, or a bounded same-origin
site crawl and reports what was observed, what it means, and how to verify a fix. It runs Chrome on
the user's machine, keeps the report local, needs no account or paid API, and sends no telemetry.

```bash
npm install
node bin/inspector.js scan https://example.com --json report.json --html report.html
node bin/inspector.js scan --local-dir ./dist --json local.json
node bin/inspector.js crawl https://example.com --json site.json --html site.html
node bin/inspector.js dashboard
```

Requires **Node.js 22.19+** and a locally installed Google Chrome. `playwright-core` is used to
launch the installed browser; it does not download a second browser. The scan does not require the
dashboard to be running.

## What it does

| Category | Implemented observations |
| --- | --- |
| Performance | LCP, FCP, CLS, TTFB, load timing, synthetic interaction observation, long tasks, requests, transferred bytes, image/script/style/font composition, render-blocking resources, third-party origins, cache and compression observations |
| Accessibility | axe-core 4.14.0 WCAG 2.0/2.1/2.2 A/AA and best-practice screening, affected selectors, WCAG/help references, remediation and manual-review prompts |
| SEO | titles, meta descriptions, canonicals, robots meta, robots.txt, sitemap discovery, headings, structured data, Open Graph, internal link checks and redirects |
| Security | HTTPS, TLS peer certificate when available, HSTS, CSP, nosniff, Referrer-Policy, Permissions-Policy, cookie attributes, mixed content, redirect direction and technology disclosure |
| Reliability | navigation errors, JavaScript exceptions, failed requests and HTTP errors, broken images, MIME mismatches, horizontal overflow and redirect chains |
| Privacy | third-party origins, external scripts and fonts, third-party cookies and conservative tracking-pattern indicators |

Every finding includes evidence, severity, confidence, detection method, remediation and a
verification step. There is no invented universal quality score.

### Important limits

- Performance numbers are **synthetic lab observations** from one or more local Chrome runs. They
  are not field Core Web Vitals and do not represent the 75th-percentile real-user target.
- axe-core finds only a subset of WCAG issues. Inspector does **not** certify WCAG 2.2 conformance.
- Missing security headers are configuration observations, not proof of a vulnerability. Inspector
  does not perform penetration testing.
- SEO observations do not prove that a URL is indexed or that it will rank.
- Only Chrome and the requested viewport(s) are exercised. Firefox, Safari, WebKit and physical
  devices are unverified.
- Speed Index is not fabricated. It is skipped until a filmstrip/Lighthouse adapter is implemented.
- Cross-origin resource timings may be incomplete without `Timing-Allow-Origin`.

## Site crawl

`crawl` uses the same six category analyzers as a single-page scan. It starts at the supplied URL,
reads robots.txt and bounded sitemap data, discovers ordinary same-origin links, and audits up to
**25 pages at depth 2** by default. It does not submit forms, click controls, start purchases or
change site state.

Defaults are enforced in code:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Pages | 25 | 100 |
| Depth | 2 | 10 |
| Concurrent page navigations | 2 | 4 |
| Total crawl time | 120 s | 15 min |
| Total request budget | 2,000 | 100,000 |
| Total transfer budget | 50 MiB | 500 MiB |
| Page-start pacing | 250 ms | 5,000 ms |
| Sitemap files / URLs | 5 / 500 | 20 / 5,000 |

Scope is the starting URL's exact origin. Sibling subdomains and external domains are not crawled.
Redirects and sitemap URLs are checked against the same URL policy. Query strings are retained;
fragments, default ports and dot segments are normalized. A page can be `completed`, `redirected`,
`robots-skipped`, `limit-skipped`, `timed-out`, `failed`, `blocked` or `inconclusive`.

robots.txt is parsed as RFC 9309-style groups with wildcard and `$` support. A 4xx response permits
crawling; a 5xx or network failure is treated as complete disallow. Sitemap indexes are bounded and
same-origin. A missing sitemap declaration falls back to `/sitemap.xml`.

Repeated findings are grouped by rule/title/severity and keep an `affectedPages` list. The report
does not invent an overall website score. See [docs/REPORT-FORMAT.md](docs/REPORT-FORMAT.md).

## CLI

```text
inspector scan <url> [options]
inspector scan --local-dir <path> [options]
inspector crawl <url> [options]
inspector crawl --local-dir <path> [options]
inspector compare <before.json> <after.json> [--json <path>] [--html <path>]
inspector verify <manifest.json> <base-url> [--json <path>] [--allow-private]
inspector dashboard [--port 4173]
```

Common scan options:

```text
--categories performance,accessibility,seo,security,reliability,privacy
--viewport 1440x900
--runs 1..5
--timeout 30000
--max-requests 200
--max-bytes 5242880
--max-links 20
--json report.json
--html report.html
--screenshot evidence/page.png
--allow-private
--local-dir ./dist
--quiet
```

Crawl options:

```text
--max-pages 25            maximum 100
--max-depth 2             maximum 10
--max-concurrency 2       maximum 4
--max-duration 120000     total milliseconds
--total-requests 2000     total request budget
--total-bytes 52428800    total transfer budget
--page-pacing 250         delay between page starts
```

`--allow-private` is an explicit escape hatch for intentional local testing. It does not permit
cloud metadata addresses. A local-project scan serves the selected directory on a temporary
loopback port and closes it after the scan.

Exit codes: `0` complete/partial scan, `2` invalid input, `3` failed scan or verification failure.

## Dashboard

`node bin/inspector.js dashboard` binds to `127.0.0.1` only and prints its URL. The dashboard
provides URL and local-directory scans, a crawl toggle with bounded page/depth settings, live
progress, discovered/audited/skipped/failed counts, expandable page results, affected-page lists,
severity and category filters, JSON/HTML export, cancellation, previous-scan comparison and a clear
list of limitations.

The dashboard uses a per-process token and same-origin checks for mutations. It is not a hosted
service and must not be exposed on a public interface.

## Visual system

Inspector uses the suite design system rather than a separate look: the WebTimize logo in a brown
masthead, cream grid-paper canvas, 2 px ink plates, numbered sections, monospace labels and small
bordered status badges. Job, result, page and finding states are readable without relying on colour
alone. Progress exposes `role="progressbar"` with current values; filters use `aria-pressed`; focus
uses a visible `:focus-visible` outline; dark mode and reduced motion are supported. HTML reports
and comparison reports share the palette, hard edges, severity plates and dark-mode rules.

The implemented tokens and contrast values live in [public/style.css](public/style.css). Curated
rendered evidence for the dashboard, crawl states, comparison, report, dark mode and
1440/1024/768/390 px layouts is under
[`evidence/visual-after/`](evidence/visual-after/). Every captured width reports zero horizontal
overflow. The before set remains in
[`evidence/visual-before/`](evidence/visual-before/) and was not overwritten.

## Integration with Compressor

Inspector consumes Compressor's **exported** JSON manifest; it never imports the Python package's
private modules.

```bash
node bin/inspector.js verify dist-assets.json https://example.com/ --json verified.json
```

`verify` fetches each manifest asset, checks the served SHA-256 and MIME type, and reports status,
hash/type mismatches, content encoding and cache-control. It checks what was served, not whether a
particular deployment process used the manifest.

Live and Inspector currently have a documented optional integration contract, but no extension
automation is shipped in this MVP. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Tests

```bash
npm test
```

The suite uses Node's built-in test runner and includes:

- URL validation, private/metadata/alternate-IP rejection, connection-time lookup, redirect,
  response-size and timeout tests;
- real Chrome scans against a controlled local fixture;
- known expected accessibility, reliability, SEO and security findings;
- browser-level SSRF blocking;
- crawl discovery, scope, limits, robots, sitemap, timeout and cancellation behavior;
- browser-backed crawl traffic through the validating proxy;
- JSON/HTML report escaping and comparison;
- Compressor manifest hash/MIME verification;
- CLI command tests, including the dashboard entry-point regression;
- dashboard token, same-origin, real local-scan, site-crawl and cancellation tests.

The latest recorded run is **41 tests, 41 passed, 0 failed**. Browser scans use the installed Chrome
157.0.8103.39 on Windows. See [docs/BROWSER-VALIDATION.md](docs/BROWSER-VALIDATION.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Audit categories](docs/AUDIT-CATEGORIES.md)
- [Report format](docs/REPORT-FORMAT.md)
- [Integration contracts](docs/INTEGRATIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Browser validation](docs/BROWSER-VALIDATION.md)
- [Third-party notices](THIRD-PARTY-NOTICES.md)

## Layout

```text
bin/                 CLI entry point
src/audits/          six category analyzers
src/core/            browser, scanner, policy, proxy and shared findings
src/crawl/           bounded crawl and robots handling
src/report/          JSON/HTML reports and Compressor verification
src/ui/              loopback dashboard
public/              dashboard assets
docs/                public documentation
evidence/            curated validation captures
__development/       local reports, experiments, backups and private notes
```

## Local files

Generated raw reports, screenshots, experiments and private notes live under the ignored
`__development/` directory. Curated evidence is under `evidence/`. The scanner's controlled fixture
is under `fixtures/`; it is intentionally imperfect and is safe to run locally.

## License

WebTimize Inspector is released under the MIT License. See [LICENSE](LICENSE).
Third-party packages retain their upstream licenses; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
