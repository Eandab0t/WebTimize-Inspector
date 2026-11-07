# Inspector architecture

## Shape

Inspector is an independent Node 22+ application. It has no shared runtime with Compressor or Live.

```text
bin/inspector.js
  └─ src/cli.js
       ├─ src/core/scanner.js          orchestration and report assembly
       │    ├─ src/crawl/crawl.js        exact-origin discovery, limits, robots/sitemap, site aggregation
       │    ├─ src/crawl/robots.js       RFC-style robots.txt parsing and decisions
       │    ├─ src/core/url-policy.js  URL, DNS, redirect and request safety
       │    ├─ src/core/proxy.js       loopback validating HTTP/CONNECT browser proxy
       │    ├─ src/core/http-audit.js  headers, TLS, cookies, robots and sitemap
       │    ├─ src/core/browser.js     Playwright-core, Chrome, route guard, axe injection
       │    ├─ src/audits/performance.js
       │    ├─ src/audits/accessibility.js
       │    ├─ src/audits/seo.js
       │    ├─ src/audits/security.js
       │    ├─ src/audits/reliability.js
       │    └─ src/audits/privacy.js
       ├─ src/report/report.js           JSON comparison, standalone HTML, CLI text
       ├─ src/report/compressor.js       exported manifest verification
       ├─ src/ui/dashboard.js        loopback HTTP dashboard and API
       └─ src/core/local-server.js     read-only static server for explicit local scans
```

The dashboard and CLI both call `runScan` for a single page and `crawlSite` for a bounded site
report. `crawlSite` calls `runScan` once per eligible page rather than duplicating audit categories.
The audit engine has no dependency on the dashboard; the dashboard is an HTTP client of the same
engine, not a second implementation.

## Scan lifecycle

1. Parse and validate the target URL; reject unsupported schemes and embedded credentials.
2. Resolve DNS and reject private, loopback, link-local and metadata addresses (unless the explicit
   local-scan escape hatch is used, which still never permits metadata).
3. Fetch the target with the custom HTTP client. Follow at most the configured redirects, validating
   each destination. Capture safe headers, TLS details, cookie attributes and robots/sitemap
   responses.
4. Launch the installed Chrome through Playwright-core. Create a fresh isolated context per run.
5. Start a loopback validating proxy and point Chrome at it. Chrome sends the destination hostname;
   the proxy resolves it, applies the URL policy, then connects to the validated address. Browser
   HTTP requests and HTTPS CONNECT tunnels therefore do not independently resolve the target.
6. Install performance observers before navigation. Also route every HTTP(S) browser request through
   the URL policy, abort prohibited requests and count request limits. Redirects and subresources are
   checked by both layers.
7. Navigate, wait for load plus a short settling window, collect DOM/resource/console/response data.
8. Inject axe-core and run the configured WCAG/best-practice tags.
9. Run the selected category analyzers over the HTTP and browser observations.
10. Normalize findings, sort by severity, deduplicate by fingerprint, and assemble the versioned
   report.
11. Close the browser, proxy and any temporary local server. Write reports only when requested.

## Crawl lifecycle

1. Validate and resolve the starting URL with the same policy as a single-page scan. The crawl scope
   is its exact origin.
2. Fetch and parse robots.txt once. A 4xx response permits crawling; 5xx and network failures are
   treated as complete disallow.
3. Read bounded sitemap locations, including sitemap indexes, then add same-origin URLs as discovery
   candidates. `/sitemap.xml` is only a fallback when no usable declaration exists.
4. Run a bounded worker pool (default 2). Each worker takes the next deterministic candidate, applies
   robots rules, page/depth/time/request/byte limits and page-start pacing, then calls `runScan`.
5. Discovery comes only from ordinary anchors, canonical declarations and sitemap entries. Failed
   pages do not abort other pages. A cancelled signal stops workers and closes the active browser.
6. Aggregate completed-page findings by rule/title/severity, retain affected page URLs, and mark
   failed/skipped pages as coverage gaps rather than passing pages.

## Boundaries

| Boundary | Rule |
| --- | --- |
| Audit engine ↔ dashboard | `runScan`/`crawlSite` accept plain options and emit progress callbacks; the dashboard owns job state |
| Audit engine ↔ reports | Findings are normalized before rendering; JSON and HTML render the same report object |
| Inspector ↔ Compressor | Only exported manifest/report JSON is consumed; no Python import |
| Inspector ↔ Live | A documented optional contract; no extension automation shipped in 0.1.0 |
| Browser ↔ network | Chrome uses a loopback validating HTTP/CONNECT proxy; the browser route guard remains a second check. HTTPS CONNECT behavior and websocket timing retain documented limits |
| Dashboard ↔ network | Loopback binding only; mutations need process token and same-origin request |
| Report ↔ secrets | Cookie values, auth headers and raw response headers are excluded |

## Run isolation and limits

- One browser process per scan; one fresh context per run; contexts are closed after each run.
- Defaults: 1 run, 30 s timeout, 200 browser requests, 5 MiB HTTP response cap, 20 internal links.
- Runs are capped at 5; requests at 1,000; response cap at 50 MiB; links at 100.
- Service workers are blocked in the audit context to keep request interception meaningful and make
  runs less stateful. This can differ from normal browsing and is a documented limitation.
- The dashboard permits one active scan at a time and rejects an overlap with HTTP 429.
- Crawl defaults: 25 pages, depth 2, 2 concurrent navigations, 120 s, 2,000 requests, 50 MiB, 500
  sitemap URLs and 250 ms page-start pacing. Values are clamped in `crawlOptions`.
- The temporary local project server binds to `127.0.0.1` on an ephemeral port and is closed in a
  `finally` path.

## Data model

A single-page report has four layers:

1. **Metadata**: schema version, tools, timestamps, target, configuration, environment.
2. **Category results**: status, findings, checks, skipped/manual checks and category-specific
   observations.
3. **Findings**: stable rule id plus a fingerprint, severity, confidence, evidence, remediation and
   verification.
4. **Artifacts/limitations**: optional screenshot path, HTTP summary and explicit run limitations.

A site report (`target.scope: "site"`) keeps that shape and adds `crawl.pages` (per-page state,
final URL, findings and coverage metadata), `crawl.skipped`, `crawl.coverage`, robots/sitemap status,
and aggregated top-level findings with `affectedPages` and `pageCount`. Each page report is not
discarded; it remains in `crawl.pages` for evidence.

There is deliberately no aggregate quality score. Category counts are counts, not a weighted grade;
checks that were not run are not treated as passes.

## Why no shared runtime

Compressor is Python and operates on files before deployment. Live is a Chrome MV3 extension with a
narrow permission model. Inspector is a local auditing process. Combining them would add coupling,
permissions and deployment surface without improving any product's correctness. Integration happens
through versioned JSON contracts and documented commands.
