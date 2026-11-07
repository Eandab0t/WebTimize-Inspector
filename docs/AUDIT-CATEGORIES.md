# Audit categories

## Performance

### Observed

- Navigation Timing TTFB, DOMContentLoaded and load.
- FCP and LCP via browser PerformanceObserver.
- Layout-shift sum (CLS observation).
- Long tasks over 50 ms.
- Event Timing durations when the page actually receives input; reported as an observation, not
  field INP.
- Resource count and transferred bytes.
- Image, script, style and font resource composition.
- Render-blocking status when Chrome exposes it.
- Third-party resource count.
- Cache-Control observations.
- Missing Content-Encoding on large text resources.
- Duplicate resource URLs.
- Viewport and page dimensions are recorded by the reliability category.

### Thresholds used

LCP > 2.5 s, CLS > 0.1, TTFB > 800 ms and a few practical resource counts produce findings. These
are **lab signals** based on Core Web Vitals good thresholds. The real Core Web Vitals target is the
75th percentile of field data; Inspector does not have field data.

### Not measured

- Speed Index (explicitly skipped).
- Total Blocking Time/Lighthouse score.
- Real INP.
- User network/device distribution.
- CrUX field values.
- Server-side processing breakdown.

## Accessibility

Automated axe-core screening covers many missing-name, label, contrast, ARIA, landmark, heading and
form patterns. Findings include selectors, HTML, WCAG/help references and remediation. `incomplete`
axe results become low-confidence manual-review items.

Manual checks remain required for keyboard operation, focus appearance/order, screen-reader output,
error handling, cognitive load, target size in context and complete WCAG conformance.

## SEO

Checks titles, descriptions, canonical links, robots meta, robots.txt, sitemap discovery, heading
hierarchy, JSON-LD parseability, Open Graph, image alt attributes (through accessibility), internal
link failures and redirect chains.

A page's markup is not evidence that Google has indexed it. Inspector cannot query a search index
or guarantee ranking.

## Security configuration

Passive checks: HTTPS, TLS peer certificate when Node exposes it, HSTS, CSP (including broad unsafe
directives), nosniff, Referrer-Policy, Permissions-Policy, cookie Secure/HttpOnly/SameSite, mixed
content, redirects to HTTP and technology-disclosure headers.

A missing header is contextual hardening advice, not a vulnerability proof. No exploit, credential,
brute-force or destructive test is performed.

## Reliability

Observed: navigation failure, page exceptions, failed requests, HTTP error responses, zero-size
images, MIME mismatches, horizontal overflow and redirect chains.

One Chrome run at one viewport does not establish cross-browser compatibility. Interaction tests are
manual unless a future explicit test mode is added.

## Privacy

Observed: third-party origins, external scripts/fonts, third-party cookies and conservative tracking
URL patterns. Values are omitted. These are review indicators, not legal conclusions. Cross-origin
frame contents and server-side tracking are not inspected.

## Findings and confidence

Severity communicates impact; confidence communicates how strongly the observation supports the
claim. A low-confidence indicator must not be read as a confirmed critical vulnerability. Automated
checks can be silent about issues they cannot observe; silence is not a pass.

## Site crawl coverage

A site crawl runs these same category analyzers for each eligible page; it does not create a second
set of audit rules. Findings repeated at the same severity and rule are grouped into a site-level
aggregate with the affected page URLs. Failed and skipped pages are not included in aggregate
findings and are never presented as passing pages.

Each page records a state: completed, redirected, robots-skipped, limit-skipped, timed-out, failed,
blocked, inconclusive or cancelled. The report also records discovered/audited/skipped/failed counts,
robots and sitemap status, the applied limits, and the crawl's limitations. A bounded crawl is a
sample of reachable pages, not a complete-site audit, and no overall score is calculated.
