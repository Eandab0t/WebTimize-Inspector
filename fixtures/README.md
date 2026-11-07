# Controlled fixtures

These fixtures are intentionally imperfect. They are local test data, not production validation.

## `site-server.js`

A dependency-free HTTP server with deliberate defects:

| Route | Purpose |
| --- | --- |
| `/` | Missing title/description, missing image alt, unlabelled input, low contrast, heading skip, broken internal link, JavaScript exception, broken image, insecure cookie and missing security headers |
| `/docs/` | Second page for navigation/link behavior |
| `/styles.css` | gzip response when requested, cache header and intentional low-contrast rule |
| `/app.js` | Throws a page exception after setting a DOM value |
| `/images/valid.svg` | Valid image |
| `/images/pixel.png` | Small valid image |
| `/robots.txt`, `/sitemap.xml` | Basic discovery responses |
| `/redirect` | Allowed same-origin redirect |
| `/redirect-private` | Redirect to a cloud metadata address; must be blocked |
| `/slow` | Timeout fixture |
| `/huge` | Response-size fixture |
| `/ssrf.html` | Browser image/fetch probes to a metadata address |

## `local-site/`

A clean static directory used to test the explicit local-project scan and the dashboard's temporary
static server. It has no known defects beyond local HTTP/header limitations.

## Rules

- Do not use these fixtures to claim production performance, security or WCAG conformance.
- Do not add real credentials, cookies, internal URLs or private network addresses.
- Keep browsers and tests isolated from a normal user profile.
