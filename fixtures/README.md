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

## `compressor-0.3.0/`

A real build emitted by WebTimize Compressor 0.3.0 (`webtim, version 0.3.0`), committed as data so
the producer's manifest schema is pinned by an actual artifact instead of a hand-written JSON copy.
Generated on 2026-11-19 with:

    python -m webtim.cli <site> -o <site>/out --hash --manifest manifest.json

The input site had `index.html`, `css/app.css`, `js/main.js` and five images whose names cover a
plain nested path, a space, a percent sign, a hash and non-ASCII text. `manifest.json` (stored-blob sha256
`42c22fab643a5c30ce1e9a50c21a70a7852952eac29c2100c0e5a98c9d4117c5`) records `final` as the raw
filesystem path, exactly as Compressor writes it; Inspector percent-encodes that path itself when it
builds the request URL. The rest of the directory is the build output those assets were copied from.

The manifest is data only: Inspector reads it and fetches the listed files from a static server, and
no Python is needed to run the test. Do not edit it by hand - regenerate with the command above and
keep the manifest and the files together. On Windows checkouts `core.autocrlf` can rewrite the manifest's line endings; the hashed
assets are single-line files, so the sha256 values it records still match the bytes served.
