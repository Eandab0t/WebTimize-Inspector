import http from "node:http";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

const HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Controlled local fixture for WebTimize Inspector tests.">
  <meta property="og:title" content="Inspector fixture">
  <meta property="og:description" content="Deliberately imperfect pages used to verify real findings.">
  <link rel="canonical" href="/">
  <title>Inspector fixture — accessibility and reliability</title>
  <link rel="stylesheet" href="/styles.css">
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Inspector fixture"}</script>
</head>
<body>
  <header><a href="/">Home</a> <a href="/missing-page.html">Broken link</a></header>
  <main>
    <h1>Controlled audit fixture</h1>
    <p class="low-contrast">This paragraph intentionally has low contrast.</p>
    <h3>Skipped heading level</h3>
    <img src="/images/valid.svg" width="40" height="40">
    <img src="/images/missing.png" width="40" height="40" alt="A missing image">
    <form action="/submit" method="get">
      <label for="email">Email</label><input id="email" name="email" type="email">
      <input name="unlabelled" type="text">
      <button type="submit">Send</button>
    </form>
    <button class="icon-only" aria-hidden="true">?</button>
    <p id="runtime"></p>
  </main>
  <script src="/app.js"></script>
</body>
</html>`;

const DOCS = `<!doctype html><html lang="en"><head><title>Docs fixture</title>
<meta name="description" content="A second page."><link rel="stylesheet" href="/styles.css"></head>
<body><h1>Docs</h1><p>Second page for link and crawl checks.</p><a href="/">Back</a></body></html>`;

const CSS = `body{font:16px/1.5 system-ui,sans-serif;margin:2rem;color:#17231e;background:#fff}
.low-contrast{color:#b9c4bf;background:#fff}.icon-only{border:0;background:#eee;padding:1rem}
img{display:block;margin:.5rem 0}header a{color:#126b52}`;

const JS = `document.getElementById("runtime").textContent = "Script ran";\nthrow new Error("fixture boom");`;

const CRAWL = `<!doctype html><html lang="en"><head><title>Crawl fixture</title><meta name="description" content="Crawl fixture index."><link rel="canonical" href="/crawl/"></head><body><h1>Crawl fixture</h1><a href="/crawl/child">Child</a><a href="/private/">Private</a><a href="http://example.com/external">External</a><a href="/crawl/?same=1#fragment">Query</a><a href="/crawl/">Duplicate</a></body></html>`;
const CHILD = `<!doctype html><html lang="en"><head><title>Crawl child</title><meta name="description" content="Crawl child."></head><body><h1>Child</h1><a href="/crawl/grandchild">Grandchild</a><a href="/crawl/">Back</a></body></html>`;
const GRANDCHILD = `<!doctype html><html lang="en"><head><title>Crawl grandchild</title><meta name="description" content="Crawl grandchild."></head><body><h1>Grandchild</h1></body></html>`;
const PRIVATE = `<!doctype html><html lang="en"><head><title>Private</title></head><body><h1>Should not be audited</h1></body></html>`;

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64"
);

function send(response, status, body, headers = {}) {
  const buffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": buffer.length,
    "x-content-type-options": "nosniff",
    "set-cookie": "fixture=1; Path=/; HttpOnly",
    ...headers
  });
  response.end(buffer);
}

export function createFixtureServer({ host = "127.0.0.1", port = 0 } = {}) {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, `http://${host}`);
    const base = `http://${request.headers.host || `${host}:${server.address().port}`}`;
    if (url.pathname === "/") return send(response, 200, HTML);
    if (url.pathname === "/docs/" || url.pathname === "/docs") return send(response, 200, DOCS);
    if (url.pathname === "/crawl/" || url.pathname === "/crawl") return send(response, 200, CRAWL);
    if (url.pathname === "/crawl/child") return send(response, 200, CHILD);
    if (url.pathname === "/crawl/grandchild") return send(response, 200, GRANDCHILD);
    if (url.pathname === "/private/") return send(response, 200, PRIVATE);
    if (url.pathname === "/styles.css") {
      const accept = request.headers["accept-encoding"] || "";
      if (accept.includes("gzip")) {
        const body = gzipSync(CSS);
        return send(response, 200, body, {
          "content-type": "text/css; charset=utf-8",
          "content-encoding": "gzip",
          "cache-control": "public, max-age=3600",
          vary: "Accept-Encoding"
        });
      }
      return send(response, 200, CSS, {
        "content-type": "text/css; charset=utf-8",
        "cache-control": "public, max-age=3600"
      });
    }
    if (url.pathname === "/app.js") {
      return send(response, 200, JS, {
        "content-type": "text/javascript; charset=utf-8",
        "cache-control": "public, max-age=3600"
      });
    }
    if (url.pathname === "/images/valid.svg") {
      return send(response, 200, '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40" fill="#126b52"/></svg>', {
        "content-type": "image/svg+xml"
      });
    }
    if (url.pathname === "/images/pixel.png") {
      return send(response, 200, PNG, { "content-type": "image/png" });
    }
    if (url.pathname === "/robots.txt") {
      return send(response, 200, `User-agent: *\nAllow: /\nDisallow: /private\nSitemap: ${base}/sitemap.xml\n`, {
        "content-type": "text/plain; charset=utf-8"
      });
    }
    if (url.pathname === "/sitemap.xml") {
      const body = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${base}/</loc></url><url><loc>${base}/docs/</loc></url><url><loc>${base}/crawl/</loc></url><url><loc>${base}/private/</loc></url></urlset>`;
      return send(response, 200, body, { "content-type": "application/xml; charset=utf-8" });
    }
    if (url.pathname === "/redirect") {
      response.writeHead(302, { location: "/", "set-cookie": "redirected=1; Path=/" });
      response.end();
      return;
    }
    if (url.pathname === "/redirect-private") {
      response.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      response.end();
      return;
    }
    if (url.pathname === "/slow") {
      setTimeout(() => send(response, 200, "slow response"), 1200);
      return;
    }
    if (url.pathname === "/huge") {
      return send(response, 200, "x".repeat(200 * 1024), { "content-type": "text/plain; charset=utf-8" });
    }
    if (url.pathname === "/ssrf.html") {
      return send(response, 200, `<!doctype html><html lang="en"><head><title>SSRF fixture</title></head><body><h1>SSRF fixture</h1><img src="http://169.254.169.254/latest/meta-data/" alt="metadata probe"><script>fetch("http://169.254.169.254/latest/meta-data/").catch(()=>{});</script></body></html>`);
    }
    if (url.pathname === "/third-party.js") {
      return send(response, 200, "window.fixtureThirdParty = true;", { "content-type": "text/javascript" });
    }
    return send(response, 404, "Not found", { "content-type": "text/plain; charset=utf-8" });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      resolve({
        server,
        host,
        port: server.address().port,
        url: `http://${host}:${server.address().port}/`,
        close: () => new Promise((done) => server.close(done))
      });
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const fixture = await createFixtureServer({ port: Number(process.env.PORT) || 4318 });
  console.log(`Inspector fixture listening at ${fixture.url}`);
}
