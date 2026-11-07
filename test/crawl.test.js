import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";
import { createFixtureServer } from "../fixtures/site-server.js";
import { crawlSite, normalizeCrawlUrl, parseSitemap } from "../src/crawl/crawl.js";
import { fetchRobots, parseRobots, robotsAllows } from "../src/crawl/robots.js";
import { UrlPolicy } from "../src/core/url-policy.js";
import { renderHtml } from "../src/report/report.js";

let fixture;
before(async () => { fixture = await createFixtureServer(); });
after(async () => { if (fixture) await fixture.close(); });

async function serve(routes) {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const route = routes[url.pathname];
    if (!route) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("missing");
      return;
    }
    route(request, response, url);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}/`, close: () => new Promise((resolve) => server.close(resolve)) };
}

test("robots parsing applies groups, wildcard patterns, specificity and malformed lines", () => {
  const parsed = parseRobots(`
    # comment
    User-agent: *
    Disallow: /private
    Allow: /private/public
    Disallow: /*.pdf$
    Sitemap: https://example.com/sitemap.xml
    Malformed line
  `);
  assert.equal(parsed.sitemaps[0], "https://example.com/sitemap.xml");
  assert.equal(robotsAllows(parsed, "http://example.com/private/file").allowed, false);
  assert.equal(robotsAllows(parsed, "http://example.com/private/public/file").allowed, true);
  assert.equal(robotsAllows(parsed, "http://example.com/file.pdf").allowed, false);
  assert.equal(robotsAllows(parsed, "http://example.com/file.pdf?download=1").allowed, true);
  assert.equal(robotsAllows(parsed, "http://example.com/public").allowed, true);
  const encoded = parseRobots("User-agent: *\nDisallow: /caf%C3%A9\nAllow: /caf\u00e9/public\n");
  assert.equal(robotsAllows(encoded, "http://example.com/caf%C3%A9/private").allowed, false);
  assert.equal(robotsAllows(encoded, "http://example.com/caf\u00e9/public").allowed, true);
  const exact = parseRobots("User-agent: *\nDisallow: /wildcard\n\nUser-agent: webtim-inspector\nDisallow: /blocked\n");
  assert.equal(robotsAllows(exact, "http://example.com/wildcard").allowed, true);
  assert.equal(robotsAllows(exact, "http://example.com/blocked").allowed, false);
});

test("sitemap parsing handles ordinary sitemaps, indexes, malformed XML and relative URLs", () => {
  assert.deepEqual(parseSitemap('<urlset><url><loc>https://example.com/a</loc></url></urlset>'), {
    index: false,
    locations: ["https://example.com/a"]
  });
  assert.deepEqual(parseSitemap('<sitemapindex><sitemap><loc>/one.xml</loc></sitemap></sitemapindex>'), {
    index: true,
    locations: ["/one.xml"]
  });
  assert.deepEqual(parseSitemap("not xml"), { index: false, locations: [] });
});

test("URL normalization keeps query identity while removing fragments and default ports", () => {
  assert.equal(normalizeCrawlUrl("HTTP://Example.COM:80/a/../b?x=1#frag"), "http://example.com/b?x=1");
  assert.equal(normalizeCrawlUrl("/docs/", "https://example.com/start/"), "https://example.com/docs/");
  assert.equal(normalizeCrawlUrl("https://example.com/a?x=1"), "https://example.com/a?x=1");
  assert.equal(normalizeCrawlUrl("https://example.com/a/"), "https://example.com/a/");
  assert.notEqual(normalizeCrawlUrl("https://example.com/a"), normalizeCrawlUrl("https://example.com/a/"));
  assert.equal(normalizeCrawlUrl("mailto:a@example.com", "https://example.com/"), null);
});

test("robots 4xx allows crawling, 5xx and network failures disallow it, and redirects are followed", async () => {
  let robotsStatus = 404;
  let redirect = false;
  const server = await serve({
    "/robots.txt": (request, response) => {
      if (redirect) {
        response.writeHead(302, { location: "/robots-real.txt" });
        response.end();
        return;
      }
      response.writeHead(robotsStatus, { "content-type": "text/plain" });
      response.end("User-agent: *\\nDisallow: /private\\n");
    },
    "/robots-real.txt": (request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("User-agent: *\\nDisallow: /redirected\\n");
    }
  });
  try {
    const local = new UrlPolicy({ allowPrivate: true });
    assert.equal((await fetchRobots(server.url, local)).status, "unavailable");
    robotsStatus = 500;
    assert.equal((await fetchRobots(server.url, local)).status, "disallowed");
    robotsStatus = 200;
    redirect = true;
    const redirected = await fetchRobots(server.url, local);
    assert.equal(redirected.status, "parsed");
    assert.match(redirected.finalUrl, /robots-real/);
    const blocked = await fetchRobots("http://127.0.0.1:1/", local);
    assert.equal(blocked.status, "disallowed");
  } finally {
    await server.close();
  }
});

test("a bounded crawl discovers same-origin pages, respects robots, records failures and aggregates findings", async () => {
  const report = await crawlSite({
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["security"],
    maxPages: 10,
    maxDepth: 2,
    maxConcurrency: 2
  });
  assert.equal(report.target.scope, "site");
  assert.equal(report.crawl.robots.status, "parsed");
  assert.equal(report.crawl.sitemap.status, "parsed");
  const states = new Map(report.crawl.pages.map((page) => [page.url, page.state]));
  assert.equal(states.get(`${fixture.url}crawl/`), "completed");
  assert.equal(states.get(`${fixture.url}crawl/child`), "completed");
  assert.equal(states.get(`${fixture.url}crawl/grandchild`), "completed");
  assert.equal(states.get(`${fixture.url}private/`), "robots-skipped");
  assert.equal(states.get(`${fixture.url}missing-page.html`), "failed");
  assert.ok([...states.keys()].some((url) => url.includes("?same=1")));
  assert.ok(![...states.keys()].some((url) => url.includes("example.com/external")));
  assert.equal(report.crawl.coverage.failed, 1);
  assert.equal(report.crawl.coverage.robotsSkipped, 1);
  const repeated = report.findings.find((finding) => finding.ruleId === "security.no-https");
  assert.ok(repeated);
  assert.ok(repeated.pageCount > 1);
  assert.ok(repeated.affectedPages.length > 1);
  assert.match(renderHtml(report), /Site crawl/);
  assert.match(renderHtml(report), /Affects \d+ page\(s\)/);
  assert.equal(report.status, "partial");
});

test("crawl page and depth limits are explicit, deterministic and not reported as passes", async () => {
  const report = await crawlSite({
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["security"],
    maxPages: 1,
    maxDepth: 0
  });
  assert.equal(report.crawl.pages.length, 1);
  assert.ok(report.crawl.skipped.length > 0);
  assert.ok(report.crawl.skipped.every((entry) => entry.state === "limit-skipped"));
  assert.equal(report.crawl.coverage.audited, 1);
  const concurrent = await crawlSite({
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["security"],
    maxPages: 1,
    maxDepth: 2,
    maxConcurrency: 2
  });
  assert.equal(concurrent.crawl.pages.length, 1);
  assert.ok(concurrent.crawl.skipped.length > 0);
});

test("repeated fixture crawls expose the same ordered page coverage", async () => {
  const options = {
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["security"],
    maxPages: 3,
    maxDepth: 1
  };
  const first = await crawlSite(options);
  const second = await crawlSite(options);
  assert.deepEqual(first.crawl.pages.map((page) => page.url), second.crawl.pages.map((page) => page.url));
  assert.deepEqual(first.crawl.skipped.map((page) => page.url), second.crawl.skipped.map((page) => page.url));
});

test("a cancelled crawl returns a partial report instead of claiming completion", async () => {
  const controller = new AbortController();
  controller.abort();
  const report = await crawlSite({
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["security"],
    maxPages: 3,
    signal: controller.signal
  });
  assert.equal(report.status, "partial");
  assert.equal(report.crawl.cancelled, true);
  assert.equal(report.crawl.coverage.audited, 0);
  assert.ok(report.crawl.pages.length === 0 || report.crawl.pages.some((page) => page.state === "cancelled"));
  assert.ok(report.crawl.skipped.some((entry) => entry.state === "cancelled"));
});

test("a timed-out page is explicit and does not abort the rest of the crawl", async () => {
  const server = await serve({
    "/robots.txt": (request, response) => {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("missing");
    },
    "/": (request, response) => {
      setTimeout(() => {
        if (!response.writableEnded) response.end("<html><body>slow</body></html>");
      }, 1_500);
    }
  });
  try {
    const report = await crawlSite({
      url: server.url,
      allowPrivate: true,
      categories: ["security"],
      maxPages: 1,
      timeoutMs: 1_000
    });
    assert.equal(report.crawl.pages[0].state, "timed-out");
    assert.equal(report.crawl.coverage.timedOut, 1);
    assert.equal(report.status, "partial");
  } finally {
    await server.close();
  }
});

test("sitemap indexes are bounded, same-origin candidates and size limits are enforced", async () => {
  const server = await serve({
    "/": (request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end('<html><head><title>Home</title></head><body><h1>Home</h1></body></html>');
    },
    "/robots.txt": (request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("User-agent: *\\nAllow: /\\nSitemap: /sitemap.xml\\n");
    },
    "/sitemap.xml": (request, response) => {
      response.writeHead(200, { "content-type": "application/xml" });
      response.end(`<sitemapindex><sitemap><loc>/one.xml</loc></sitemap><sitemap><loc>/two.xml</loc></sitemap></sitemapindex>`);
    },
    "/one.xml": (request, response) => {
      response.writeHead(200, { "content-type": "application/xml" });
      response.end(`<urlset><url><loc>/a</loc></url><url><loc>/b</loc></url><url><loc>https://example.com/external</loc></url></urlset>`);
    },
    "/two.xml": (request, response) => {
      response.writeHead(200, { "content-type": "application/xml" });
      response.end(`<urlset><url><loc>/c</loc></url></urlset>`);
    },
    "/a": (request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<html><body><h1>A</h1></body></html>");
    }
  });
  try {
    const report = await crawlSite({
      url: server.url,
      allowPrivate: true,
      categories: ["security"],
      maxPages: 5,
      maxSitemapFiles: 5,
      maxSitemapUrls: 2
    });
    assert.equal(report.crawl.sitemap.status, "parsed");
    assert.equal(report.crawl.sitemap.urls.length, 2);
    assert.equal(report.crawl.sitemap.truncated, true);
    assert.ok(report.crawl.pages.every((page) => page.url.startsWith(server.url)));
  } finally {
    await server.close();
  }
});

test("a browser-backed crawl audits multiple pages through the validating proxy", async () => {
  const report = await crawlSite({
    url: `${fixture.url}crawl/`,
    allowPrivate: true,
    categories: ["accessibility"],
    maxPages: 2,
    maxDepth: 1
  });
  assert.equal(report.status, "complete");
  assert.equal(report.crawl.coverage.audited, 2);
  assert.ok(report.crawl.pages.every((page) => page.categories.accessibility.status === "ok"));
  assert.ok(report.crawl.pages.every((page) => page.environment.browser.version.startsWith("157.")));
  const boundary = report.crawl.pages[0].environment.networkBoundary;
  assert.equal(boundary.mode, "validating-proxy");
  assert.ok(boundary.httpRequests + boundary.connections > 0);
});
