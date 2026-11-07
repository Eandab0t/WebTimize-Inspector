import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createFixtureServer } from "../fixtures/site-server.js";
import { isBlockedAddress, isMetadataAddress, requestSafe, UrlPolicy } from "../src/core/url-policy.js";

let fixture;
before(async () => { fixture = await createFixtureServer(); });
after(async () => { if (fixture) await fixture.close(); });

test("private, loopback, link-local, metadata and non-canonical destinations are rejected", async () => {
  const policy = new UrlPolicy();
  for (const url of [
    "http://localhost/",
    "http://metadata.google.internal/",
    "file:///etc/passwd",
    "http://user:pass@example.com/"
  ]) {
    assert.throws(() => policy.parse(url), undefined, url);
  }
  for (const url of [
    "http://127.0.0.1/",
    "http://10.1.2.3/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[fd00::1]/"
  ]) {
    await assert.rejects(() => policy.resolve(url), undefined, url);
  }
  assert.equal(isBlockedAddress("::ffff:127.0.0.1"), true);
  assert.equal(isBlockedAddress("2606:4700:4700::1111"), false);
  assert.equal(isMetadataAddress("169.254.169.254"), true);
});

test("an explicitly local scan can reach loopback but still cannot reach metadata", async () => {
  const local = new UrlPolicy({ allowPrivate: true });
  assert.equal(local.parse(fixture.url).href, fixture.url);
  assert.equal(local.parse("http://169.254.169.254/").hostname, "169.254.169.254");
  await assert.rejects(() => local.resolve("http://169.254.169.254/"), /metadata/i);
});

test("requestSafe validates the connection and follows an allowed redirect", async () => {
  const local = new UrlPolicy({ allowPrivate: true });
  const result = await requestSafe(new URL("/redirect", fixture.url).href, { policy: local });
  assert.equal(result.status, 200);
  assert.equal(result.redirects.length, 1);
  assert.match(result.body.toString(), /Controlled audit fixture/);
});

test("requestSafe rejects a redirect into a metadata endpoint", async () => {
  const local = new UrlPolicy({ allowPrivate: true });
  await assert.rejects(
    () => requestSafe(new URL("/redirect-private", fixture.url).href, { policy: local }),
    /metadata/i
  );
});

test("response size and timeout limits fail closed", async () => {
  const local = new UrlPolicy({ allowPrivate: true });
  await assert.rejects(
    () => requestSafe(new URL("/huge", fixture.url).href, { policy: local, maxBytes: 1024 }),
    /exceeds/i
  );
  await assert.rejects(
    () => requestSafe(new URL("/slow", fixture.url).href, { policy: local, timeoutMs: 100 }),
    /timed out/i
  );
});

test("the default policy rejects a local fixture before a browser is launched", async () => {
  const policy = new UrlPolicy();
  await assert.rejects(() => policy.resolve(fixture.url), /blocked|private/i);
});
