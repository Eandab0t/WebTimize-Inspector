import fs from "node:fs";
import { createHash } from "node:crypto";
import { requestSafe, UrlPolicy } from "../core/url-policy.js";

// Compressor declares `text/javascript`; servers may answer with the equally valid
// `application/javascript` and usually append `; charset=…`. Compare the MIME essence.
const JS_TYPES = new Set(["text/javascript", "application/javascript", "application/x-javascript", "text/x-javascript"]);

function mimeEssence(value) {
  return String(value || "").split(";")[0].trim().toLowerCase();
}

function typeMatches(expected, actual) {
  const want = mimeEssence(expected);
  if (!want) return null;
  const got = mimeEssence(actual);
  return got === want || (want === "text/javascript" && JS_TYPES.has(got));
}

// A manifest is data the user can edit, so `final` must be a plain relative path: anything that
// could select another origin or leave the deployed root is a manifest error, reported without a
// request. The decoded form is checked too, because the URL parser normalises `%2E%2E/` and a
// server may decode `%2f`. Compressor emits only plain relative paths.
function decodedDotSegments(value) {
  return value.replace(/%2e/gi, ".").replace(/%2f/gi, "/").replace(/%5c/gi, "\\");
}

function isPlainRelativePath(value) {
  if (typeof value !== "string" || value === "") return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return false;
  const unsafe = (path) => path.startsWith("//") || path.includes("\\") || path.split("/").includes("..");
  return !unsafe(value) && !unsafe(decodedDotSegments(value));
}

function failureResult(asset, url, error) {
  return {
    original: asset.original,
    final: asset.final ?? null,
    url,
    status: null,
    hashExpected: asset.sha256 || null,
    hashActual: null,
    hashMatch: false,
    typeExpected: asset.type || null,
    typeActual: null,
    typeMatch: false,
    contentEncoding: null,
    cacheControl: null,
    error
  };
}

export async function verifyManifest(manifestPath, baseUrl, {
  allowPrivate = false,
  timeoutMs = 15_000,
  maxBytes = 20 * 1024 * 1024
} = {}) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.schema_version !== 1 || !Array.isArray(manifest.assets)) {
    throw new Error("unsupported manifest: expected schema_version 1 and an assets array");
  }
  const policy = new UrlPolicy({ allowPrivate });
  const base = policy.parse(baseUrl);
  await policy.resolve(base.href);
  const results = [];
  for (const asset of manifest.assets) {
    if (!isPlainRelativePath(asset.final)) {
      results.push(failureResult(asset, null, 'invalid manifest entry: "final" must be a plain relative path'));
      continue;
    }
    // `final` is a file path, not a URL: `%`, `#` and `?` in a name belong to the filename
    // (Compressor emits such names), so encode them rather than let a server decode a `%XX` into
    // a different name or the URL parser read a fragment/query.
    const urlPath = String(asset.final).replace(/%/g, "%25").replace(/[#?]/g, (char) => (char === "#" ? "%23" : "%3F"));
    const url = new URL(urlPath, base).href;
    try {
      const response = await requestSafe(url, { policy, timeoutMs, maxBytes });
      const expectedHash = String(asset.sha256 || "").toLowerCase();
      const actualHash = createHash("sha256").update(response.body).digest("hex");
      const contentType = String(response.headers["content-type"] || "").toLowerCase();
      results.push({
        original: asset.original,
        final: asset.final,
        url,
        status: response.status,
        bytes: response.bytes,
        hashExpected: expectedHash || null,
        hashActual: actualHash,
        hashMatch: expectedHash ? actualHash === expectedHash : null,
        typeExpected: asset.type || null,
        typeActual: contentType || null,
        typeMatch: typeMatches(asset.type, contentType),
        contentEncoding: response.headers["content-encoding"] || null,
        cacheControl: response.headers["cache-control"] || null,
        error: null
      });
    } catch (error) {
      results.push(failureResult(asset, url, error.message));
    }
  }
  const failures = results.filter((result) => result.error || result.status >= 400 || result.hashMatch === false || result.typeMatch === false);
  return {
    schemaVersion: 1,
    tool: "webtim-inspector",
    checkedAt: new Date().toISOString(),
    manifest: manifestPath,
    baseUrl: base.href,
    assets: results,
    summary: { total: results.length, failures: failures.length },
    limitations: [
      "Verification checks the manifest against bytes served at the supplied base URL. It does not prove that a deployment used this manifest.",
      "A 200 response is not proof that a CDN is serving every edge location or that the asset was not later replaced."
    ]
  };
}
