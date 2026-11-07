import fs from "node:fs";
import { createHash } from "node:crypto";
import { requestSafe, UrlPolicy } from "../core/url-policy.js";

function expectedMime(type) {
  return String(type || "").toLowerCase();
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
    const url = new URL(asset.final, base).href;
    try {
      const response = await requestSafe(url, { policy, timeoutMs, maxBytes });
      const actualHash = createHash("sha256").update(response.body).digest("hex");
      const expectedHash = String(asset.sha256 || "").toLowerCase();
      const contentType = String(response.headers["content-type"] || "").toLowerCase();
      const result = {
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
        typeMatch: asset.type ? contentType.includes(expectedMime(asset.type)) : null,
        contentEncoding: response.headers["content-encoding"] || null,
        cacheControl: response.headers["cache-control"] || null,
        error: null
      };
      results.push(result);
    } catch (error) {
      results.push({
        original: asset.original,
        final: asset.final,
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
        error: error.message
      });
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
