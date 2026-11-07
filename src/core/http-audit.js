import { requestSafe } from "./url-policy.js";

function header(headers, name) {
  return headers?.[name.toLowerCase()] ?? null;
}

function parseCookies(raw) {
  if (!raw) return [];
  const values = Array.isArray(raw) ? raw : [raw];
  return values.map((value) => {
    const [pair, ...attributes] = String(value).split(";").map((part) => part.trim());
    const [name] = pair.split("=");
    const lower = attributes.map((attribute) => attribute.toLowerCase());
    return {
      name,
      secure: lower.includes("secure"),
      httpOnly: lower.includes("httponly"),
      sameSite: attributes.find((attribute) => /^samesite=/i.test(attribute))?.split("=")[1] || null,
      hasExpiry: lower.some((attribute) => /^(max-age|expires)=/.test(attribute))
    };
  });
}

function safeHeaders(headers) {
  const selected = {};
  for (const name of [
    "content-type",
    "content-encoding",
    "cache-control",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-frame-options",
    "server",
    "x-powered-by",
    "location"
  ]) {
    if (headers?.[name] !== undefined) selected[name] = headers[name];
  }
  return selected;
}

async function optionalText(url, policy, { timeoutMs, maxBytes }) {
  try {
    const result = await requestSafe(url, { policy, timeoutMs, maxBytes: Math.min(maxBytes, 512 * 1024) });
    return {
      url: result.url,
      status: result.status,
      contentType: header(result.headers, "content-type"),
      text: result.body.toString("utf8").slice(0, 256 * 1024),
      error: null
    };
  } catch (error) {
    return { url, status: null, contentType: null, text: null, error: error.message };
  }
}

export async function inspectHttp(url, policy, {
  timeoutMs = 15_000,
  maxBytes = 5 * 1024 * 1024
} = {}) {
  const started = Date.now();
  try {
    const result = await requestSafe(url, { policy, timeoutMs, maxBytes });
    const finalUrl = result.url;
    const origin = new URL(finalUrl).origin;
    const [robots, sitemap] = await Promise.all([
      optionalText(new URL("/robots.txt", origin).href, policy, { timeoutMs, maxBytes }),
      optionalText(new URL("/sitemap.xml", origin).href, policy, { timeoutMs, maxBytes })
    ]);
    return {
      ok: true,
      requestedUrl: url,
      finalUrl,
      status: result.status,
      durationMs: Date.now() - started,
      redirects: result.redirects,
      headers: safeHeaders(result.headers),
      rawHeaders: result.headers,
      cookies: parseCookies(result.headers["set-cookie"]),
      tls: result.tls,
      contentLength: result.body.length,
      body: result.body,
      contentType: header(result.headers, "content-type"),
      robots,
      sitemap,
      error: null
    };
  } catch (error) {
    return {
      ok: false,
      requestedUrl: url,
      finalUrl: null,
      status: null,
      durationMs: Date.now() - started,
      redirects: [],
      headers: {},
      rawHeaders: {},
      cookies: [],
      tls: null,
      contentLength: 0,
      body: null,
      contentType: null,
      robots: null,
      sitemap: null,
      error: { code: error.code || "REQUEST_FAILED", message: error.message }
    };
  }
}

export function headerValue(headers, name) {
  return header(headers, name);
}
