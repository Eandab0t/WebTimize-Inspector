import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";

const RESTRICTED_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];
const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "instance-data.ec2.internal"
]);

export class UrlPolicyError extends Error {
  constructor(message, code = "URL_REJECTED") {
    super(message);
    this.name = "UrlPolicyError";
    this.code = code;
  }
}

function parseIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const bytes = parts.map(Number);
  return bytes.every((part) => part >= 0 && part <= 255) ? bytes : null;
}

function parseIPv6(value) {
  if (!value.includes(":")) return null;
  const text = value.split("%")[0].toLowerCase();
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const leftInput = halves[0] ? halves[0].split(":") : [];
  const rightInput = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const parseSide = (input) => {
    const groups = [];
    for (const group of input) {
      if (group.includes(".")) {
        const ipv4 = parseIPv4(group);
        if (!ipv4) throw new Error("bad IPv4-in-IPv6");
        groups.push(((ipv4[0] << 8) | ipv4[1]).toString(16));
        groups.push(((ipv4[2] << 8) | ipv4[3]).toString(16));
      } else {
        groups.push(group);
      }
    }
    return groups;
  };
  let left;
  let right;
  try {
    left = parseSide(leftInput);
    right = parseSide(rightInput);
  } catch {
    return null;
  }
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  const expanded = [...left, ...Array(missing).fill("0"), ...right];
  if (expanded.length !== 8 || expanded.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }
  const bytes = [];
  for (const group of expanded) {
    const number = parseInt(group, 16);
    bytes.push((number >> 8) & 0xff, number & 0xff);
  }
  return bytes;
}

function inIpv4Range(bytes, network, prefix) {
  const value = bytes.reduce((total, byte) => (total << 8) | byte, 0) >>> 0;
  const base = network.reduce((total, byte) => (total << 8) | byte, 0) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function blockedIpv4(bytes) {
  const ranges = [
    [[0, 0, 0, 0], 8],
    [[10, 0, 0, 0], 8],
    [[100, 64, 0, 0], 10],
    [[127, 0, 0, 0], 8],
    [[169, 254, 0, 0], 16],
    [[172, 16, 0, 0], 12],
    [[192, 0, 0, 0], 24],
    [[192, 0, 2, 0], 24],
    [[192, 88, 99, 0], 24],
    [[192, 168, 0, 0], 16],
    [[198, 18, 0, 0], 15],
    [[198, 51, 100, 0], 24],
    [[203, 0, 113, 0], 24],
    [[224, 0, 0, 0], 4],
    [[240, 0, 0, 0], 4]
  ];
  return ranges.some(([network, prefix]) => inIpv4Range(bytes, network, prefix));
}

function blockedIpv6(bytes) {
  if (bytes.every((byte) => byte === 0)) return true;
  if (bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1) return true;
  if ((bytes[0] & 0xfe) === 0xfc) return true;
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0xc0) return true;
  if ((bytes[0] & 0xff) === 0xff) return true;
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return true;

  const mapped = bytes.slice(0, 10).every((byte) => byte === 0) &&
    bytes[10] === 0xff && bytes[11] === 0xff;
  if (mapped) return blockedIpv4(bytes.slice(12, 16));

  const translated = bytes.slice(0, 8).every((byte) => byte === 0) &&
    bytes.slice(8, 12).every((byte) => byte === 0xff);
  if (translated) return blockedIpv4(bytes.slice(12, 16));

  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b) return true;
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    const embedded = bytes.slice(2, 6);
    if (blockedIpv4(embedded)) return true;
  }
  return false;
}

export function isMetadataAddress(value) {
  const address = String(value || "").split("%")[0].toLowerCase();
  return address === "169.254.169.254" || address === "fd00:ec2::254";
}

export function isBlockedAddress(value) {
  const address = String(value || "").split("%")[0];
  const family = net.isIP(address);
  if (family === 4) {
    const bytes = parseIPv4(address);
    return !bytes || blockedIpv4(bytes);
  }
  if (family === 6) {
    const bytes = parseIPv6(address);
    return !bytes || blockedIpv6(bytes);
  }
  return true;
}

function looksNumeric(host) {
  return (
    /^\d+(\.\d+)*$/.test(host) ||
    /^0x[0-9a-f]+$/i.test(host) ||
    /^\d+$/.test(host) ||
    /^[0-9a-f:]+\.(in-addr|ip6)\.arpa$/i.test(host)
  );
}

export class UrlPolicy {
  constructor({ allowPrivate = false } = {}) {
    this.allowPrivate = allowPrivate;
  }

  assertHostname(hostname) {
    const host = String(hostname || "").replace(/\.$/, "").toLowerCase();
    if (!host || host.length > 253 || host.includes("%") || /[\s/\\]/.test(host)) {
      throw new UrlPolicyError("invalid hostname", "INVALID_HOST");
    }
    if (METADATA_HOSTS.has(host) || host.endsWith(".metadata.google.internal")) {
      throw new UrlPolicyError(`blocked metadata hostname: ${host}`, "METADATA_HOST");
    }
    if (!this.allowPrivate) {
      if (host === "localhost" || RESTRICTED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
        throw new UrlPolicyError(`blocked hostname: ${host}`, "PRIVATE_HOST");
      }
      if (looksNumeric(host) && net.isIP(host) === 0) {
        throw new UrlPolicyError("non-canonical numeric address is not accepted", "NUMERIC_HOST");
      }
    }
  }

  parse(rawUrl) {
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new UrlPolicyError("URL is not valid", "INVALID_URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new UrlPolicyError("only http and https URLs are supported", "INVALID_SCHEME");
    }
    if (url.username || url.password) {
      throw new UrlPolicyError("credentials in URLs are not accepted", "URL_CREDENTIALS");
    }
    if (url.port === "0") throw new UrlPolicyError("port zero is not accepted", "INVALID_PORT");
    const hostname = bareHostname(url);
    this.assertHostname(hostname);
    if (!hostname.includes(":")) url.hostname = hostname;
    return url;
  }

  async resolve(rawUrl) {
    const url = this.parse(rawUrl);
    const hostname = bareHostname(url);
    if (net.isIP(hostname)) {
      if (isMetadataAddress(hostname)) {
        throw new UrlPolicyError(`blocked metadata address: ${hostname}`, "METADATA_ADDRESS");
      }
      if (!this.allowPrivate && isBlockedAddress(hostname)) {
        throw new UrlPolicyError(`blocked IP address: ${hostname}`, "PRIVATE_ADDRESS");
      }
      return [hostname];
    }
    const addresses = await new Promise((resolve, reject) => {
      dns.lookup(hostname, { all: true, verbatim: true }, (error, results) => {
        if (error) reject(new UrlPolicyError(`DNS lookup failed: ${error.code || "error"}`, "DNS_ERROR"));
        else resolve(results);
      });
    });
    if (!addresses.length) throw new UrlPolicyError("hostname resolved to no addresses", "DNS_EMPTY");
    for (const result of addresses) {
      if (isMetadataAddress(result.address)) {
        throw new UrlPolicyError(`hostname resolves to a metadata address: ${result.address}`, "METADATA_ADDRESS");
      }
      if (!this.allowPrivate && isBlockedAddress(result.address)) {
        throw new UrlPolicyError(`hostname resolves to a blocked address: ${result.address}`, "PRIVATE_ADDRESS");
      }
    }
    return addresses.map((result) => result.address);
  }

  lookup(hostname, options, callback) {
    const done = (error, addresses) => {
      if (error) {
        callback(error);
        return;
      }
      if (options && options.all) callback(null, addresses);
      else callback(null, addresses[0].address, addresses[0].family);
    };
    dns.lookup(hostname, { ...options, all: true, verbatim: true }, (error, addresses) => {
      if (error) {
        done(new UrlPolicyError("connection-time DNS lookup failed", "DNS_ERROR"));
        return;
      }
      if (!addresses?.length) {
        done(new UrlPolicyError("connection-time DNS lookup returned no addresses", "DNS_EMPTY"));
        return;
      }
      const metadata = addresses.find((entry) => isMetadataAddress(entry.address));
      if (metadata) {
        done(new UrlPolicyError(`connection-time address is a metadata endpoint: ${metadata.address}`, "METADATA_ADDRESS"));
        return;
      }
      if (!this.allowPrivate) {
        const blocked = addresses.find((entry) => isBlockedAddress(entry.address));
        if (blocked) {
          done(new UrlPolicyError(`connection-time address is blocked: ${blocked.address}`, "PRIVATE_ADDRESS"));
          return;
        }
      }
      done(null, addresses);
    });
  }
}

export async function assertSafeUrl(rawUrl, { allowPrivate = false } = {}) {
  const policy = new UrlPolicy({ allowPrivate });
  await policy.resolve(rawUrl);
  return policy.parse(rawUrl).href;
}

/**
 * Make one HTTP request with connection-time address validation. Redirects are
 * followed explicitly so every destination is checked by the same policy.
 */
function bareHostname(url) {
  return url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export async function requestSafe(rawUrl, {
  policy = new UrlPolicy(),
  maxRedirects = 5,
  maxBytes = 5 * 1024 * 1024,
  timeoutMs = 15_000,
  method = "GET",
  headers = {}
} = {}) {
  const redirects = [];
  let current = policy.parse(rawUrl);

  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
    const result = await requestOnce(current, {
      policy,
      maxBytes,
      timeoutMs,
      method,
      headers,
      redirectCount
    });
    const location = result.headers.location;
    if (![301, 302, 303, 307, 308].includes(result.status) || !location) {
      return { ...result, redirects };
    }
    if (redirectCount === maxRedirects) {
      throw new UrlPolicyError("too many redirects", "TOO_MANY_REDIRECTS");
    }
    const next = policy.parse(new URL(location, current).href);
    await policy.resolve(next.href);
    redirects.push({ url: current.href, status: result.status, location: next.href });
    current = next;
  }
  throw new UrlPolicyError("redirect limit exceeded", "TOO_MANY_REDIRECTS");
}

function requestOnce(url, { policy, maxBytes, timeoutMs, method, headers, redirectCount }) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    let tls = null;
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const request = transport.request(url, {
      method,
      headers: {
        "user-agent": "Webtimize-Inspector/0.1 (+local audit)",
        accept: "*/*",
        "accept-encoding": "gzip, deflate, br",
        ...headers
      },
      lookup: policy.lookup.bind(policy),
      timeout: timeoutMs,
      rejectUnauthorized: true,
      servername: bareHostname(url)
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          request.destroy();
          finish(reject, new UrlPolicyError(`response exceeds ${maxBytes} bytes`, "RESPONSE_TOO_LARGE"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        finish(resolve, {
          url: url.href,
          status: response.statusCode || 0,
          headers: response.headers,
          rawHeaders: response.rawHeaders,
          body: Buffer.concat(chunks),
          bytes,
          tls,
          redirectCount
        });
      });
      response.on("error", (error) => finish(reject, error));
    });
    if (url.protocol === "https:") {
      request.on("socket", (socket) => {
        socket.once("secureConnect", () => {
          try {
            const certificate = socket.getPeerCertificate();
            tls = {
              authorized: socket.authorized,
              authorizationError: socket.authorizationError || null,
              validFrom: certificate?.valid_from || null,
              validTo: certificate?.valid_to || null,
              subject: certificate?.subject?.CN || null,
              issuer: certificate?.issuer?.CN || null
            };
          } catch {
            tls = { authorized: false, authorizationError: "certificate unavailable" };
          }
        });
      });
    }
    request.setTimeout(timeoutMs, () => {
      request.destroy(new UrlPolicyError("request timed out", "TIMEOUT"));
    });
    request.on("error", (error) => finish(reject, error));
    request.end();
  });
}
