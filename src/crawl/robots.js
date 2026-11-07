import { requestSafe } from "../core/url-policy.js";

const MAX_ROBOTS_BYTES = 512 * 1024;

function clean(value) {
  return String(value || "").trim();
}

/**
 * Parse RFC 9309 group records. Rules are matched against path + query.
 * Unknown lines are ignored; malformed records do not abort the crawl.
 */
export function parseRobots(text) {
  const groups = [];
  const sitemaps = [];
  let group = null;
  for (const rawLine of String(text || "").replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const split = /^([a-z-]+)\s*:\s*(.*)$/i.exec(line);
    if (!split) continue;
    const name = split[1].toLowerCase();
    const value = clean(split[2]);
    if (name === "user-agent") {
      if (!group || group.rules.length) {
        group = { agents: [], rules: [] };
        groups.push(group);
      }
      if (value) group.agents.push(value.toLowerCase());
      continue;
    }
    if (name === "allow" || name === "disallow") {
      if (!group) {
        group = { agents: ["*"], rules: [] };
        groups.push(group);
      }
      if (value) group.rules.push({ allow: name === "allow", pattern: value });
      continue;
    }
    if (name === "sitemap" && value) sitemaps.push(value);
  }
  return {
    groups: groups.filter((entry) => entry.agents.length || entry.rules.length),
    sitemaps: [...new Set(sitemaps)]
  };
}

function patternRegex(pattern) {
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const escaped = body.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${escaped}${anchored ? "$" : ""}`);
}

function ruleSpecificity(pattern) {
  return pattern.replace(/\$$/, "").replaceAll("*", "").length;
}

function decodePath(value) {
  try { return decodeURI(value); } catch { return value; }
}

function matchingRules(parsed, userAgent) {
  const token = String(userAgent || "webtim-inspector").toLowerCase();
  const exact = parsed.groups.filter((group) => group.agents.some((agent) => agent === token || agent.startsWith(`${token}/`)));
  const fallback = parsed.groups.filter((group) => group.agents.includes("*"));
  return [...(exact.length ? exact : fallback).flatMap((group) => group.rules)];
}

export function robotsAllows(parsed, url, userAgent = "webtim-inspector") {
  const target = new URL(url);
  const path = decodePath(`${target.pathname}${target.search}`);
  const rules = matchingRules(parsed, userAgent);
  if (!rules.length) return { allowed: true, rule: null };
  const matching = rules
    .filter((rule) => patternRegex(decodePath(rule.pattern)).test(path))
    .sort((left, right) => {
      const specificity = ruleSpecificity(right.pattern) - ruleSpecificity(left.pattern);
      return specificity || Number(right.allow) - Number(left.allow);
    });
  const rule = matching[0] || null;
  return { allowed: !rule || rule.allow, rule };
}

export async function fetchRobots(origin, policy, {
  timeoutMs = 15_000,
  userAgent = "webtim-inspector"
} = {}) {
  const url = new URL("/robots.txt", origin).href;
  try {
    const response = await requestSafe(url, {
      policy,
      timeoutMs,
      maxBytes: MAX_ROBOTS_BYTES,
      headers: { "user-agent": userAgent, "accept-encoding": "identity" }
    });
    if (response.status >= 200 && response.status < 300) {
      const parsed = parseRobots(response.body.toString("utf8"));
      return {
        url,
        finalUrl: response.url,
        status: "parsed",
        httpStatus: response.status,
        groups: parsed.groups,
        sitemaps: parsed.sitemaps,
        error: null
      };
    }
    if (response.status >= 500) {
      return {
        url, finalUrl: response.url, status: "disallowed", httpStatus: response.status,
        groups: [], sitemaps: [], error: `robots.txt returned HTTP ${response.status}`
      };
    }
    return {
      url, finalUrl: response.url, status: "unavailable", httpStatus: response.status,
      groups: [], sitemaps: [], error: null
    };
  } catch (error) {
    return {
      url, finalUrl: url, status: "disallowed", httpStatus: null,
      groups: [], sitemaps: [], error: error.message
    };
  }
}

export function robotsDecision(robots, url, userAgent = "webtim-inspector") {
  if (!robots || robots.status === "unavailable") return { allowed: true, rule: null };
  if (robots.status === "disallowed") return { allowed: false, rule: null };
  return robotsAllows(robots, url, userAgent);
}
