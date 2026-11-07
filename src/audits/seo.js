import { createFinding } from "../core/findings.js";
import { requestSafe } from "../core/url-policy.js";

function add(findings, input) {
  findings.push(createFinding({ category: "seo", ...input }));
}

function sitemapCount(text) {
  if (!text) return 0;
  return (text.match(/<loc\b/gi) || []).length;
}

export async function seoAudit({ browser, http, url, policy, maxLinks = 20, maxBytes = 5 * 1024 * 1024, timeoutMs = 10_000 }) {
  const findings = [];
  const checks = [];
  const skipped = [];
  const page = browser?.runs?.find((run) => run.pageData)?.pageData;
  const title = page?.title?.trim() || "";
  const description = page?.meta?.description?.trim() || "";
  const robots = String(page?.meta?.robots || "").toLowerCase();

  checks.push(
    { id: "seo.title", status: title ? "observed" : "missing" },
    { id: "seo.meta-description", status: description ? "observed" : "missing" },
    { id: "seo.robots-txt", status: http?.robots?.status ? "observed" : "unavailable" },
    { id: "seo.sitemap", status: http?.sitemap?.status ? "observed" : "unavailable" }
  );

  if (!title) {
    add(findings, {
      ruleId: "missing-title",
      title: "The page has no title",
      description: "No non-empty document title was found. Search engines and browser tabs use the title as a primary label.",
      severity: "high",
      confidence: "high",
      evidence: `<title>${page?.title || ""}</title>`,
      url,
      detection: "DOM document.title",
      reference: "https://developers.google.com/search/docs/appearance/title-link",
      remediation: "Add a unique, descriptive title in the document head.",
      impact: "Search results and browser tabs cannot describe the page accurately.",
      verification: "Reload the page and inspect the browser tab and rendered head."
    });
  } else {
    if (title.length < 15) {
      add(findings, {
        ruleId: "short-title",
        title: "The page title is very short",
        description: `The title is ${title.length} characters. Short titles may omit important context, although Google does not apply a fixed character limit.`,
        severity: "low",
        confidence: "high",
        evidence: title,
        url,
        element: "title",
        detection: "DOM document.title",
        reference: "https://developers.google.com/search/docs/appearance/title-link",
        remediation: "Describe the page and site without keyword stuffing.",
        impact: "Users may not understand the page's purpose from a search result.",
        verification: "Review the title in search-result preview tools after deployment."
      });
    }
    if (title.length > 70) {
      add(findings, {
        ruleId: "long-title",
        title: "The page title is long",
        description: `The title is ${title.length} characters and may be truncated in some search or browser surfaces. Character limits are presentation-dependent, not a ranking rule.`,
        severity: "informational",
        confidence: "high",
        evidence: title,
        url,
        element: "title",
        detection: "DOM document.title length",
        reference: "https://developers.google.com/search/docs/appearance/title-link",
        remediation: "Keep the distinguishing information near the start and avoid repetitive boilerplate.",
        impact: "The visible title may be shortened.",
        verification: "Check a search-result preview at the target device width."
      });
    }
  }

  if (!description) {
    add(findings, {
      ruleId: "missing-meta-description",
      title: "The page has no meta description",
      description: "No meta[name=description] content was found. Google may generate a snippet, but a description can still improve presentation.",
      severity: "medium",
      confidence: "high",
      evidence: "meta[name=description] absent or empty",
      url,
      detection: "DOM metadata",
      reference: "https://developers.google.com/search/docs/appearance/snippet",
      remediation: "Add a concise page-specific description that accurately summarizes the content.",
      impact: "Search engines may use an unrelated snippet.",
      verification: "Inspect the rendered head after deployment and check a search preview."
    });
  }

  if (http?.robots?.status === 404 || http?.robots?.error) {
    add(findings, {
      ruleId: "robots-unavailable",
      title: "robots.txt could not be read",
      description: `The /robots.txt request returned ${http.robots.status ?? "an error"}. A missing robots.txt is not automatically a crawl defect, but the site owner should know what is being served.`,
      severity: "informational",
      confidence: "high",
      evidence: http.robots.error || `HTTP ${http.robots.status}`,
      url: http.robots.url,
      detection: "Controlled HTTP request",
      reference: "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
      remediation: "Publish and validate robots.txt if crawling rules are needed; an empty file is valid.",
      impact: "Crawler directives may be absent or unexpectedly handled by the host.",
      verification: "Request /robots.txt directly and validate its syntax."
    });
  }

  if (http?.sitemap?.status === 404 || http?.sitemap?.error) {
    add(findings, {
      ruleId: "sitemap-unavailable",
      title: "A sitemap was not found at /sitemap.xml",
      description: "The conventional /sitemap.xml location returned no sitemap. Sitemaps are optional and may be declared elsewhere.",
      severity: "informational",
      confidence: "medium",
      evidence: http.sitemap.error || `HTTP ${http.sitemap.status}`,
      url: http.sitemap.url,
      detection: "Controlled HTTP request",
      reference: "https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap",
      remediation: "If a sitemap exists, declare it in robots.txt or submit it through the appropriate search-engine console.",
      impact: "Discovery of new or changed URLs may be less predictable.",
      verification: "Fetch the sitemap URL and confirm valid XML and absolute URLs."
    });
  } else if (http?.sitemap?.status && http.sitemap.status < 400) {
    checks.push({ id: "seo.sitemap.urls", status: "observed", value: sitemapCount(http.sitemap.text), unit: "loc entries" });
    if (!sitemapCount(http.sitemap.text)) {
      add(findings, {
        ruleId: "sitemap-without-loc",
        title: "The sitemap contains no loc entries",
        description: "A sitemap responded successfully but no <loc> entries were found in the inspected prefix.",
        severity: "low",
        confidence: "medium",
        evidence: http.sitemap.text.slice(0, 500),
        url: http.sitemap.url,
        detection: "Sitemap XML prefix scan",
        reference: "https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap",
        remediation: "Add valid absolute URLs to the sitemap and validate it with a sitemap tool.",
        impact: "The sitemap cannot help crawlers discover URLs.",
        verification: "Validate the XML and inspect the submitted sitemap."
      });
    }
  }

  if (page) {
    const headings = page.headings || [];
    const h1 = headings.filter((heading) => heading.level === 1);
    if (!h1.length) {
      add(findings, {
        ruleId: "missing-h1",
        title: "The page has no h1 heading",
        description: "No level-one heading was found. This is a structural signal, not proof that a page cannot rank.",
        severity: "medium",
        confidence: "high",
        evidence: headings.map((heading) => `h${heading.level} ${heading.text}`).join("\n") || "no headings",
        url,
        detection: "DOM heading outline",
        reference: "https://developers.google.com/search/docs/appearance/title-link",
        remediation: "Use one clear h1 that describes the page's main topic; preserve a logical heading hierarchy.",
        impact: "Users and parsers have a weaker outline of the page.",
        verification: "Inspect the rendered heading outline and confirm it matches the content."
      });
    }
    if (h1.length > 1) {
      add(findings, {
        ruleId: "multiple-h1",
        title: "The page has multiple h1 headings",
        description: `${h1.length} h1 elements were found. Multiple h1s are valid HTML; review whether the outline communicates one primary topic.`,
        severity: "informational",
        confidence: "high",
        evidence: h1.map((heading) => heading.text).join("\n"),
        url,
        detection: "DOM heading outline",
        reference: "https://html.spec.whatwg.org/multipage/sections.html#the-h1,-h2,-h3,-h4,-h5,-and-h6-elements",
        remediation: "Use headings to describe structure; do not add or remove them solely for a guessed ranking effect.",
        impact: "The outline may be ambiguous.",
        verification: "Review the outline with assistive technology and the rendered page."
      });
    }
    for (let index = 1; index < headings.length; index += 1) {
      if (headings[index].level - headings[index - 1].level > 1) {
        add(findings, {
          ruleId: "heading-level-skip",
          title: "The heading hierarchy skips a level",
          description: `The outline jumps from h${headings[index - 1].level} to h${headings[index].level}.`,
          severity: "low",
          confidence: "high",
          evidence: `${headings[index - 1].text} -> ${headings[index].text}`,
      url,
          element: headings[index].selector,
          detection: "DOM heading outline",
          reference: "https://www.w3.org/WAI/tutorials/page-structure/headings/",
          remediation: "Use the next heading level for nested sections, or adjust the document structure.",
          impact: "The page outline is harder to follow.",
          verification: "Recheck the outline after changing the markup."
        });
        break;
      }
    }
    if (page.meta?.robots && /\bnoindex\b/i.test(robots)) {
      add(findings, {
        ruleId: "noindex-directive",
        title: "The page declares noindex",
        description: "A robots meta directive includes noindex. This is a deliberate or accidental indexability signal, not proof of current search-engine state.",
        severity: "medium",
        confidence: "high",
        evidence: page.meta.robots,
        url,
        element: "meta[name=robots]",
        detection: "DOM robots meta tag",
        reference: "https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag",
        remediation: "Remove noindex if the page should be eligible for indexing; confirm with the site owner before changing it.",
        impact: "Search engines are instructed not to index the page.",
        verification: "Inspect the deployed head and use the search engine's URL inspection tool; this scan cannot confirm indexing."
      });
    }
    if (page.canonical) {
      try {
        const canonical = new URL(page.canonical, url);
        if (canonical.origin !== new URL(url).origin) {
          add(findings, {
            ruleId: "cross-origin-canonical",
            title: "The canonical URL points to another origin",
            description: `The canonical link resolves to ${canonical.origin}. This can be intentional, but it changes the preferred URL signal.`,
            severity: "medium",
            confidence: "high",
            evidence: canonical.href,
            url,
            element: 'link[rel="canonical"]',
            detection: "DOM canonical link",
            reference: "https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls",
            remediation: "Use the intended canonical URL and make sure it is indexable and reachable.",
            impact: "Search engines may consolidate signals on a different host or page.",
            verification: "Request the canonical URL and inspect the rendered head on both pages."
          });
        }
      } catch {
        add(findings, {
          ruleId: "invalid-canonical",
          title: "The canonical URL is invalid",
          description: "The canonical href could not be parsed as a URL.",
          severity: "medium",
          confidence: "high",
          evidence: page.canonical,
          url,
          element: 'link[rel="canonical"]',
          detection: "DOM canonical link",
          reference: "https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls",
          remediation: "Use an absolute or correctly resolved canonical URL.",
          impact: "The preferred URL signal is unusable.",
          verification: "Validate the canonical URL in the rendered page."
        });
      }
    } else {
      add(findings, {
        ruleId: "missing-canonical",
        title: "No canonical link was found",
        description: "No link[rel=canonical] was present. Canonicalization is optional, but it helps when the same content is reachable at multiple URLs.",
        severity: "informational",
        confidence: "high",
        evidence: "link[rel=canonical] absent",
        url,
        detection: "DOM canonical link",
        reference: "https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls",
        remediation: "Add a self-referencing canonical if duplicate URL variants are possible; test before rollout.",
        impact: "Duplicate URL signals may be split.",
        verification: "Check the canonical in both source and deployed HTML."
      });
    }
    if (!page.meta?.ogTitle && !page.meta?.ogDescription) {
      add(findings, {
        ruleId: "missing-open-graph",
        title: "Open Graph metadata is absent",
        description: "No og:title or og:description was found. Open Graph affects link previews, not necessarily search ranking.",
        severity: "informational",
        confidence: "high",
        evidence: "og:title and og:description absent",
        url,
        detection: "DOM metadata",
        reference: "https://ogp.me/",
        remediation: "Add Open Graph title, description and image if the page is shared socially.",
        impact: "Shared links may use a generic preview.",
        verification: "Preview the page in a social sharing debugger after deployment."
      });
    }
    if (page.structuredData?.some((item) => item?.parseError)) {
      add(findings, {
        ruleId: "invalid-structured-data",
        title: "A JSON-LD block could not be parsed",
        description: "At least one application/ld+json script contains invalid JSON.",
        severity: "medium",
        confidence: "high",
        evidence: "JSON.parse failed for an application/ld+json block",
        url,
        detection: "DOM JSON-LD parsing",
        reference: "https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data",
        remediation: "Validate the JSON and the schema vocabulary, then test with a structured-data validator.",
        impact: "Search engines cannot read the intended structured data.",
        verification: "Re-run a JSON parser and the search engine's structured-data test."
      });
    }
  }

  const internalLinks = [];
  const seen = new Set();
  for (const link of page?.links || []) {
    try {
      const parsed = new URL(link.href, url);
      if (!/^https?:$/.test(parsed.protocol)) continue;
      if (parsed.origin !== new URL(url).origin || seen.has(parsed.href)) continue;
      seen.add(parsed.href);
      internalLinks.push({ href: parsed.href, text: link.text, anchor: parsed.hash });
    } catch {
      // Ignore malformed links here; the browser may still expose them.
    }
  }
  const toCheck = internalLinks.slice(0, maxLinks);
  if (internalLinks.length > maxLinks) {
    skipped.push({ check: "internal-link-check", reason: `limited to the first ${maxLinks} of ${internalLinks.length} internal links` });
  }
  const broken = [];
  for (const link of toCheck) {
    try {
      const result = await requestSafe(link.href, { policy, timeoutMs, maxBytes: Math.min(maxBytes, 512 * 1024) });
      if (result.status >= 400) broken.push({ ...link, status: result.status });
    } catch (error) {
      broken.push({ ...link, error: error.message });
    }
  }
  checks.push({ id: "seo.internal-links", status: "observed", value: toCheck.length, unit: "checked" });
  for (const link of broken) {
    add(findings, {
      ruleId: "broken-internal-link",
      title: "An internal link returned an error",
      description: `The linked URL could not be loaded successfully (${link.status || link.error}).`,
      severity: "medium",
      confidence: "high",
      evidence: `${link.href}\n${link.text || "(no link text)"}`,
      url: link.href,
      element: link.anchor ? `a[href$="${link.anchor}"]` : "a[href]",
      detection: "Controlled HTTP request from the page's origin",
      reference: "https://developer.chrome.com/docs/lighthouse/seo/",
      remediation: "Fix or remove the broken link, or redirect it to the intended page.",
      impact: "Visitors and crawlers reach an error instead of the intended content.",
      verification: "Request the link again and confirm a 2xx/3xx response and correct destination."
    });
  }
  return {
    findings,
    checks,
    skipped,
    linksChecked: toCheck.length,
    linksDiscovered: internalLinks.length,
    caveat: "Markup and HTTP observations do not prove that a URL is indexed or that it will rank."
  };
}
