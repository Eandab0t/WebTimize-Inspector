import fs from "node:fs/promises";
import path from "node:path";
import { runScan } from "./core/scanner.js";
import { crawlSite } from "./crawl/crawl.js";
import { renderCli, renderHtml, renderComparisonHtml, compareReports } from "./report/report.js";
import { createStaticServer } from "./core/local-server.js";
import { verifyManifest } from "./report/compressor.js";

const HELP = `WebTimize Inspector — local-first website auditing

Usage:
  inspector scan <url> [options]
  inspector scan --local-dir <path> [options]
  inspector crawl <url> [options]
  inspector crawl --local-dir <path> [options]
  inspector compare <before.json> <after.json> [--html <path>]
  inspector verify <manifest.json> <base-url> [--json <path>] [--allow-private]
  inspector dashboard [--port 4173]

Scan options:
  --categories <list>       performance,accessibility,seo,security,reliability,privacy
  --viewport <WxH>          default 1440x900
  --runs <1-5>              synthetic runs, default 1
  --timeout <ms>            request/browser timeout, default 30000
  --max-requests <n>        browser request limit, default 200
  --max-bytes <n>           response body limit, default 5 MiB
  --max-links <n>           internal link checks, default 20
  --json <path>             write JSON report
  --html <path>             write standalone HTML report
  --screenshot <path>       capture one full-page screenshot
  --allow-private           explicitly allow loopback/private targets
  --local-dir <path>        serve a local directory on loopback and scan it
  --quiet                   print only errors

Crawl options:
  --max-pages <n>           default 25 (maximum 100)
  --max-depth <n>           default 2 (maximum 10)
  --max-concurrency <n>     default 2 (maximum 4)
  --page-pacing <ms>        delay between page starts, default 250
  --max-duration <ms>       total crawl time, default 120000
  --total-requests <n>      total browser request budget, default 2000
  --total-bytes <n>         total transfer budget, default 52428800

Exit codes: 0 complete/partial scan, 2 invalid input, 3 failed scan.
Reports are local. No account, API key or upload is required.
`;

function parse(argv) {
  const positional = [];
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const [rawName, inline] = token.slice(2).split("=", 2);
    const name = rawName.replaceAll("-", "_");
    if (inline !== undefined) {
      flags[name] = inline;
    } else if (["allow_private", "quiet", "help"].includes(name)) {
      flags[name] = true;
    } else {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw new Error(`--${rawName} requires a value`);
      flags[name] = value;
      index += 1;
    }
  }
  return { positional, flags };
}

async function write(pathname, content) {
  await fs.mkdir(path.dirname(path.resolve(pathname)), { recursive: true });
  await fs.writeFile(pathname, content);
}

async function scanCommand(argv) {
  const { positional, flags } = parse(argv);
  const localDir = flags.local_dir;
  const target = positional[0];
  if (!target && !localDir) throw new Error("scan requires a URL or --local-dir <path>");
  if (target && localDir) throw new Error("use either a URL or --local-dir, not both");
  let fixture = null;
  try {
    let url = target;
    if (localDir) {
      fixture = await createStaticServer(path.resolve(localDir));
      url = fixture.url;
    }
    const report = await runScan({
      url,
      categories: flags.categories,
      viewport: flags.viewport,
      runs: flags.runs,
      timeoutMs: flags.timeout,
      maxRequests: flags.max_requests,
      maxBytes: flags.max_bytes,
      maxLinks: flags.max_links,
      allowPrivate: Boolean(flags.allow_private || localDir),
      screenshotPath: flags.screenshot,
      onProgress: flags.quiet ? undefined : (event) => {
        if (event.message) process.stderr.write(`[${event.phase}] ${event.message}\n`);
      }
    });
    if (flags.json) await write(flags.json, `${JSON.stringify(report, null, 2)}\n`);
    if (flags.html) await write(flags.html, renderHtml(report));
    if (!flags.quiet) {
      console.log(renderCli(report));
      if (flags.json) console.log(`\nJSON: ${path.resolve(flags.json)}`);
      if (flags.html) console.log(`HTML: ${path.resolve(flags.html)}`);
    }
    return report.status === "failed" ? 3 : 0;
  } finally {
    if (fixture) await fixture.close();
  }
}

async function compareCommand(argv) {
  const { positional, flags } = parse(argv);
  if (positional.length !== 2) throw new Error("compare requires before.json and after.json");
  const [before, after] = await Promise.all(positional.map(async (file) => JSON.parse(await fs.readFile(file, "utf8"))));
  const comparison = compareReports(before, after);
  if (flags.json) await write(flags.json, `${JSON.stringify(comparison, null, 2)}\n`);
  if (flags.html) await write(flags.html, renderComparisonHtml(comparison));
  console.log(`New: ${comparison.added.length}  Absent: ${comparison.resolved.length}  Persistent: ${comparison.persistent.length}`);
  for (const finding of comparison.added) console.log(`  + [${finding.severity}] ${finding.title} (${finding.ruleId})`);
  for (const finding of comparison.resolved) console.log(`  - [${finding.severity}] ${finding.title} (${finding.ruleId})`);
  console.log(`\n${comparison.caveat}`);
  return 0;
}

async function crawlCommand(argv) {
  const { positional, flags } = parse(argv);
  const localDir = flags.local_dir;
  const target = positional[0];
  if (!target && !localDir) throw new Error("crawl requires a URL or --local-dir <path>");
  if (target && localDir) throw new Error("use either a URL or --local-dir, not both");
  let fixture = null;
  try {
    let url = target;
    if (localDir) {
      fixture = await createStaticServer(path.resolve(localDir));
      url = fixture.url;
    }
    const report = await crawlSite({
      url,
      categories: flags.categories,
      viewport: flags.viewport,
      runs: flags.runs,
      timeoutMs: flags.timeout,
      maxRequests: flags.max_requests,
      maxBytes: flags.max_bytes,
      maxLinks: flags.max_links,
      maxPages: flags.max_pages,
      maxDepth: flags.max_depth,
      maxConcurrency: flags.max_concurrency,
      pagePacingMs: flags.page_pacing,
      maxDurationMs: flags.max_duration,
      maxTotalRequests: flags.total_requests,
      maxTotalBytes: flags.total_bytes,
      allowPrivate: Boolean(flags.allow_private || localDir),
      onProgress: flags.quiet ? undefined : (event) => {
        if (event.message) process.stderr.write(`[${event.phase}] ${event.message}\n`);
      }
    });
    if (flags.json) await write(flags.json, `${JSON.stringify(report, null, 2)}\n`);
    if (flags.html) await write(flags.html, renderHtml(report));
    if (!flags.quiet) {
      console.log(renderCli(report));
      if (flags.json) console.log(`\nJSON: ${path.resolve(flags.json)}`);
      if (flags.html) console.log(`HTML: ${path.resolve(flags.html)}`);
    }
    return report.status === "failed" ? 3 : 0;
  } finally {
    if (fixture) await fixture.close();
  }
}

async function verifyCommand(argv) {
  const { positional, flags } = parse(argv);
  if (positional.length !== 2) throw new Error("verify requires a manifest path and a base URL");
  const result = await verifyManifest(positional[0], positional[1], {
    allowPrivate: Boolean(flags.allow_private),
    timeoutMs: Number(flags.timeout) || 15_000
  });
  if (flags.json) await write(flags.json, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`Verified ${result.summary.total - result.summary.failures}/${result.summary.total} assets; ${result.summary.failures} failure(s).`);
  for (const asset of result.assets) {
    if (asset.error || asset.status >= 400 || asset.hashMatch === false || asset.typeMatch === false) {
      console.log(`  FAIL ${asset.final}: ${asset.error || `status ${asset.status}, hashMatch=${asset.hashMatch}, typeMatch=${asset.typeMatch}`}`);
    }
  }
  return result.summary.failures ? 3 : 0;
}

async function main(argv = process.argv.slice(2)) {
  const command = argv[0];
  if (!command || command === "--help" || command === "help") {
    console.log(HELP);
    return 0;
  }
  try {
    if (command === "scan") return await scanCommand(argv.slice(1));
    if (command === "crawl") return await crawlCommand(argv.slice(1));
    if (command === "compare") return await compareCommand(argv.slice(1));
    if (command === "verify") return await verifyCommand(argv.slice(1));
    if (command === "dashboard") {
      const { startDashboard } = await import("./ui/dashboard.js");
      const { flags } = parse(argv.slice(1));
      const dashboard = await startDashboard({ port: Number(flags.port) || 4173 });
      await new Promise((resolve) => dashboard.server.once("close", resolve));
      return 0;
    }
    throw new Error(`unknown command: ${command}`);
  } catch (error) {
    console.error(`Inspector error: ${error.message}`);
    if (process.env.INSPECTOR_DEBUG) console.error(error.stack);
    return 2;
  }
}

export { main, parse, HELP };
