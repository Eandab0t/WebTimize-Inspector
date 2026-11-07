import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { after, before, test } from "node:test";
import { createStaticServer } from "../src/core/local-server.js";

const exec = promisify(execFile);
const root = path.resolve(".");
const cli = path.join(root, "bin", "inspector.js");
let temp;
let server;
before(async () => {
  temp = await fs.mkdtemp(path.join(os.tmpdir(), "webtim-inspector-cli-"));
  server = await createStaticServer(path.join(root, "fixtures", "local-site"));
});
after(async () => {
  if (server) await server.close();
  if (temp) await fs.rm(temp, { recursive: true, force: true });
});

async function run(args) {
  return exec(process.execPath, [cli, ...args], { cwd: root, timeout: 30_000 });
}

test("help is useful without starting a scan", async () => {
  const result = await run(["--help"]);
  assert.match(result.stdout, /inspector scan/);
  assert.match(result.stdout, /Exit codes/);
});

test("CLI scans a local project and writes JSON and HTML without starting a browser for security-only scans", async () => {
  const json = path.join(temp, "report.json");
  const html = path.join(temp, "report.html");
  const result = await run([
    "scan", "--local-dir", path.join(root, "fixtures", "local-site"),
    "--categories", "security", "--json", json, "--html", html, "--quiet"
  ]);
  assert.equal(result.stdout, "");
  const report = JSON.parse(await fs.readFile(json, "utf8"));
  assert.equal(report.status, "complete");
  assert.equal(report.categories.performance.status, "not-selected");
  assert.ok(report.findings.some((finding) => finding.ruleId === "security.no-https"));
  assert.match(await fs.readFile(html, "utf8"), /WebTimize Inspector/);
});

test("CLI compare reports new and absent findings", async () => {
  const before = path.join(temp, "before.json");
  const after = path.join(temp, "after.json");
  await fs.writeFile(before, JSON.stringify({ scanId: "a", target: {}, findings: [{ id: "one", ruleId: "a.one", title: "One", severity: "low", category: "x" }], categories: {} }));
  await fs.writeFile(after, JSON.stringify({ scanId: "b", target: {}, findings: [], categories: {} }));
  const result = await run(["compare", before, after]);
  assert.match(result.stdout, /New: 0/);
  assert.match(result.stdout, /Absent: 1/);
});

test("CLI crawl writes a bounded site report", async () => {
  const json = path.join(temp, "crawl.json");
  const html = path.join(temp, "crawl.html");
  const result = await run([
    "crawl", "--local-dir", path.join(root, "fixtures", "local-site"),
    "--categories", "security", "--max-pages", "2", "--max-depth", "1",
    "--json", json, "--html", html, "--quiet"
  ]);
  assert.equal(result.stdout, "");
  const report = JSON.parse(await fs.readFile(json, "utf8"));
  assert.equal(report.target.scope, "site");
  assert.ok(report.crawl.pages.length >= 1);
  assert.match(await fs.readFile(html, "utf8"), /Site crawl/);
});

test("CLI verify checks a real served manifest", async () => {
  const fsExtra = await import("node:fs");
  const crypto = await import("node:crypto");
  const css = fsExtra.readFileSync(path.join(root, "fixtures", "local-site", "styles.css"));
  const manifest = path.join(temp, "manifest.json");
  await fs.writeFile(manifest, JSON.stringify({
    schema_version: 1,
    assets: [{
      original: "styles.css",
      final: "styles.css",
      sha256: crypto.createHash("sha256").update(css).digest("hex"),
      type: "text/css"
    }]
  }));
  const result = await run(["verify", manifest, server.url, "--allow-private"]);
  assert.match(result.stdout, /1\/1 assets/);
  assert.match(result.stdout, /0 failure/);
});

test("invalid input exits 2 rather than inventing a report", async () => {
  await assert.rejects(
    () => run(["scan", "http://127.0.0.1:1/", "--quiet"]),
    (error) => error.code === 2
  );
});
