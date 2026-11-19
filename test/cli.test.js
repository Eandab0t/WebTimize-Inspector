import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile, spawn } from "node:child_process";
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

function runCapturingExit(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [cli, ...args], { cwd: root, timeout: 30_000 }, (error, stdout, stderr) => {
      resolve({ code: error ? error.signal ?? error.code ?? -1 : 0, stdout, stderr });
    });
  });
}

test("a subcommand followed by --help prints usage instead of running", async () => {
  for (const command of ["dashboard", "scan"]) {
    const result = await runCapturingExit([command, "--help"]);
    assert.equal(result.code, 0, `${command} --help exited ${result.code}`);
    assert.match(result.stdout, /WebTimize Inspector — local-first website auditing/);
    assert.doesNotMatch(result.stdout, /Loopback only/, "dashboard server must not start");
    assert.equal(result.stderr, "");
  }
});

test("CLI dashboard command starts the relocated dashboard module", async (t) => {
  const child = spawn(process.execPath, [cli, "dashboard", "--port", "0"], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"]
  });
  t.after(() => {
    child.kill();
  });
  let output = "";
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("dashboard did not report a loopback URL")), 10_000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match) {
        clearTimeout(timer);
        resolve(match[0]);
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`dashboard exited before reporting a URL: ${code}\n${output}`));
    });
  });
  const health = await fetch(`${url}/api/health`);
  assert.equal(health.status, 403);
  assert.match(health.headers.get("content-type"), /application\/json/);
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

test("CLI verify refuses manifest entries that would select another origin or escape the root", async () => {
  const fsExtra = await import("node:fs");
  const crypto = await import("node:crypto");
  const css = fsExtra.readFileSync(path.join(root, "fixtures", "local-site", "styles.css"));
  const hash = crypto.createHash("sha256").update(css).digest("hex");
  let attackHits = 0;
  const attackServer = http.createServer((request, response) => {
    attackHits += 1;
    response.writeHead(200, { "content-type": "text/css" });
    response.end("body{color:red}");
  });
  await new Promise((resolve) => attackServer.listen(0, "127.0.0.1", resolve));
  const attack = `127.0.0.1:${attackServer.address().port}`;
  // The `..` and same-origin absolute entries resolve to the base fixture origin, so record what
  // the base server is actually asked for: only the one good asset may appear.
  const baseRequests = [];
  const recordBase = (request) => baseRequests.push(request.url);
  server.server.on("request", recordBase);
  try {
    const entry = (final, original = "evil.css") => ({ original, final, sha256: hash, type: "text/css" });
    const manifest = path.join(temp, "manifest-attack.json");
    await fs.writeFile(manifest, JSON.stringify({
      schema_version: 1,
      assets: [
        { original: "styles.css", final: "styles.css", sha256: hash, type: "text/css" },
        entry(`http://${attack}/steal.css`),
        entry(`//${attack}/protocol-relative.css`),
        entry("../../outside.css"),
        entry("..\\..\\outside.css"),
        entry("%2e%2e%2foutside.css"),
        entry("%2E%2E/outside.css"),
        entry(`${server.url}styles.css`)
      ]
    }));
    const result = await runCapturingExit(["verify", manifest, server.url, "--allow-private"]);
    assert.deepEqual(baseRequests, ["/styles.css"], "only the good relative entry may reach the base origin");
    assert.equal(attackHits, 0, "a manifest-supplied origin must never be requested");
    assert.equal(result.code, 3);
    assert.match(result.stdout, /Verified 1\/8 assets; 7 failure/);
  } finally {
    server.server.off("request", recordBase);
    await new Promise((resolve) => attackServer.close(resolve));
  }
});

test("invalid input exits 2 rather than inventing a report", async () => {
  await assert.rejects(
    () => run(["scan", "http://127.0.0.1:1/", "--quiet"]),
    (error) => error.code === 2
  );
});
