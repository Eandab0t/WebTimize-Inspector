import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { VERSION } from "../src/core/meta.js";

test("package and report metadata versions agree", () => {
  const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.version, VERSION);
});