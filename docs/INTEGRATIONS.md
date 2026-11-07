# Integration contracts

Inspector is independent. These are file/command contracts, not a shared runtime or a monorepo.

## 1. Compressor → Inspector — implemented

### Input contract

Compressor's `--manifest` JSON, schema version 1, with `assets` entries:

```json
{
  "schema_version": 1,
  "tool": { "name": "webtim", "version": "0.3.0" },
  "hash_algorithm": "sha256",
  "hash_length": 8,
  "dry_run": false,
  "assets": [
    {
      "original": "css/app.css",
      "final": "css/app.5bd292c2.css",
      "sha256": "full-sha256-hex",
      "type": "text/css",
      "hashed": true,
      "reason": null
    }
  ]
}
```

### Command

```bash
node bin/inspector.js verify dist-assets.json https://example.com/ --json verified.json
```

For a local deployment under test:

```bash
node bin/inspector.js verify dist-assets.json http://127.0.0.1:8080/ --allow-private
```

### Checks

- manifest schema/version and asset array;
- final URL resolution against the base URL;
- HTTP status;
- served SHA-256 versus the manifest hash;
- expected MIME type versus served Content-Type;
- Content-Encoding and Cache-Control as observations;
- per-asset failure output and a non-zero exit on failure.

### Non-goals and limits

A successful build does not prove a successful deployment. Verification checks the bytes at the
supplied base URL; it cannot prove that a particular CDN edge, DNS split or future deployment uses
the same files. The base URL must be under Inspector's URL policy.

## 2. Live → Inspector — specified, not shipped

The intended optional workflow is an explicit test mode, not a silent extension install:

1. User supplies a supported Live profile and a local or authorized URL.
2. Inspector validates the profile through a copied/read-only contract or Live's exported profile
   file; it never edits the user's real browser profile.
3. Inspector launches an isolated Chrome context with a temporary extension/profile directory,
   loads the page, captures a baseline, enables the profile, captures the modified state and then
   disables the profile and captures the restored state.
4. It compares screenshots/DOM state, console errors, failed requests, selected interaction checks
   and restoration.
5. It labels every comparison as a supported-profile test, not a general-site guarantee.

Security requirements for that future work:

- isolated user-data directory and no signed-in real profile;
- explicit supported-host allowlist derived from the profile and manifest;
- no network access to non-public targets beyond the same policy;
- temporary directory cleanup with a guaranteed `finally` path;
- no report of cookies or browser storage values;
- no silent extension installation or browser permission changes.

This milestone does not ship the Live automation. Inspector can already scan the same URL and report
baseline reliability/accessibility/security issues, but it does not claim to have tested Live.

## 3. Inspector → Compressor — recommendations only

Inspector findings can identify candidate issues (for example large images, uncompressed text,
cache gaps or render-blocking resources). It does **not** modify a site or generate a Compressor
command automatically in 0.1.0. A future explicit workflow may produce a proposed command from
verified findings, but the user must review and run it.

## Version compatibility

| Contract | Version | Behavior on mismatch |
| --- | ---: | --- |
| Inspector report | 1 | Single-page and site (`crawl`) reports share schema version 1; `crawl` is additive. Comparison handles both; unknown future fields are ignored |
| Compressor manifest | 1 | `verify` rejects unknown/missing schemas instead of guessing |
| Finding rule ids | tool-defined | Report comparison fingerprints the rule + category + element + title; origin is excluded so a local port or host move does not make every finding look new |
| Live profile | existing Live schema, unmodified | Future integration must validate it through a documented adapter |

There are no circular dependencies: Inspector imports neither Compressor's Python modules nor Live's
extension code.

Site crawl output remains a local report. It is not a deployment gate, a sitemap submission, a
search-index query or permission to crawl a third-party site. A consumer should read
`target.scope`, page states and coverage before treating a site report as complete coverage.
