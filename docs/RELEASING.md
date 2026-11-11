# Releasing WebTimize Inspector

No release has been published yet. When the owner approves a release:

1. Confirm `npm test` passes (currently 41 tests) and
   `npm pack --dry-run` shows only intended files.
2. Confirm `package.json` and `src/core/meta.js` versions agree
   (covered by `test/version.test.js`).
3. Create an annotated tag matching the package version, e.g. `v0.1.0`.
4. Publish a GitHub Release from that tag with notes from `CHANGELOG.md`.
5. Do **not** publish to npm: `package.json` sets `"private": true`
   and npm distribution requires separate owner approval.

Never force-push, rewrite published tags, or delete the
`codex/pre-release-review` recovery branch without owner approval.
