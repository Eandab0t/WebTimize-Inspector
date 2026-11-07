# Third-party notices

Inspector itself is currently **unlicensed** (no project license has been selected). The following
runtime packages are installed from npm and retain their upstream licenses:

| Package | Version | License | Use |
| --- | ---: | --- | --- |
| `playwright-core` | 1.65.0 | Apache-2.0 | Launch the locally installed Chrome and control an isolated browser context |
| `axe-core` | 4.14.0 | MPL-2.0 | Automated accessibility rule engine injected into the audited page |

- Playwright: <https://github.com/microsoft/playwright>
- axe-core: <https://github.com/dequelabs/axe-core>

The package lock records the installed versions. `axe-core` is not modified; its license and
third-party acknowledgements are shipped in its npm package. Any redistribution of a modified
axe-core file must comply with MPL-2.0's file-level source requirements.

Lighthouse, Lighthouse CI, sitespeed.io, WebPageTest and CrUX are **not** runtime dependencies in
this release. Their licenses and limitations are recorded in the internal notes under
`__development/docs/`.
