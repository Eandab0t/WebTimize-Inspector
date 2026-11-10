# Third-party notices

WebTimize Inspector is licensed under the MIT License. The following runtime packages are
installed from npm and retain their upstream licenses:

| Package | Version | License | Use |
| --- | ---: | --- | --- |
| `playwright-core` | 1.65.0 | Apache-2.0 | Launch the locally installed Chrome and control an isolated browser context |
| `axe-core` | 4.14.0 | MPL-2.0 | Automated accessibility rule engine injected into the audited page |

- Playwright: <https://github.com/microsoft/playwright>
- axe-core: <https://github.com/dequelabs/axe-core>

The package lock records the installed versions. `axe-core` is not modified; its npm package ships
`LICENSE` and `LICENSE-3RD-PARTY.txt`. `playwright-core` ships `LICENSE` and `NOTICE`. Any
distribution that bundles executable packages containing either dependency must also include those
upstream files. Any redistribution of a modified axe-core file must comply with MPL-2.0's
file-level source requirements.

Lighthouse, Lighthouse CI, sitespeed.io, WebPageTest and CrUX are **not** runtime dependencies in
this release. Their licenses and limitations are recorded in the internal notes under
`__development/docs/`.
