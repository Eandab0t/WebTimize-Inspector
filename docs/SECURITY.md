# Inspector security model

## Scope

Inspector accepts an arbitrary website URL. That makes it a potential SSRF tool and a potential
source of unsafe report content. The implementation is defensive, but it is not a sandbox for a
hostile browser, a penetration-testing framework or a hosted multi-tenant scanner.

## URL and HTTP protections

Implemented in `src/core/url-policy.js`:

- only `http:` and `https:`;
- rejection of embedded usernames/passwords;
- strict hostname checks and canonical-address handling;
- rejection of loopback, RFC 1918, link-local, carrier-grade NAT, documentation, multicast,
  unspecified and reserved IPv4 ranges;
- rejection of IPv6 loopback, unspecified, unique-local, link-local, multicast, documentation,
  IPv4-mapped and IPv4-translated private addresses;
- rejection of cloud metadata hostnames and the common metadata addresses, even in explicit local
  mode;
- DNS validation of every resolved address before use;
- a custom `http`/`https` `lookup` callback that validates the address at connection time, reducing
  DNS-rebinding and check/use gaps;
- explicit redirect following with a redirect cap and validation of every destination;
- response-byte limits, request timeout and connection errors surfaced as failed checks;
- no cookie jar, authentication header injection or proxy configuration.

`--allow-private` exists only for intentional local-project scans. It still rejects metadata
addresses and hostnames. It must not be enabled for an untrusted public URL.

## Browser protections

The browser uses an isolated Playwright context, blocks service workers, rejects downloads, routes
every HTTP(S) request through the URL policy, counts requests, aborts prohibited destinations, and
closes websockets whose URL fails the policy. Redirects are seen as browser requests and checked.

### Loopback validating proxy

Chrome is launched with a per-scan loopback proxy and with its implicit loopback bypass disabled.
This is the connection-level boundary, not just request interception:

- for ordinary HTTP browser requests, Chrome sends an absolute URL to the proxy; the proxy resolves
  the hostname with `UrlPolicy`, applies the policy and connects to a validated address;
- for HTTPS, Chrome sends a `CONNECT` host:port; the proxy resolves and validates it before opening
  the upstream TCP tunnel;
- the browser route guard remains in place as a second check for subresources, frames, redirects and
  request-count limits;
- the proxy is destroyed with the browser and is never exposed beyond loopback.

The fixture-backed browser crawl verifies that browser scans use the proxy (`networkBoundary.mode`
is `validating-proxy` and HTTP/CONNECT counters advance). Direct proxy tests verify allowed and
blocked HTTP requests and CONNECT destinations.

Residual limitations:

- The proxy is an application boundary, not an operating-system firewall or network namespace. The
  browser engine is trusted local software; keep Chrome patched.
- HTTPS `CONNECT` destinations are validated before the tunnel opens, but the tunneled bytes are not
  inspected by Inspector. Chrome performs its own TLS certificate validation. There is no controlled
  TLS fixture in the current suite, so HTTPS browser traffic is not claimed as end-to-end tested.
- Websocket validation occurs when the socket event is emitted, after the handshake begins; the
  socket is closed on failure. The proxy does not implement a custom websocket upgrade path.
- Browser response-size enforcement uses declared content length and the HTTP-level cap. A chunked
  response without a declared length is not streamed against a byte budget by Playwright; the
  request budget and per-scan pacing still bound the crawl.
- `CONNECT` tunnels do not receive the proxy's HTTP response-byte cap.
- Service-worker blocking changes site behavior and should be listed when interpreting findings.

## Dashboard protections

- Binds only to `127.0.0.1`; no public host option is exposed.
- Per-process random token embedded in the served HTML and required on API requests.
- Mutations require a same-origin `Origin` header; read-only API calls require the token.
- Content-Security-Policy restricts scripts/styles/connections to self; no inline script is used.
- API request bodies are capped at 64 KiB; one scan can run at a time.
- Crawl cancellation aborts the active browser/scan, stops the worker queue, and closes the
  temporary local fixture in a `finally` path.
- Report and screenshot routes use strict IDs/path checks; arbitrary filesystem paths are not
  served.
- The explicit local-project path is user-selected. A local user can already read their own files;
  the server nevertheless resolves paths under that root and rejects traversal.

## Report safety

- Cookie values are never recorded; only names and attributes.
- `Set-Cookie`, `Authorization` and other raw headers are not copied into the report.
- Browser DOM text is truncated in evidence; report HTML escapes untrusted values and embeds the
  report JSON with `<` escaped to prevent script termination.
- Screenshots are optional and can contain page content. Store them locally and treat them as scan
  evidence, not public artifacts.
- Reports can still include target URLs, third-party origins, page text and element snippets. Review
  them before sharing.

## Non-goals

Inspector does **not** perform exploitation, credential attacks, directory brute forcing, form
submission, account creation, payment actions, ad interaction or penetration testing. A missing
header is not labelled a vulnerability; it is labelled a configuration observation with context.

## Known risk register

| Risk | Status | Mitigation |
| --- | --- | --- |
| SSRF through target URL | Reduced, tested | Deny lists, DNS resolution, connection lookup, explicit redirect validation |
| Browser DNS rebinding | Reduced, not eliminated as an OS guarantee | Chrome uses a loopback validating proxy that resolves and pins the validated address; the proxy is still application software, not a firewall/namespace |
| Malicious page content in report | Reduced | DOM text is output as text and HTML-escaped; no page scripts execute in the dashboard |
| Dashboard CSRF | Reduced | Token plus same-origin mutation checks |
| Local directory traversal | Reduced | Explicit user selection, static-server containment |
| Cookie/secret leakage | Reduced | Values and raw headers omitted |
| Browser process escape | Not claimed | Use a maintained Chrome and a dedicated disposable context |
| External data transmission | Not implemented | No CrUX, Observatory or WebPageTest calls in 0.1.0 |

This is a source and local-fixture security review, not a penetration test of a deployed service.
