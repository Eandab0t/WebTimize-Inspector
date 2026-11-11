# Security Policy

## Supported versions

Only the latest tagged release of WebTimize Inspector receives security fixes.
The tool runs locally and never transmits scanned data anywhere by itself.

## Reporting a vulnerability

Use **GitHub Security Advisories** for this repository
(Security tab → Advisories → Report a vulnerability).
Do not open a public issue for a suspected vulnerability.

Please include:

- the Inspector version (`inspector --version`);
- the command and flags used;
- whether the target was a local fixture or a remote URL;
- steps to reproduce, without credentials, tokens, or private session data.

## Scope notes

- The dashboard binds to loopback only and requires its per-run token;
  do not expose it beyond your machine.
- `inspector verify --allow-private` is an explicit opt-in for scanning
  non-public targets; use it only where you are authorized to scan.
