# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/bdparrish/ztward/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Include:

- the affected component (service, SDK, or sample) and version or commit
- steps to reproduce, or a proof of concept
- the impact you expect (for example key disclosure, authorization bypass, denial of service)

You should get an acknowledgment within 5 business days. We will keep you updated while we
work on a fix and credit you in the advisory unless you ask us not to.

## Supported versions

Ztward is pre-1.0. Security fixes go to the latest release and the `main` branch only.

## Scope

In scope: the services under `go/`, the SDKs under `sdk/`, and the deployment configuration
under `deployment/`.

Out of scope: the `samples/` applications (they use development-only
credentials and self-signed certificates by design), and findings that require the dev
defaults (`make certs` certificates, the local Keycloak realm, the example `.env` values)
to be used in production.
