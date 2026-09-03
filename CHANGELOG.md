# Changelog

All notable changes are documented here. This project follows Semantic
Versioning for its public interfaces.

## [0.2.0] - 2026-09-03

### Added

- Strict issuer, audience, lifetime, subject, role, `typ`, algorithm, and `kid`
  validation.
- Bounded local JWK Set loading with multi-key rotation support.
- Per-direct-peer token-bucket rate limiting with `Retry-After` responses.
- Allow-listed JSON audit events with request correlation identifiers.
- Explicit upstream timeouts, response-size limits, redirect suppression, and
  sanitized failure responses.
- Bounded token lifetime and request-body handling, proxy-header stripping, and
  disabled raw request access logs.
- Fail-closed rejection of encoded request bodies with server-side automatic
  decompression disabled.
- Stateless upstream proxying that strips inbound `Cookie` and outbound
  `Set-Cookie` headers and disables the gateway client's cookie jar.
- Fail-closed normalization of non-ASCII compact JWT values into audited
  authentication denials instead of internal errors.
- Rejection of underscore-bearing header aliases before forwarding.
- Installable package metadata, MIT license, architecture and configuration
  documentation, Python 3.11–3.14 CI, CodeQL, and Dependabot configuration.

### Changed

- Authentication failures now consistently return a generic HTTP 401 JSON
  response instead of revealing token failure details to callers.
- The local token simulator now requires explicit ephemeral JWK material and
  produces complete issuer/audience/lifetime claims.
- Quick-start key creation now uses exclusive owner-only file creation,
  verifies that group/world access is absent, and refuses existing files and
  symbolic links; the bearer-token example keeps
  credentials out of process arguments.

### Removed

- The repository's embedded default shared secret.
