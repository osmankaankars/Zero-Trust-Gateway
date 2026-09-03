# Zero Trust Gateway

[![CI](https://github.com/osmankaankars/Zero-Trust-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/osmankaankars/Zero-Trust-Gateway/actions/workflows/ci.yml)
[![CodeQL](https://github.com/osmankaankars/Zero-Trust-Gateway/actions/workflows/codeql.yml/badge.svg)](https://github.com/osmankaankars/Zero-Trust-Gateway/actions/workflows/codeql.yml)
[![Python 3.11–3.14](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A loopback-only identity-aware reverse-proxy lab for deterministic JWT,
network, role, rate-limit, trusted-header, and upstream failure controls.

Version **0.2.0** replaces the original shared-secret PoC with explicit local
JWK Set configuration, `kid`-based rotation, strict issuer/audience validation,
bounded request handling, and allow-listed structured audit events.

> [!IMPORTANT]
> This is an independent educational project, not a production zero-trust
> platform and not evidence of compliance with NIST SP 800-207, NIS2, DORA, or
> another framework. Run it only with services and data you own or are
> authorized to test.

## Security properties demonstrated

- exact `iss` and `aud` matching with required `exp`, `iat`, `nbf`, `sub`, and
  `role` claims;
- explicit `HS256`/`RS256`/`ES256` allowlist and exact key-type/algorithm match;
- local-only, bounded JWK Set parsing and known-`kid` selection for rotation;
- direct-peer IP and role policy that ignores spoofable forwarded-IP headers;
- bounded in-memory token-bucket rate limiting with `Retry-After`;
- replacement of caller-supplied identity and request-ID headers;
- removal of inbound `Cookie` and outbound `Set-Cookie` state so JWT-derived
  identity cannot conflict with an upstream browser session;
- upstream timeout, response-size bound, and redirect suppression;
- JSON audit events whose schema cannot accept tokens, key material, request
  bodies, headers, or query strings.

See [Architecture and trust boundaries](docs/ARCHITECTURE.md) for the complete
contract and explicit non-goals.

## Quick start

Requires Python 3.11 or later. Create an isolated environment and install the
project:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Generate a fresh throwaway key set in a git-ignored local file. The simulator
creates an owner-only file (`0600` on compatible POSIX filesystems), verifies
that group/world access is absent, and refuses an existing path or symbolic
link; this avoids overwriting a permissive file or following a redirected path.
Remove the file when the exercise is complete:

```bash
python idp_simulator.py --generate-keyset-file jwks.local.json
```

In terminal A, start a local upstream service on port 8080:

```bash
source .venv/bin/activate
python -m http.server 8080 --bind 127.0.0.1 --directory docs
```

In terminal B, start the gateway on port 9000:

```bash
source .venv/bin/activate
export ZERO_TRUST_JWKS_FILE="$PWD/jwks.local.json"
python gateway.py
```

In terminal C, use the same local key file to mint a short-lived token and make
an authorized request:

```bash
source .venv/bin/activate
export ZERO_TRUST_JWKS_FILE="$PWD/jwks.local.json"
TOKEN="$(python idp_simulator.py --user lab-admin --role admin)"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | \
  curl --fail-with-body --config - \
  http://127.0.0.1:9000/
unset TOKEN
```

Passing the header through curl's standard-input configuration keeps the token
out of curl's process arguments. Do not run this example with shell tracing
enabled. The simulator prints only the token. It is not an identity provider
and anyone with the configured symmetric key can mint tokens; use it only
inside the isolated lab.

> [!NOTE]
> Loopback does not prevent other local processes from bypassing the gateway and
> reaching port 8080 directly. A real adaptation must independently isolate the
> upstream service; see the documented trust boundary.

## Rotation exercise

A local JWK Set may contain multiple unique `kid` values. A safe lab rotation
sequence is:

1. Add the new verification key while keeping the previous key.
2. Restart the gateway so it loads the updated JWK Set.
3. Set `ZERO_TRUST_ACTIVE_KID` to the new key for the simulator.
4. Verify new and unexpired old tokens during the bounded overlap window.
5. Remove the retired key after its last token has expired, then restart the
   gateway again.

Unknown or retired `kid` values fail closed. Remote JWKS discovery is
intentionally out of scope, so the request path never fetches key material.
Key configuration is a startup snapshot; there is no hot reload.
Keep the overlap no longer than `ZERO_TRUST_MAX_TOKEN_LIFETIME_SECONDS` plus the
configured leeway.

## Configuration

Startup requires exactly one of `ZERO_TRUST_JWKS_JSON` or
`ZERO_TRUST_JWKS_FILE`. The gateway otherwise refuses to start. Listener and
upstream hosts must be loopback addresses.

See the [configuration reference](docs/CONFIGURATION.md) for every setting,
default, and accepted bound.

## Development and verification

```bash
python -m pip install -e '.[dev]'
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -W error::DeprecationWarning -m unittest discover -s tests -v
python -m build
```

CI runs lint, formatting, strict type analysis, and the full suite on Ubuntu and
macOS with Python 3.11–3.14. CodeQL and weekly dependency update checks cover
the public repository.

## Failure behavior

Authentication failures return a generic `401`, authorization failures return
`403`, oversized request bodies return `413`, encoded request bodies return
`415`, limits return `429`, and sanitized upstream failures return `502`.
Detailed reason codes are written only to the structured local audit stream.
Responses use `Cache-Control: no-store` and carry a generated `X-Request-ID`.

## Project documents

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [v0.2.0 release notes](release-notes/v0.2.0.md)
- [MIT license](LICENSE)

Maintained by [Osman Kaan Kars](https://github.com/osmankaankars).
