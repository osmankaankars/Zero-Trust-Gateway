# Architecture and trust boundaries

## Request path

```text
direct loopback client
        |
        v
bounded rate limiter -> JWT verifier -> IP/role policy -> header filter
                                                         |
                                                         v
                                              loopback upstream service
```

The gateway treats the direct TCP peer, bearer token, headers, path, query, and
body as untrusted. It does not trust `Forwarded` or `X-Forwarded-For`. The
upstream URL and verification JWK Set come only from startup configuration and
are validated before the listener starts.

## Identity contract

- The JOSE header must contain `typ=JWT`, an allowed algorithm, and a known
  `kid`.
- A key's declared type and algorithm must match. `none` and algorithm fallback
  are not supported.
- `exp`, `iat`, `nbf`, `iss`, `aud`, `sub`, and `role` are required.
- `exp`, `iat`, and `nbf` must be finite JSON numbers; token lifetime is bounded.
- Issuer and audience are matched to exact configured values.
- Local JWK Sets are bounded to 32 keys and 64 KiB. Symmetric verification keys
  must contain at least 256 bits. RSA keys must be at least 2048 bits and ES256
  keys must use P-256. Asymmetric verification JWKs must not contain private key
  parameters.

Multiple known `kid` values provide a rotation window. Remove an old key only
after every token signed with it has expired. JWK Sets are read only at startup,
so each add/remove step requires a controlled gateway restart.

## Availability controls

The in-memory token bucket is bounded by a configured entry count and idle TTL.
Request and response bodies are bounded, upstream requests have a total timeout,
and upstream redirects are returned to the caller without being followed.
The provided server runner disables automatic request decompression and rejects
encoded request bodies, preventing decompression ambiguity and compressed-body
limit bypasses.

The proxy is intentionally stateless across both sides of the boundary. It
discards inbound `Cookie` and outbound `Set-Cookie` headers, and its upstream
client uses a non-persistent cookie jar. This prevents a browser-held upstream
session established under one JWT subject from being replayed with another
subject's gateway-injected identity. Applications that require upstream session
cookies need a separate, subject-bound design and threat model.

Incoming and upstream response header names containing an underscore are also
discarded. This prevents common CGI/WSGI normalization from treating an
attacker-controlled underscore alias as one of the gateway's trusted
hyphenated identity headers.

The direct-peer rate limiter is deliberately coarse. All callers that share one
loopback address also share one availability bucket; this educational lab does
not claim per-user isolation. Repeated rejection events should be collected
with bounded retention in any adapted deployment.

## Upstream isolation requirement

Loopback binding limits network exposure but does not stop another process on
the same host from connecting directly to the upstream port. This lab therefore
does not make the upstream service private. A real deployment must independently
restrict upstream reachability with an operating-system, container, service-mesh,
or equivalent process/network boundary so only the gateway can connect.
Upstream `Location` headers are returned without rewriting; an absolute upstream
URL can also reveal a direct route and must be governed by that same boundary.

## Audit contract

Audit records use a fixed schema. They contain a generated request ID, direct
peer IP, method, matched route template, decision, reason code, response status,
and—after successful authentication—subject and role. The API does not accept
raw paths, headers, tokens, request bodies, key material, or query strings.
The command-line runtime disables aiohttp's raw request access log so paths,
queries, referrers, and user agents are not emitted outside this schema.

## Explicit non-goals

This lab is not a production zero-trust platform. It has no durable/distributed
rate limiting, remote discovery, certificate pinning, mTLS, device posture,
identity lifecycle, refresh tokens, revocation service, WebSocket proxying,
streaming backpressure, multi-tenant policy engine, or compliance claim. The
loopback restriction is deliberate; adapting it to a network deployment needs
a separate threat model and trusted-proxy design.
