# Configuration reference

The process fails closed if key material is missing, ambiguous, oversized, or
invalid. Values are read once at startup.

| Variable | Default | Constraint |
| --- | --- | --- |
| `ZERO_TRUST_JWKS_JSON` | none | Inline local JWK Set; mutually exclusive with file |
| `ZERO_TRUST_JWKS_FILE` | none | UTF-8 local JWK Set file, maximum 64 KiB |
| `ZERO_TRUST_ALLOWED_ALGORITHMS` | `HS256,RS256,ES256` | Explicit allowlist |
| `ZERO_TRUST_ISSUER` | `https://issuer.example.test` | Exact expected `iss` |
| `ZERO_TRUST_AUDIENCE` | `zero-trust-gateway` | Exact expected `aud` |
| `ZERO_TRUST_ALLOWED_IPS` | `127.0.0.1,::1` | Direct peer IPs; forwarded headers ignored |
| `ZERO_TRUST_REQUIRED_ROLE` | `admin` | Exact required role |
| `ZERO_TRUST_UPSTREAM_URL` | `http://127.0.0.1:8080` | Absolute loopback HTTP(S) URL |
| `ZERO_TRUST_HOST` | `127.0.0.1` | Loopback listener IP |
| `ZERO_TRUST_PORT` | `9000` | `1..65535` |
| `ZERO_TRUST_TOKEN_LEEWAY_SECONDS` | `5` | `0..60` |
| `ZERO_TRUST_MAX_TOKEN_LIFETIME_SECONDS` | `3600` | Maximum `exp - iat`; `1..86400` seconds |
| `ZERO_TRUST_RATE_LIMIT_CAPACITY` | `20` | `1..10000` |
| `ZERO_TRUST_RATE_LIMIT_REFILL_PER_SECOND` | `2` | `0.01..10000` |
| `ZERO_TRUST_RATE_LIMIT_MAX_ENTRIES` | `1024` | `1..100000` |
| `ZERO_TRUST_RATE_LIMIT_IDLE_TTL_SECONDS` | `300` | `1..86400` |
| `ZERO_TRUST_MAX_REQUEST_BYTES` | `1048576` | `1 KiB..16 MiB` |
| `ZERO_TRUST_MAX_RESPONSE_BYTES` | `4194304` | `1 KiB..64 MiB` |
| `ZERO_TRUST_UPSTREAM_TIMEOUT_SECONDS` | `5` | `0.1..60` |
| `ZERO_TRUST_ACTIVE_KID` | `local-2026-01` | Simulator signing key only |

Never commit a JWK Set containing symmetric key material or any private key.
`jwks.local.json`, `*.key`, and `*.pem` are ignored as a last line of defense,
not as a substitute for secret management.
