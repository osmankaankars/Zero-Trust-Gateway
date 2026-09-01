# Zero Trust Gateway

> An asynchronous Python proof of concept that puts simple JWT, source-IP, and role checks in front of a local HTTP service.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Architecture](https://img.shields.io/badge/Pattern-Policy_Enforcement_Point-red)
![CI](https://github.com/osmankaankars/Zero-Trust-Gateway/actions/workflows/ci.yml/badge.svg)

## What it demonstrates

For each direct request, the gateway:

1. Reads an `HS256` bearer token and validates its signature and expiry.
2. Builds a small security context from the direct peer IP and token claims.
3. Requires a loopback source (`127.0.0.1` or `::1`) and the `admin` role.
4. Removes caller credentials and hop-by-hop headers before proxying an allowed request to `http://127.0.0.1:8080` with `aiohttp`.

`idp_simulator.py` generates short-lived tokens for local testing. It is a token generator, not an identity provider.

## Install

```bash
git clone https://github.com/osmankaankars/Zero-Trust-Gateway.git
cd Zero-Trust-Gateway
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Local workflow

Choose a shared secret and export the same value in every shell that runs the gateway or simulator:

```bash
export ZERO_TRUST_JWT_SECRET="replace-with-a-long-random-local-secret"
```

Start an upstream service on `127.0.0.1:8080`, then start the gateway. The
demonstration listener is bound to `127.0.0.1:9000` by default:

```bash
python gateway.py
```

In a second shell with the same environment variable, generate a token:

```bash
python idp_simulator.py --user lab-admin --role admin
```

Use the printed token from the same workstation:

```bash
curl -H "Authorization: Bearer <TOKEN>" http://localhost:9000/
```

The source constants in `gateway.py` define the upstream URL, gateway port, loopback allowlist, required role, and algorithm. The repository includes an explicit local-demo secret only as a convenience; set `ZERO_TRUST_JWT_SECRET` before any shared use.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers allow/deny policy decisions, missing or invalid required claims, token compatibility with the simulator, environment-based secret configuration, request/response header filtering, repeated response headers, and compressed upstream bodies. GitHub Actions runs the same checks on Python 3.11.

## Security and architecture limits

This is a learning PoC, not a production identity-aware proxy and not evidence of NIST SP 800-207, NIS2, or other regulatory compliance.

- The implementation has no real identity lifecycle, issuer/audience validation, JWKS rotation, device posture, mTLS, or phishing-resistant authentication.
- Anyone with the shared secret can use the simulator to mint an `admin` token. Keep the demo isolated and never reuse the secret.
- The peer-IP check is intentionally local-only and is not proxy-aware. It does not safely process forwarded-client-IP headers.
- The gateway does not add TLS, rate limiting, audit durability, an application-aware header policy, WebSocket support, or streaming guarantees; request and response bodies are buffered in memory.
- Upstream requests have no explicit timeout. A stalled upstream can therefore hold a gateway request until the underlying client or network fails.
- A new upstream client session is created per request; no performance benchmark or concurrency capacity is claimed.
- Running this process does not hide the upstream service. Enforce that separately with host and network controls.
- Review request/response header behavior and failure handling before adapting the code to any real system.
