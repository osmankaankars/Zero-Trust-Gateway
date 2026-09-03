from __future__ import annotations

import json
from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from zero_trust_gateway.audit import AuditEvent
from zero_trust_gateway.config import GatewayConfig

KEY_A = b"A" * 32
KEY_B = b"B" * 32
ISSUER = "https://issuer.example.test"
AUDIENCE = "zero-trust-gateway"


def _encoded(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def jwks(*keys: tuple[str, bytes]) -> str:
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "oct",
                    "kid": kid,
                    "alg": "HS256",
                    "use": "sig",
                    "key_ops": ["sign", "verify"],
                    "k": _encoded(key),
                }
                for kid, key in keys
            ]
        }
    )


def token(
    *,
    key: bytes = KEY_A,
    kid: str = "key-a",
    issuer: str = ISSUER,
    audience: str | list[str] = AUDIENCE,
    subject: str = "lab-admin",
    role: str = "admin",
    issued_at: datetime | None = None,
    expires_in: int = 300,
    headers: dict[str, Any] | None = None,
) -> str:
    now = issued_at or datetime.now(UTC)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    token_headers = {"kid": kid, "typ": "JWT"}
    if headers:
        token_headers.update(headers)
    return jwt.encode(claims, key, algorithm="HS256", headers=token_headers)


def config(**overrides: Any) -> GatewayConfig:
    base = GatewayConfig(jwks_text=jwks(("key-a", KEY_A)))
    return replace(base, **overrides)


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)
