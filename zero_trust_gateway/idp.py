"""A deliberately local token generator for exercising the gateway."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import uuid
from base64 import urlsafe_b64encode
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

from .config import load_jwks_text
from .keys import JWKKeyRing, KeyConfigurationError

DEFAULT_ISSUER = "https://issuer.example.test"
DEFAULT_AUDIENCE = "zero-trust-gateway"


def generate_demo_jwks(*, kid: str = "local-2026-01") -> str:
    """Create a fresh 256-bit local HS256 JWK Set for a throwaway demo."""

    if not kid or len(kid) > 128:
        raise ValueError("kid must be between 1 and 128 characters")
    key = urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "oct",
                    "kid": kid,
                    "alg": "HS256",
                    "use": "sig",
                    "key_ops": ["sign", "verify"],
                    "k": key,
                }
            ]
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def write_new_demo_jwks(path: Path, *, kid: str = "local-2026-01") -> None:
    """Create one new owner-only key file without following a final symlink."""

    payload = f"{generate_demo_jwks(kid=kid)}\n".encode()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
            raise PermissionError("key-set file has group or world permissions")
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def generate_token(
    username: str,
    role: str,
    *,
    jwks_text: str,
    kid: str,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    lifetime_seconds: int = 900,
    now: datetime | None = None,
) -> str:
    """Generate a short-lived token from one explicitly selected local key."""

    if not username or len(username) > 256:
        raise ValueError("username must be between 1 and 256 characters")
    if not role or len(role) > 128:
        raise ValueError("role must be between 1 and 128 characters")
    if not 1 <= lifetime_seconds <= 3_600:
        raise ValueError("lifetime_seconds must be between 1 and 3600")
    ring = JWKKeyRing.from_json(jwks_text, allowed_algorithms=("HS256",))
    algorithm, signing_key = ring.signing_key(kid)
    issued_at = now or datetime.now(UTC)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": username,
        "role": role,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(seconds=lifetime_seconds),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        payload,
        signing_key,
        algorithm=algorithm,
        headers={"kid": kid, "typ": "JWT"},
    )


def _environment_value(environment: Mapping[str, str], name: str, default: str) -> str:
    value = environment.get(name, default)
    if not value:
        raise KeyConfigurationError(f"{name} must not be empty")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate short-lived JWTs for the isolated gateway demo"
    )
    generation = parser.add_mutually_exclusive_group()
    generation.add_argument("--generate-keyset", action="store_true")
    generation.add_argument(
        "--generate-keyset-file",
        type=Path,
        metavar="PATH",
        help=(
            "Create a new owner-only JWK Set file; refuse existing paths and symlinks."
        ),
    )
    parser.add_argument(
        "--kid", default=os.getenv("ZERO_TRUST_ACTIVE_KID", "local-2026-01")
    )
    parser.add_argument("--user", default="lab-admin")
    parser.add_argument("--role", default="admin")
    parser.add_argument("--lifetime", type=int, default=900)
    args = parser.parse_args()

    if args.generate_keyset:
        print(generate_demo_jwks(kid=args.kid))
        return
    if args.generate_keyset_file is not None:
        try:
            write_new_demo_jwks(args.generate_keyset_file, kid=args.kid)
        except OSError as exc:
            parser.error(
                f"could not create new key-set file {args.generate_keyset_file}: {exc}"
            )
        print(f"Created key set: {args.generate_keyset_file}")
        return

    environment = os.environ
    token = generate_token(
        args.user,
        args.role,
        jwks_text=load_jwks_text(environment),
        kid=args.kid,
        issuer=_environment_value(environment, "ZERO_TRUST_ISSUER", DEFAULT_ISSUER),
        audience=_environment_value(
            environment, "ZERO_TRUST_AUDIENCE", DEFAULT_AUDIENCE
        ),
        lifetime_seconds=args.lifetime,
    )
    print(token)
