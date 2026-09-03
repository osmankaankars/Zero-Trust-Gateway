"""Strict local JWK Set parsing and JWT verification."""

from __future__ import annotations

import json
import math
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from typing import Any, TypeGuard

import jwt

MAX_KEYS = 32
MAX_TOKEN_BYTES = 8_192
MAX_NUMERIC_DATE = 253_402_300_799  # 9999-12-31T23:59:59Z
ASYMMETRIC_PRIVATE_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
EXPECTED_KEY_TYPES = {"HS256": "oct", "RS256": "RSA", "ES256": "EC"}


class KeyConfigurationError(ValueError):
    """Raised when a local JWK Set is ambiguous or unsafe."""


class TokenValidationError(ValueError):
    """Raised with a non-sensitive reason code for invalid tokens."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KeyConfigurationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _decode_base64url(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise KeyConfigurationError("invalid base64url key material") from exc


def _is_numeric_date(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0 <= value <= MAX_NUMERIC_DATE
    return (
        isinstance(value, float)
        and math.isfinite(value)
        and 0 <= value <= MAX_NUMERIC_DATE
    )


@dataclass(frozen=True, slots=True)
class VerificationKey:
    kid: str
    algorithm: str
    key_type: str
    key: Any


class JWKKeyRing:
    """A bounded, local-only set of verification keys selected by ``kid``."""

    def __init__(self, keys: dict[str, VerificationKey]) -> None:
        self._keys = keys

    @classmethod
    def from_json(cls, text: str, *, allowed_algorithms: tuple[str, ...]) -> JWKKeyRing:
        try:
            document = json.loads(text, object_pairs_hook=_object_without_duplicates)
        except (json.JSONDecodeError, TypeError) as exc:
            raise KeyConfigurationError("JWK Set must be valid JSON") from exc
        if not isinstance(document, dict) or set(document) != {"keys"}:
            raise KeyConfigurationError("JWK Set must contain only a keys array")
        raw_keys = document["keys"]
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= MAX_KEYS:
            raise KeyConfigurationError("JWK Set must contain between 1 and 32 keys")

        allowed = frozenset(allowed_algorithms)
        parsed: dict[str, VerificationKey] = {}
        for raw in raw_keys:
            if not isinstance(raw, dict):
                raise KeyConfigurationError("each JWK must be an object")
            kid = raw.get("kid")
            algorithm = raw.get("alg")
            key_type = raw.get("kty")
            if not isinstance(kid, str) or not kid or len(kid) > 128:
                raise KeyConfigurationError("each JWK requires a bounded string kid")
            if kid in parsed:
                raise KeyConfigurationError(f"duplicate JWK kid: {kid}")
            if algorithm not in allowed or algorithm not in EXPECTED_KEY_TYPES:
                raise KeyConfigurationError(f"JWK {kid} uses a disallowed algorithm")
            if key_type != EXPECTED_KEY_TYPES[algorithm]:
                raise KeyConfigurationError(
                    f"JWK {kid} key type does not match its algorithm"
                )
            if raw.get("use", "sig") != "sig":
                raise KeyConfigurationError(f"JWK {kid} is not a signing key")
            key_ops = raw.get("key_ops")
            if key_ops is not None and (
                not isinstance(key_ops, list) or "verify" not in key_ops
            ):
                raise KeyConfigurationError(f"JWK {kid} does not permit verification")

            if key_type == "oct":
                encoded = raw.get("k")
                if not isinstance(encoded, str) or len(_decode_base64url(encoded)) < 32:
                    raise KeyConfigurationError(
                        f"JWK {kid} must contain at least 256 bits of key material"
                    )
            elif ASYMMETRIC_PRIVATE_FIELDS.intersection(raw):
                raise KeyConfigurationError(
                    f"JWK {kid} must not expose asymmetric private key material"
                )
            if algorithm == "ES256" and raw.get("crv") != "P-256":
                raise KeyConfigurationError(f"JWK {kid} must use the P-256 curve")

            try:
                pyjwk = jwt.PyJWK.from_dict(raw, algorithm=algorithm)
            except (jwt.PyJWKError, ValueError, TypeError) as exc:
                raise KeyConfigurationError(f"JWK {kid} is invalid") from exc
            if algorithm == "RS256" and getattr(pyjwk.key, "key_size", 0) < 2_048:
                raise KeyConfigurationError(
                    f"JWK {kid} must use an RSA key of at least 2048 bits"
                )
            parsed[kid] = VerificationKey(
                kid=kid,
                algorithm=algorithm,
                key_type=key_type,
                key=pyjwk.key,
            )
        return cls(parsed)

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def signing_key(self, kid: str) -> tuple[str, bytes]:
        """Return local HMAC material for the bundled token simulator only."""

        selected = self._keys.get(kid)
        if selected is None:
            raise KeyConfigurationError(
                "active signing kid is not present in the JWK Set"
            )
        if selected.key_type != "oct" or not isinstance(selected.key, bytes):
            raise KeyConfigurationError(
                "the local simulator can sign only with an oct/HS256 key"
            )
        return selected.algorithm, selected.key

    def decode(
        self,
        token: str,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int,
        max_lifetime_seconds: int = 3_600,
    ) -> dict[str, Any]:
        """Verify a JWT against its exact local key and expected claims."""

        try:
            token_bytes = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise TokenValidationError("malformed_token") from exc
        if len(token_bytes) > MAX_TOKEN_BYTES:
            raise TokenValidationError("token_too_large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError("malformed_token") from exc
        kid = header.get("kid")
        algorithm = header.get("alg")
        token_type = header.get("typ")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("missing_kid")
        if not isinstance(algorithm, str) or algorithm == "none":
            raise TokenValidationError("disallowed_algorithm")
        if token_type != "JWT":  # noqa: S105 - JOSE token type, not a password
            raise TokenValidationError("invalid_token_type")
        selected = self._keys.get(kid)
        if selected is None:
            raise TokenValidationError("unknown_kid")
        if algorithm != selected.algorithm:
            raise TokenValidationError("algorithm_key_mismatch")

        try:
            claims = jwt.decode(
                token,
                selected.key,
                algorithms=[selected.algorithm],
                issuer=issuer,
                audience=audience,
                leeway=leeway_seconds,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "role"],
                    "strict_aud": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("expired_token") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenValidationError("token_not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenValidationError("invalid_issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenValidationError("invalid_audience") from exc
        except (jwt.PyJWTError, TypeError, ValueError, OverflowError) as exc:
            raise TokenValidationError("invalid_token") from exc

        subject = claims.get("sub")
        role = claims.get("role")
        issued_at = claims.get("iat")
        not_before = claims.get("nbf")
        expires_at = claims.get("exp")
        if (
            not _is_numeric_date(issued_at)
            or not _is_numeric_date(not_before)
            or not _is_numeric_date(expires_at)
            or expires_at <= issued_at
            or not_before >= expires_at
            or expires_at - issued_at > max_lifetime_seconds
        ):
            raise TokenValidationError("invalid_token_lifetime")
        if not isinstance(subject, str) or not subject or len(subject) > 256:
            raise TokenValidationError("invalid_subject")
        if not isinstance(role, str) or not role or len(role) > 128:
            raise TokenValidationError("invalid_role")
        return claims
