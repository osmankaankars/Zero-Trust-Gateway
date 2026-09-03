"""Validated configuration for the local gateway demonstration."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_JWKS_BYTES = 65_536
SUPPORTED_ALGORITHMS = frozenset({"HS256", "RS256", "ES256"})


class ConfigurationError(ValueError):
    """Raised when gateway configuration is missing or unsafe."""


def _bounded_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = environment.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_float(
    environment: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = environment.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_jwks_text(environment: Mapping[str, str] | None = None) -> str:
    """Load a bounded local JWK Set from exactly one configured source."""

    env = os.environ if environment is None else environment
    inline = env.get("ZERO_TRUST_JWKS_JSON")
    file_name = env.get("ZERO_TRUST_JWKS_FILE")
    if bool(inline) == bool(file_name):
        raise ConfigurationError(
            "configure exactly one of ZERO_TRUST_JWKS_JSON or ZERO_TRUST_JWKS_FILE"
        )

    if inline is not None:
        encoded = inline.encode("utf-8")
        if len(encoded) > MAX_JWKS_BYTES:
            raise ConfigurationError("ZERO_TRUST_JWKS_JSON exceeds 65536 bytes")
        return inline

    if file_name is None:
        raise ConfigurationError("ZERO_TRUST_JWKS_FILE is required")
    path = Path(file_name).expanduser()
    try:
        if not path.is_file():
            raise ConfigurationError("ZERO_TRUST_JWKS_FILE must reference a file")
        if path.stat().st_size > MAX_JWKS_BYTES:
            raise ConfigurationError("ZERO_TRUST_JWKS_FILE exceeds 65536 bytes")
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError("unable to read ZERO_TRUST_JWKS_FILE") from exc


def _validate_local_url(value: str, name: str) -> str:
    parsed = urlsplit(value)
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError(f"{name} contains an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ConfigurationError(f"{name} must be an absolute HTTP(S) URL")
    if port is not None and not 1 <= port <= 65_535:
        raise ConfigurationError(f"{name} port must be between 1 and 65535")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError(
            f"{name} must not contain userinfo, a query, or a fragment"
        )
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.lower() != "localhost":
            raise ConfigurationError(f"{name} must target a loopback host") from None
    else:
        if not address.is_loopback:
            raise ConfigurationError(f"{name} must target a loopback address")
    return value.rstrip("/")


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Complete, fail-closed runtime configuration."""

    jwks_text: str
    issuer: str = "https://issuer.example.test"
    audience: str = "zero-trust-gateway"
    allowed_algorithms: tuple[str, ...] = ("HS256", "RS256", "ES256")
    allowed_ips: frozenset[str] = frozenset({"127.0.0.1", "::1"})
    required_role: str = "admin"
    upstream_url: str = "http://127.0.0.1:8080"
    host: str = "127.0.0.1"
    port: int = 9000
    token_leeway_seconds: int = 5
    max_token_lifetime_seconds: int = 3_600
    rate_limit_capacity: int = 20
    rate_limit_refill_per_second: float = 2.0
    rate_limit_max_entries: int = 1_024
    rate_limit_idle_ttl_seconds: int = 300
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 4_194_304
    upstream_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.issuer.strip() or len(self.issuer) > 512:
            raise ConfigurationError("issuer must be between 1 and 512 characters")
        if not self.audience.strip() or len(self.audience) > 256:
            raise ConfigurationError("audience must be between 1 and 256 characters")
        if not self.required_role.strip() or len(self.required_role) > 128:
            raise ConfigurationError(
                "required_role must be between 1 and 128 characters"
            )
        if not self.allowed_algorithms:
            raise ConfigurationError("at least one JWT algorithm must be allowed")
        unsupported = set(self.allowed_algorithms) - SUPPORTED_ALGORITHMS
        if unsupported:
            raise ConfigurationError(
                f"unsupported JWT algorithms: {', '.join(sorted(unsupported))}"
            )
        if not self.allowed_ips:
            raise ConfigurationError("at least one direct peer IP must be allowed")
        for address in self.allowed_ips:
            ipaddress.ip_address(address)
        _validate_local_url(self.upstream_url, "upstream_url")
        host_address = ipaddress.ip_address(self.host)
        if not host_address.is_loopback:
            raise ConfigurationError("host must be a loopback address")
        if not 1 <= self.port <= 65_535:
            raise ConfigurationError("port must be between 1 and 65535")
        if not 0 <= self.token_leeway_seconds <= 60:
            raise ConfigurationError("token_leeway_seconds must be between 0 and 60")
        if not 1 <= self.max_token_lifetime_seconds <= 86_400:
            raise ConfigurationError(
                "max_token_lifetime_seconds must be between 1 and 86400"
            )
        if not 1 <= self.rate_limit_capacity <= 10_000:
            raise ConfigurationError("rate_limit_capacity must be between 1 and 10000")
        if not 0.01 <= self.rate_limit_refill_per_second <= 10_000:
            raise ConfigurationError(
                "rate_limit_refill_per_second must be between 0.01 and 10000"
            )
        if not 1 <= self.rate_limit_max_entries <= 100_000:
            raise ConfigurationError(
                "rate_limit_max_entries must be between 1 and 100000"
            )
        if not 1 <= self.rate_limit_idle_ttl_seconds <= 86_400:
            raise ConfigurationError(
                "rate_limit_idle_ttl_seconds must be between 1 and 86400"
            )
        if not 1_024 <= self.max_request_bytes <= 16_777_216:
            raise ConfigurationError(
                "max_request_bytes must be between 1024 and 16777216"
            )
        if not 1_024 <= self.max_response_bytes <= 67_108_864:
            raise ConfigurationError(
                "max_response_bytes must be between 1024 and 67108864"
            )
        if not 0.1 <= self.upstream_timeout_seconds <= 60:
            raise ConfigurationError(
                "upstream_timeout_seconds must be between 0.1 and 60"
            )

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> GatewayConfig:
        """Parse and validate supported environment variables."""

        env = os.environ if environment is None else environment
        algorithms = tuple(
            item.strip().upper()
            for item in env.get(
                "ZERO_TRUST_ALLOWED_ALGORITHMS", "HS256,RS256,ES256"
            ).split(",")
            if item.strip()
        )
        try:
            raw_ips = {
                str(ipaddress.ip_address(item.strip()))
                for item in env.get("ZERO_TRUST_ALLOWED_IPS", "127.0.0.1,::1").split(
                    ","
                )
                if item.strip()
            }
        except ValueError as exc:
            raise ConfigurationError(
                "ZERO_TRUST_ALLOWED_IPS contains an invalid IP"
            ) from exc
        upstream = _validate_local_url(
            env.get("ZERO_TRUST_UPSTREAM_URL", "http://127.0.0.1:8080"),
            "ZERO_TRUST_UPSTREAM_URL",
        )
        host = env.get("ZERO_TRUST_HOST", "127.0.0.1")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise ConfigurationError("ZERO_TRUST_HOST must be an IP address") from exc

        return cls(
            jwks_text=load_jwks_text(env),
            issuer=env.get("ZERO_TRUST_ISSUER", "https://issuer.example.test"),
            audience=env.get("ZERO_TRUST_AUDIENCE", "zero-trust-gateway"),
            allowed_algorithms=algorithms,
            allowed_ips=frozenset(raw_ips),
            required_role=env.get("ZERO_TRUST_REQUIRED_ROLE", "admin"),
            upstream_url=upstream,
            host=host,
            port=_bounded_int(env, "ZERO_TRUST_PORT", 9000, minimum=1, maximum=65_535),
            token_leeway_seconds=_bounded_int(
                env, "ZERO_TRUST_TOKEN_LEEWAY_SECONDS", 5, minimum=0, maximum=60
            ),
            max_token_lifetime_seconds=_bounded_int(
                env,
                "ZERO_TRUST_MAX_TOKEN_LIFETIME_SECONDS",
                3_600,
                minimum=1,
                maximum=86_400,
            ),
            rate_limit_capacity=_bounded_int(
                env, "ZERO_TRUST_RATE_LIMIT_CAPACITY", 20, minimum=1, maximum=10_000
            ),
            rate_limit_refill_per_second=_bounded_float(
                env,
                "ZERO_TRUST_RATE_LIMIT_REFILL_PER_SECOND",
                2.0,
                minimum=0.01,
                maximum=10_000,
            ),
            rate_limit_max_entries=_bounded_int(
                env,
                "ZERO_TRUST_RATE_LIMIT_MAX_ENTRIES",
                1_024,
                minimum=1,
                maximum=100_000,
            ),
            rate_limit_idle_ttl_seconds=_bounded_int(
                env,
                "ZERO_TRUST_RATE_LIMIT_IDLE_TTL_SECONDS",
                300,
                minimum=1,
                maximum=86_400,
            ),
            max_request_bytes=_bounded_int(
                env,
                "ZERO_TRUST_MAX_REQUEST_BYTES",
                1_048_576,
                minimum=1_024,
                maximum=16_777_216,
            ),
            max_response_bytes=_bounded_int(
                env,
                "ZERO_TRUST_MAX_RESPONSE_BYTES",
                4_194_304,
                minimum=1_024,
                maximum=67_108_864,
            ),
            upstream_timeout_seconds=_bounded_float(
                env,
                "ZERO_TRUST_UPSTREAM_TIMEOUT_SECONDS",
                5.0,
                minimum=0.1,
                maximum=60,
            ),
        )
