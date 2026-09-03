"""Compatibility entry point for the packaged gateway."""

from zero_trust_gateway.app import (
    SecurityContext,
    ZeroTrustEngine,
    build_forward_headers,
    build_response_headers,
    create_app,
    main,
    proxy_handler,
)
from zero_trust_gateway.config import GatewayConfig
from zero_trust_gateway.keys import JWKKeyRing

__all__ = [
    "GatewayConfig",
    "JWKKeyRing",
    "SecurityContext",
    "ZeroTrustEngine",
    "build_forward_headers",
    "build_response_headers",
    "create_app",
    "main",
    "proxy_handler",
]


if __name__ == "__main__":
    main()
