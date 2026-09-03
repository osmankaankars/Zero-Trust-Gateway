"""Compatibility entry point for the local token simulator."""

from zero_trust_gateway.idp import (
    generate_demo_jwks,
    generate_token,
    main,
    write_new_demo_jwks,
)

__all__ = ["generate_demo_jwks", "generate_token", "main", "write_new_demo_jwks"]


if __name__ == "__main__":
    main()
