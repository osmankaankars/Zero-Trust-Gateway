from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.helpers import KEY_A, jwks
from zero_trust_gateway.config import (
    ConfigurationError,
    GatewayConfig,
    load_jwks_text,
)


class ConfigurationTests(unittest.TestCase):
    def test_requires_exactly_one_local_key_source(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_jwks_text({})
        with self.assertRaises(ConfigurationError):
            load_jwks_text(
                {
                    "ZERO_TRUST_JWKS_JSON": jwks(("key-a", KEY_A)),
                    "ZERO_TRUST_JWKS_FILE": "/tmp/example",  # noqa: S108
                }
            )

    def test_reads_bounded_utf8_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jwks.json"
            path.write_text(jwks(("key-a", KEY_A)), encoding="utf-8")
            self.assertEqual(
                load_jwks_text({"ZERO_TRUST_JWKS_FILE": str(path)}),
                path.read_text(encoding="utf-8"),
            )

    def test_rejects_non_loopback_upstream_and_listener(self) -> None:
        with self.assertRaises(ConfigurationError):
            GatewayConfig(
                jwks_text=jwks(("key-a", KEY_A)),
                upstream_url="https://example.com",
            )
        with self.assertRaises(ConfigurationError):
            GatewayConfig(
                jwks_text=jwks(("key-a", KEY_A)),
                host="0.0.0.0",  # noqa: S104
            )
        with self.assertRaises(ConfigurationError):
            GatewayConfig(
                jwks_text=jwks(("key-a", KEY_A)),
                upstream_url="http://127.0.0.1:8080?redirect=unexpected",
            )
        for value in (
            "http://127.0.0.1:not-a-port",
            "http://127.0.0.1:0",
            "http://127.0.0.1:70000",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError):
                    GatewayConfig(jwks_text=jwks(("key-a", KEY_A)), upstream_url=value)

    def test_environment_parser_is_strict_and_normalizes_ips(self) -> None:
        parsed = GatewayConfig.from_env(
            {
                "ZERO_TRUST_JWKS_JSON": jwks(("key-a", KEY_A)),
                "ZERO_TRUST_ALLOWED_ALGORITHMS": "HS256",
                "ZERO_TRUST_ALLOWED_IPS": "127.0.0.1, ::1",
                "ZERO_TRUST_RATE_LIMIT_CAPACITY": "7",
                "ZERO_TRUST_MAX_TOKEN_LIFETIME_SECONDS": "900",
            }
        )
        self.assertEqual(parsed.allowed_algorithms, ("HS256",))
        self.assertEqual(parsed.allowed_ips, frozenset({"127.0.0.1", "::1"}))
        self.assertEqual(parsed.rate_limit_capacity, 7)
        self.assertEqual(parsed.max_token_lifetime_seconds, 900)

        with self.assertRaises(ConfigurationError):
            GatewayConfig.from_env(
                {
                    "ZERO_TRUST_JWKS_JSON": jwks(("key-a", KEY_A)),
                    "ZERO_TRUST_ALLOWED_IPS": "not-an-ip",
                }
            )


if __name__ == "__main__":
    unittest.main()
