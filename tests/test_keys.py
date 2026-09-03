from __future__ import annotations

import json
import unittest
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tests.helpers import AUDIENCE, ISSUER, KEY_A, KEY_B, jwks, token
from zero_trust_gateway.idp import (
    generate_demo_jwks,
    generate_token,
    write_new_demo_jwks,
)
from zero_trust_gateway.keys import (
    JWKKeyRing,
    KeyConfigurationError,
    TokenValidationError,
)


class KeyRingTests(unittest.TestCase):
    def test_rejects_duplicate_members_kids_and_short_hmac_keys(self) -> None:
        with self.assertRaises(KeyConfigurationError):
            JWKKeyRing.from_json('{"keys":[],"keys":[]}', allowed_algorithms=("HS256",))
        with self.assertRaises(KeyConfigurationError):
            JWKKeyRing.from_json(
                jwks(("duplicate", KEY_A), ("duplicate", KEY_B)),
                allowed_algorithms=("HS256",),
            )
        short_key = urlsafe_b64encode(b"short").rstrip(b"=").decode("ascii")
        document = json.dumps(
            {
                "keys": [
                    {
                        "kty": "oct",
                        "kid": "short",
                        "alg": "HS256",
                        "k": short_key,
                    }
                ]
            }
        )
        with self.assertRaises(KeyConfigurationError):
            JWKKeyRing.from_json(document, allowed_algorithms=("HS256",))

    def test_rotation_accepts_each_known_kid_and_rejects_unknown_kid(self) -> None:
        ring = JWKKeyRing.from_json(
            jwks(("key-a", KEY_A), ("key-b", KEY_B)),
            allowed_algorithms=("HS256",),
        )
        for kid, key in (("key-a", KEY_A), ("key-b", KEY_B)):
            claims = ring.decode(
                token(kid=kid, key=key),
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )
            self.assertEqual(claims["sub"], "lab-admin")
        with self.assertRaisesRegex(TokenValidationError, "unknown_kid"):
            ring.decode(
                token(kid="retired", key=KEY_A),
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )
        with self.assertRaisesRegex(TokenValidationError, "invalid_token"):
            ring.decode(
                token(kid="key-a", key=KEY_B),
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )

    def test_rejects_expired_wrong_issuer_wrong_audience_and_wrong_type(self) -> None:
        ring = JWKKeyRing.from_json(
            jwks(("key-a", KEY_A)), allowed_algorithms=("HS256",)
        )
        missing_type = token(headers={"typ": None})
        self.assertNotIn("typ", jwt.get_unverified_header(missing_type))
        cases = (
            (
                token(
                    issued_at=datetime.now(UTC) - timedelta(minutes=5),
                    expires_in=1,
                ),
                "expired_token",
            ),
            (token(issuer="https://wrong.example"), "invalid_issuer"),
            (token(audience="wrong-audience"), "invalid_audience"),
            (token(headers={"typ": "NOT-JWT"}), "invalid_token_type"),
            (missing_type, "invalid_token_type"),
        )
        for encoded, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(TokenValidationError, reason):
                    ring.decode(
                        encoded,
                        issuer=ISSUER,
                        audience=AUDIENCE,
                        leeway_seconds=0,
                    )

    def test_rejects_multi_audience_and_oversized_tokens(self) -> None:
        ring = JWKKeyRing.from_json(
            jwks(("key-a", KEY_A)), allowed_algorithms=("HS256",)
        )
        encoded = token(audience=[AUDIENCE, "another-service"])
        with self.assertRaisesRegex(TokenValidationError, "invalid_audience"):
            ring.decode(
                encoded,
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )
        with self.assertRaisesRegex(TokenValidationError, "token_too_large"):
            ring.decode(
                "x" * 8_193,
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )
        with self.assertRaisesRegex(TokenValidationError, "malformed_token"):
            ring.decode(
                "header.payload.\udcff",
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway_seconds=0,
            )

    def test_keyset_file_creation_is_exclusive_private_and_no_follow(self) -> None:
        import stat
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "jwks.local.json"
            write_new_demo_jwks(output, kid="exclusive")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(output.read_text())["keys"][0]["kid"], "exclusive"
            )

            original = output.read_bytes()
            with self.assertRaises(FileExistsError):
                write_new_demo_jwks(output)
            self.assertEqual(output.read_bytes(), original)

            target = root / "target.json"
            target.write_text("sentinel", encoding="utf-8")
            link = root / "linked.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                write_new_demo_jwks(link)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")

    def test_rejects_algorithm_mismatch_missing_claims_and_long_lifetime(self) -> None:
        ring = JWKKeyRing.from_json(
            jwks(("key-a", KEY_A)), allowed_algorithms=("HS256",)
        )
        valid = token()
        _, payload, signature = valid.split(".")
        altered_header = (
            urlsafe_b64encode(
                json.dumps(
                    {"alg": "HS384", "kid": "key-a", "typ": "JWT"},
                    separators=(",", ":"),
                ).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        now = datetime.now(UTC)
        missing_role = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "lab-admin",
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(minutes=5),
            },
            KEY_A,
            algorithm="HS256",
            headers={"kid": "key-a", "typ": "JWT"},
        )
        malformed_exp = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "lab-admin",
                "role": "admin",
                "iat": now,
                "nbf": now,
                "exp": [],
            },
            KEY_A,
            algorithm="HS256",
            headers={"kid": "key-a", "typ": "JWT"},
        )
        malformed_nbf = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "lab-admin",
                "role": "admin",
                "iat": now,
                "nbf": True,
                "exp": now + timedelta(minutes=5),
            },
            KEY_A,
            algorithm="HS256",
            headers={"kid": "key-a", "typ": "JWT"},
        )
        oversized_numeric_date = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "lab-admin",
                "role": "admin",
                "iat": 1,
                "nbf": 1,
                "exp": 10**1_000,
            },
            KEY_A,
            algorithm="HS256",
            headers={"kid": "key-a", "typ": "JWT"},
        )
        cases = (
            (f"{altered_header}.{payload}.{signature}", "algorithm_key_mismatch"),
            (missing_role, "invalid_token"),
            (malformed_exp, "invalid_token"),
            (malformed_nbf, "invalid_token_lifetime"),
            (oversized_numeric_date, "invalid_token_lifetime"),
            (token(expires_in=3_601), "invalid_token_lifetime"),
        )
        for encoded, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(TokenValidationError, reason):
                    ring.decode(
                        encoded,
                        issuer=ISSUER,
                        audience=AUDIENCE,
                        leeway_seconds=0,
                        max_lifetime_seconds=3_600,
                    )

    def test_verifies_supported_asymmetric_public_keys(self) -> None:
        now = datetime.now(UTC)
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "lab-admin",
            "role": "admin",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
        }
        cases = (
            (
                "RS256",
                rsa.generate_private_key(public_exponent=65_537, key_size=2_048),
                jwt.algorithms.RSAAlgorithm,
            ),
            (
                "ES256",
                ec.generate_private_key(ec.SECP256R1()),
                jwt.algorithms.ECAlgorithm,
            ),
        )
        for algorithm, private_key, converter in cases:
            with self.subTest(algorithm=algorithm):
                public_jwk = json.loads(converter.to_jwk(private_key.public_key()))
                public_jwk.update(
                    {"kid": algorithm.lower(), "alg": algorithm, "use": "sig"}
                )
                ring = JWKKeyRing.from_json(
                    json.dumps({"keys": [public_jwk]}),
                    allowed_algorithms=(algorithm,),
                )
                encoded = jwt.encode(
                    claims,
                    private_key,
                    algorithm=algorithm,
                    headers={"kid": algorithm.lower(), "typ": "JWT"},
                )
                decoded = ring.decode(
                    encoded,
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    leeway_seconds=0,
                )
                self.assertEqual(decoded["sub"], "lab-admin")

    def test_rejects_weak_rsa_and_wrong_es256_curve(self) -> None:
        weak_rsa = rsa.generate_private_key(
            public_exponent=65_537,
            key_size=1_024,  # noqa: S505 - rejection fixture
        )
        wrong_curve = ec.generate_private_key(ec.SECP384R1())
        cases = (
            (
                "RS256",
                weak_rsa,
                jwt.algorithms.RSAAlgorithm,
                "at least 2048 bits",
            ),
            (
                "ES256",
                wrong_curve,
                jwt.algorithms.ECAlgorithm,
                "P-256 curve",
            ),
        )
        for algorithm, private_key, converter, reason in cases:
            with self.subTest(algorithm=algorithm):
                public_jwk = json.loads(converter.to_jwk(private_key.public_key()))
                public_jwk.update(
                    {"kid": algorithm.lower(), "alg": algorithm, "use": "sig"}
                )
                with self.assertRaisesRegex(KeyConfigurationError, reason):
                    JWKKeyRing.from_json(
                        json.dumps({"keys": [public_jwk]}),
                        allowed_algorithms=(algorithm,),
                    )

    def test_simulator_generates_a_verifiable_short_lived_token(self) -> None:
        document = generate_demo_jwks(kid="active")
        encoded = generate_token(
            "lab-admin",
            "admin",
            jwks_text=document,
            kid="active",
            lifetime_seconds=60,
        )
        ring = JWKKeyRing.from_json(document, allowed_algorithms=("HS256",))
        claims = ring.decode(
            encoded, issuer=ISSUER, audience=AUDIENCE, leeway_seconds=0
        )
        self.assertEqual(claims["role"], "admin")


if __name__ == "__main__":
    unittest.main()
