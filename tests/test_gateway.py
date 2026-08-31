import gzip
import importlib
import os
import unittest
from unittest import mock

import aiohttp
import jwt
from aiohttp import web
from aiohttp.test_utils import TestServer
from multidict import CIMultiDict

import gateway
import idp_simulator


class PolicyEngineTests(unittest.TestCase):
    def test_allows_loopback_admin_identity(self):
        context = gateway.SecurityContext(
            ip="127.0.0.1", token_payload={"sub": "lab-admin", "role": "admin"}
        )

        self.assertTrue(gateway.ZeroTrustEngine.evaluate_policy(context))

    def test_denies_untrusted_network_or_missing_admin_role(self):
        cases = (
            gateway.SecurityContext(
                ip="192.0.2.10", token_payload={"sub": "lab-admin", "role": "admin"}
            ),
            gateway.SecurityContext(ip="127.0.0.1"),
            gateway.SecurityContext(
                ip="127.0.0.1", token_payload={"sub": "lab-user", "role": "guest"}
            ),
        )

        for context in cases:
            with self.subTest(ip=context.ip, role=context.role):
                self.assertFalse(gateway.ZeroTrustEngine.evaluate_policy(context))

    def test_idp_simulator_token_is_accepted_by_gateway_configuration(self):
        token = idp_simulator.generate_token("lab-admin", "admin")

        payload = jwt.decode(
            token,
            gateway.JWT_SECRET,
            algorithms=[gateway.ALGORITHM],
        )

        self.assertEqual(payload["sub"], "lab-admin")
        self.assertEqual(payload["role"], "admin")


class GatewayRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_token_is_denied_before_proxying(self):
        request = mock.Mock(remote="127.0.0.1", headers={})

        response = await gateway.proxy_handler(request)

        self.assertEqual(response.status, 403)
        self.assertEqual(response.text, "Zero Trust Gateway: Access Denied")
        request.read.assert_not_called()

    async def test_invalid_token_is_rejected(self):
        request = mock.Mock(
            remote="127.0.0.1",
            headers={"Authorization": "Bearer invalid-token"},
        )

        response = await gateway.proxy_handler(request)

        self.assertEqual(response.status, 403)
        self.assertEqual(response.text, "Gateway Error: Invalid Token")

    async def test_token_without_required_expiry_is_rejected(self):
        token = jwt.encode(
            {"sub": "lab-admin", "role": "admin"},
            gateway.JWT_SECRET,
            algorithm=gateway.ALGORITHM,
        )
        request = mock.Mock(
            remote="127.0.0.1",
            headers={"Authorization": f"Bearer {token}"},
            path_qs="/",
            method="GET",
        )

        response = await gateway.proxy_handler(request)

        self.assertEqual(response.status, 403)
        self.assertEqual(response.text, "Gateway Error: Invalid Token")


class ForwardHeaderTests(unittest.TestCase):
    def test_drops_caller_credentials_and_replaces_identity_header(self):
        headers = CIMultiDict(
            [
                ("Authorization", "Bearer caller-token"),
                ("Connection", "keep-alive"),
                ("Connection", "X-Remove-Me"),
                ("Host", "gateway.test"),
                ("X-Authenticated-User", "spoofed-user"),
                ("X-Remove-Me", "hop-by-hop-value"),
                ("X-Trace-ID", "trace-123"),
            ]
        )

        forwarded = gateway.build_forward_headers(headers, "verified-user")

        self.assertNotIn("Authorization", forwarded)
        self.assertNotIn("Connection", forwarded)
        self.assertNotIn("Host", forwarded)
        self.assertNotIn("X-Remove-Me", forwarded)
        self.assertEqual(forwarded["X-Authenticated-User"], "verified-user")
        self.assertEqual(forwarded["X-Trace-ID"], "trace-123")


class ProxyResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_preserves_compressed_body_and_filters_hop_by_hop_headers(self):
        plaintext = b"compressed upstream response"
        compressed = gzip.compress(plaintext)

        async def upstream_handler(_request):
            response = web.Response(
                body=compressed,
                headers={
                    "Content-Encoding": "gzip",
                    "Connection": "keep-alive",
                },
            )
            response.headers.add("Set-Cookie", "first=one; Path=/")
            response.headers.add("Set-Cookie", "second=two; Path=/")
            return response

        upstream_app = web.Application()
        upstream_app.router.add_get("/", upstream_handler)
        upstream_server = TestServer(upstream_app)

        proxy_app = web.Application()
        proxy_app.router.add_route("*", "/{tail:.*}", gateway.proxy_handler)
        proxy_server = TestServer(proxy_app)

        await upstream_server.start_server()
        await proxy_server.start_server()
        token = idp_simulator.generate_token("lab-admin", "admin")

        try:
            upstream_url = str(upstream_server.make_url("/")).rstrip("/")
            with mock.patch.object(gateway, "UPSTREAM_SERVICE_URL", upstream_url):
                async with aiohttp.ClientSession(auto_decompress=False) as client:
                    response = await client.get(
                        proxy_server.make_url("/"),
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    body = await response.read()

            self.assertEqual(response.status, 200)
            self.assertEqual(body, compressed)
            self.assertEqual(response.headers["Content-Encoding"], "gzip")
            self.assertEqual(int(response.headers["Content-Length"]), len(compressed))
            self.assertNotIn("Connection", response.headers)
            self.assertEqual(
                response.headers.getall("Set-Cookie"),
                ["first=one; Path=/", "second=two; Path=/"],
            )
        finally:
            await proxy_server.close()
            await upstream_server.close()


class ConfigurationTests(unittest.TestCase):
    def test_shared_secret_can_be_overridden_for_the_lab(self):
        configured_secret = "test-only-secret-with-sufficient-length"
        try:
            with mock.patch.dict(
                os.environ, {"ZERO_TRUST_JWT_SECRET": configured_secret}, clear=False
            ):
                importlib.reload(gateway)
                importlib.reload(idp_simulator)
                self.assertEqual(gateway.JWT_SECRET, configured_secret)
                self.assertEqual(idp_simulator.JWT_SECRET, configured_secret)
        finally:
            importlib.reload(gateway)
            importlib.reload(idp_simulator)


if __name__ == "__main__":
    unittest.main()
