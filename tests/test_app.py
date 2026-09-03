from __future__ import annotations

import asyncio
import gzip
import json
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from multidict import CIMultiDict

from tests.helpers import MemoryAuditSink, config, token
from zero_trust_gateway.app import (
    SecurityContext,
    ZeroTrustEngine,
    build_forward_headers,
    create_app,
    main,
)


class PolicyAndHeaderTests(unittest.TestCase):
    def test_policy_requires_direct_loopback_and_required_role(self) -> None:
        cfg = config()
        self.assertEqual(
            ZeroTrustEngine.evaluate_policy(
                SecurityContext("127.0.0.1", "lab-admin", "admin"), cfg
            ),
            (True, "policy_satisfied"),
        )
        self.assertEqual(
            ZeroTrustEngine.evaluate_policy(
                SecurityContext("192.0.2.1", "lab-admin", "admin"), cfg
            ),
            (False, "untrusted_direct_peer"),
        )
        self.assertEqual(
            ZeroTrustEngine.evaluate_policy(
                SecurityContext("127.0.0.1", "lab-user", "guest"), cfg
            ),
            (False, "insufficient_role"),
        )

    def test_forward_headers_remove_credentials_hop_headers_and_spoofed_identity(
        self,
    ) -> None:
        headers = CIMultiDict(
            [
                ("Authorization", "Bearer secret-token"),
                ("Cookie", "upstream-session=subject-a"),
                ("Connection", "keep-alive, X-Remove-Me"),
                ("Host", "gateway.test"),
                ("X-Authenticated-User", "spoofed"),
                ("X-Authenticated-Role", "spoofed"),
                ("X_Authenticated_User", "underscore-spoofed"),
                ("X_Forwarded_For", "203.0.113.7"),
                ("X-Request-ID", "spoofed"),
                ("Forwarded", "for=192.0.2.1"),
                ("X-Forwarded-For", "192.0.2.1"),
                ("x-forwarded-for", "198.51.100.2"),
                ("X-Forwarded-Custom", "untrusted"),
                ("X-Real-IP", "192.0.2.1"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy", "http://attacker.invalid:8080"),
                ("X-Remove-Me", "remove"),
                ("X-Trace", "keep"),
            ]
        )
        forwarded = build_forward_headers(headers, "verified", "admin", "request-1")
        for removed in (
            "Authorization",
            "Cookie",
            "Connection",
            "Host",
            "X-Remove-Me",
            "Forwarded",
            "X-Forwarded-For",
            "X-Forwarded-Custom",
            "X_Authenticated_User",
            "X_Forwarded_For",
            "X-Real-IP",
            "Proxy-Connection",
            "Proxy",
        ):
            self.assertNotIn(removed, forwarded)
        self.assertEqual(forwarded["X-Authenticated-User"], "verified")
        self.assertEqual(forwarded["X-Authenticated-Role"], "admin")
        self.assertEqual(forwarded["X-Request-ID"], "request-1")
        self.assertEqual(forwarded["X-Trace"], "keep")


class GatewayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.audit = MemoryAuditSink()
        self._clients: list[TestClient] = []
        self._servers: list[TestServer] = []

    async def asyncTearDown(self) -> None:
        for client in reversed(self._clients):
            await client.close()
        for server in reversed(self._servers):
            await server.close()

    async def _upstream(self, handler) -> str:
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        server = TestServer(app)
        await server.start_server()
        self._servers.append(server)
        return str(server.make_url("/")).rstrip("/")

    async def _gateway(self, *, upstream_url: str, **overrides) -> TestClient:
        cfg = config(upstream_url=upstream_url, **overrides)
        server = TestServer(create_app(cfg, audit_sink=self.audit))
        await server.start_server(auto_decompress=False)
        client = TestClient(server)
        await client.start_server()
        self._clients.append(client)
        return client

    async def test_authentication_and_authorization_failure_paths(self) -> None:
        async def upstream(_request: web.Request) -> web.Response:
            return web.Response(text="should not be reached")

        client = await self._gateway(upstream_url=await self._upstream(upstream))
        cases = (
            ({}, 401, "authentication_required"),
            (
                {"Authorization": f"Bearer {token(issuer='https://wrong.example')}"},
                401,
                "invalid_token",
            ),
            (
                {"Authorization": f"Bearer {token(role='guest')}"},
                403,
                "access_denied",
            ),
        )
        for headers, expected_status, expected_code in cases:
            with self.subTest(code=expected_code):
                response = await client.get("/protected", headers=headers)
                payload = await response.json()
                self.assertEqual(response.status, expected_status)
                self.assertEqual(payload["error"]["code"], expected_code)
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    async def test_proxies_allowed_request_without_credentials_and_without_redirects(
        self,
    ) -> None:
        observed: dict[str, str] = {}

        async def upstream(request: web.Request) -> web.Response:
            observed.update(request.headers)
            if request.path == "/redirect":
                raise web.HTTPFound("/final")
            compressed = gzip.compress(b"upstream")
            response = web.Response(
                body=compressed,
                headers={"Content-Encoding": "gzip", "Connection": "keep-alive"},
            )
            response.headers.add("Set-Cookie", "one=1; Path=/")
            response.headers.add("Set-Cookie", "two=2; Path=/")
            return response

        client = await self._gateway(upstream_url=await self._upstream(upstream))
        authorization = f"Bearer {token()}"
        async with aiohttp.ClientSession(auto_decompress=False) as raw_client:
            response = await raw_client.get(
                client.make_url("/resource?view=one"),
                headers={
                    "Authorization": authorization,
                    "X-Authenticated-User": "spoofed",
                },
            )
            body = await response.read()
        self.assertEqual(response.status, 200)
        self.assertEqual(body, gzip.compress(b"upstream"))
        self.assertNotIn("Authorization", observed)
        self.assertEqual(observed["X-Authenticated-User"], "lab-admin")
        self.assertEqual(observed["X-Authenticated-Role"], "admin")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("Connection", response.headers)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

        redirect = await client.get(
            "/redirect",
            headers={"Authorization": authorization},
            allow_redirects=False,
        )
        self.assertEqual(redirect.status, 302)

    async def test_upstream_cookie_state_is_not_forwarded_or_returned(self) -> None:
        observed_cookies: list[str | None] = []

        async def upstream(request: web.Request) -> web.Response:
            observed_cookies.append(request.headers.get("Cookie"))
            response = web.Response(text="ok")
            if request.path == "/establish-session":
                response.set_cookie("upstream-session", "victim-session")
            return response

        upstream_url = (await self._upstream(upstream)).replace(
            "127.0.0.1", "localhost"
        )
        client = await self._gateway(upstream_url=upstream_url)

        first = await client.get(
            "/establish-session",
            headers={"Authorization": f"Bearer {token(subject='subject-a')}"},
        )
        await first.read()
        self.assertNotIn("Set-Cookie", first.headers)

        second = await client.get(
            "/observe-session",
            headers={
                "Authorization": f"Bearer {token(subject='subject-b')}",
                "Cookie": "upstream-session=victim-session",
            },
        )
        await second.read()

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertEqual(observed_cookies, [None, None])

    async def test_non_utf8_bearer_bytes_fail_closed_and_are_audited(self) -> None:
        async def upstream(_request: web.Request) -> web.Response:
            return web.Response(text="must not be reached")

        client = await self._gateway(upstream_url=await self._upstream(upstream))
        reader, writer = await asyncio.open_connection(
            client.server.host, client.server.port
        )
        writer.write(
            b"GET /protected HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Authorization: Bearer \xff\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()

        self.assertTrue(response.startswith(b"HTTP/1.1 401 Unauthorized\r\n"))
        self.assertEqual(self.audit.events[-1].event, "authentication")
        self.assertEqual(self.audit.events[-1].reason, "malformed_token")

    async def test_rate_limit_returns_retry_after(self) -> None:
        async def upstream(_request: web.Request) -> web.Response:
            return web.Response(text="ok")

        client = await self._gateway(
            upstream_url=await self._upstream(upstream),
            rate_limit_capacity=1,
            rate_limit_refill_per_second=0.01,
        )
        first = await client.get("/")
        second = await client.get("/")
        self.assertEqual(first.status, 401)
        self.assertEqual(second.status, 429)
        self.assertGreaterEqual(int(second.headers["Retry-After"]), 1)

    async def test_upstream_failure_and_oversized_response_are_sanitized(self) -> None:
        closed_server = TestServer(web.Application())
        await closed_server.start_server()
        closed_url = str(closed_server.make_url("/")).rstrip("/")
        await closed_server.close()
        unavailable = await self._gateway(upstream_url=closed_url)
        response = await unavailable.get(
            "/", headers={"Authorization": f"Bearer {token()}"}
        )
        self.assertEqual(response.status, 502)
        self.assertEqual(
            (await response.json())["error"]["code"], "upstream_unavailable"
        )

        async def large(request: web.Request) -> web.StreamResponse:
            response = web.StreamResponse()
            await response.prepare(request)
            await response.write(b"x" * 600)
            await response.write(b"y" * 600)
            await response.write_eof()
            return response

        oversized = await self._gateway(
            upstream_url=await self._upstream(large), max_response_bytes=1_024
        )
        response = await oversized.get(
            "/", headers={"Authorization": f"Bearer {token()}"}
        )
        self.assertEqual(response.status, 502)
        self.assertEqual((await response.json())["error"]["code"], "upstream_failure")

    async def test_request_limit_and_upstream_timeout_fail_closed(self) -> None:
        async def upstream(_request: web.Request) -> web.Response:
            await asyncio.sleep(0.25)
            return web.Response(text="too late")

        upstream_url = await self._upstream(upstream)
        limited = await self._gateway(
            upstream_url=upstream_url,
            max_request_bytes=1_024,
        )
        response = await limited.post(
            "/upload",
            data=b"x" * 1_025,
            headers={"Authorization": f"Bearer {token()}"},
        )
        self.assertEqual(response.status, 413)
        self.assertEqual((await response.json())["error"]["code"], "request_too_large")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

        timed_out = await self._gateway(
            upstream_url=upstream_url,
            upstream_timeout_seconds=0.1,
        )
        response = await timed_out.get(
            "/slow", headers={"Authorization": f"Bearer {token()}"}
        )
        self.assertEqual(response.status, 502)
        self.assertEqual(
            (await response.json())["error"]["code"], "upstream_unavailable"
        )

    async def test_encoded_request_bodies_are_rejected_before_upstream(self) -> None:
        observed: dict[str, object] = {}

        async def upstream(request: web.Request) -> web.Response:
            observed["body"] = await request.read()
            observed["content_encoding"] = request.headers.get("Content-Encoding")
            return web.Response(text="ok")

        client = await self._gateway(upstream_url=await self._upstream(upstream))
        headers = {
            "Authorization": f"Bearer {token()}",
            "Content-Encoding": "gzip",
        }
        for body in (gzip.compress(b"decoded"), b"invalid-gzip"):
            with self.subTest(body=body[:8]):
                response = await client.post("/upload", data=body, headers=headers)
                self.assertEqual(response.status, 415)
                self.assertEqual(
                    (await response.json())["error"]["code"],
                    "unsupported_content_encoding",
                )
                self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(observed, {})

    async def test_audit_events_do_not_capture_token_or_query_string(self) -> None:
        async def upstream(_request: web.Request) -> web.Response:
            return web.Response(text="ok")

        client = await self._gateway(upstream_url=await self._upstream(upstream))
        sensitive_token = "unique-sensitive-token-value"
        await client.get(
            "/audit?credential=do-not-log",
            headers={"Authorization": f"Bearer {sensitive_token}"},
        )
        serialized = json.dumps(
            [
                event.__dict__ if hasattr(event, "__dict__") else str(event)
                for event in self.audit.events
            ]
        )
        self.assertNotIn(sensitive_token, serialized)
        self.assertNotIn("do-not-log", serialized)
        self.assertEqual(self.audit.events[-1].route, "/{tail}")


class RuntimeLoggingTests(unittest.TestCase):
    @patch("zero_trust_gateway.app.web.run_app")
    @patch("zero_trust_gateway.app.GatewayConfig.from_env")
    def test_main_disables_raw_aiohttp_access_log(self, from_env, run_app) -> None:
        from_env.return_value = config()
        main()
        self.assertIsNone(run_app.call_args.kwargs["access_log"])
        self.assertFalse(run_app.call_args.kwargs["auto_decompress"])


if __name__ == "__main__":
    unittest.main()
