"""A bounded local reverse proxy with explicit identity and policy checks."""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

import aiohttp
from aiohttp import web
from aiohttp.web_protocol import RequestPayloadError
from multidict import CIMultiDict, CIMultiDictProxy

from .audit import AuditEvent, AuditSink, StructuredAuditLogger
from .config import GatewayConfig
from .keys import JWKKeyRing, TokenValidationError
from .rate_limit import TokenBucketRateLimiter

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
BLOCKED_FORWARD_HEADERS = HOP_BY_HOP_HEADERS | frozenset(
    {
        "authorization",
        "content-encoding",
        "content-length",
        "cookie",
        "forwarded",
        "host",
        "proxy",
        "proxy-connection",
        "x-authenticated-role",
        "x-authenticated-user",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
        "x-request-id",
    }
)
BLOCKED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | frozenset(
    {"content-length", "set-cookie", "x-request-id"}
)

CONFIG_KEY = web.AppKey("config", GatewayConfig)
KEYRING_KEY = web.AppKey("keyring", JWKKeyRing)
RATE_LIMITER_KEY = web.AppKey("rate_limiter", TokenBucketRateLimiter)
AUDIT_KEY = web.AppKey("audit", AuditSink)
SESSION_KEY = web.AppKey("session", aiohttp.ClientSession)


@dataclass(frozen=True, slots=True)
class SecurityContext:
    ip: str
    subject: str
    role: str


class ZeroTrustEngine:
    """Evaluate direct-peer and role policy without trusting forwarded headers."""

    @staticmethod
    def evaluate_policy(
        context: SecurityContext, config: GatewayConfig
    ) -> tuple[bool, str]:
        if context.ip not in config.allowed_ips:
            return False, "untrusted_direct_peer"
        if context.role != config.required_role:
            return False, "insufficient_role"
        return True, "policy_satisfied"


def _filter_headers(
    headers: CIMultiDictProxy[str] | CIMultiDict[str],
    blocked_headers: frozenset[str],
) -> CIMultiDict[str]:
    connection_tokens = {
        token.strip().lower()
        for key, value in headers.items()
        if key.lower() == "connection"
        for token in value.split(",")
        if token.strip()
    }
    blocked = blocked_headers.union(connection_tokens)
    return CIMultiDict(
        (key, value)
        for key, value in headers.items()
        if "_" not in key and key.lower() not in blocked
    )


def build_forward_headers(
    headers: CIMultiDictProxy[str] | CIMultiDict[str],
    authenticated_user: str,
    authenticated_role: str,
    request_id: str,
) -> CIMultiDict[str]:
    """Drop bearer, proxy, and cookie state; replace trusted identity headers."""

    forwarded = CIMultiDict(
        (key, value)
        for key, value in _filter_headers(headers, BLOCKED_FORWARD_HEADERS).items()
        if not key.lower().startswith("x-forwarded-")
    )
    forwarded["X-Authenticated-User"] = authenticated_user
    forwarded["X-Authenticated-Role"] = authenticated_role
    forwarded["X-Request-ID"] = request_id
    return forwarded


def build_response_headers(
    headers: CIMultiDictProxy[str] | CIMultiDict[str], request_id: str
) -> CIMultiDict[str]:
    """Drop hop-by-hop, cookie, and caller-controlled tracing headers."""

    response = _filter_headers(headers, BLOCKED_RESPONSE_HEADERS)
    response["X-Request-ID"] = request_id
    response["Cache-Control"] = "no-store"
    return response


def _error_response(
    *,
    status: int,
    code: str,
    message: str,
    request_id: str,
    retry_after: int | None = None,
) -> web.Response:
    headers = {"X-Request-ID": request_id, "Cache-Control": "no-store"}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return web.json_response(
        {"error": {"code": code, "message": message}, "request_id": request_id},
        status=status,
        headers=headers,
    )


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    scheme, separator, token = authorization.partition(" ")
    if scheme != "Bearer" or separator != " " or not token or " " in token:
        return None
    return token


def _audit(
    request: web.Request,
    *,
    event: str,
    outcome: str,
    request_id: str,
    client_ip: str,
    reason: str,
    status: int,
    subject: str | None = None,
    role: str | None = None,
) -> None:
    route_resource = request.match_info.route.resource
    route = getattr(route_resource, "canonical", "unmatched")
    request.app[AUDIT_KEY].emit(
        AuditEvent(
            event=event,
            outcome=outcome,
            request_id=request_id,
            client_ip=client_ip,
            reason=reason,
            method=request.method,
            route=route,
            status=status,
            subject=subject,
            role=role,
        )
    )


async def proxy_handler(request: web.Request) -> web.Response:
    """Authenticate, authorize, rate limit, and proxy one bounded request."""

    config = request.app[CONFIG_KEY]
    client_ip = request.remote or "unknown"
    request_id = secrets.token_hex(16)

    decision = request.app[RATE_LIMITER_KEY].check(client_ip)
    if not decision.allowed:
        retry_after = max(1, math.ceil(decision.retry_after_seconds))
        _audit(
            request,
            event="rate_limit",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason="request_rate_exceeded",
            status=429,
        )
        return _error_response(
            status=429,
            code="rate_limited",
            message="Too many requests",
            request_id=request_id,
            retry_after=retry_after,
        )

    token = _bearer_token(request.headers.get("Authorization"))
    if token is None:
        _audit(
            request,
            event="authentication",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason="missing_or_malformed_bearer_token",
            status=401,
        )
        return _error_response(
            status=401,
            code="authentication_required",
            message="A valid bearer token is required",
            request_id=request_id,
        )

    try:
        claims = request.app[KEYRING_KEY].decode(
            token,
            issuer=config.issuer,
            audience=config.audience,
            leeway_seconds=config.token_leeway_seconds,
            max_lifetime_seconds=config.max_token_lifetime_seconds,
        )
    except TokenValidationError as exc:
        _audit(
            request,
            event="authentication",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason=exc.reason,
            status=401,
        )
        return _error_response(
            status=401,
            code="invalid_token",
            message="The bearer token is invalid",
            request_id=request_id,
        )

    context = SecurityContext(ip=client_ip, subject=claims["sub"], role=claims["role"])
    allowed, reason = ZeroTrustEngine.evaluate_policy(context, config)
    if not allowed:
        _audit(
            request,
            event="authorization",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason=reason,
            status=403,
            subject=context.subject,
            role=context.role,
        )
        return _error_response(
            status=403,
            code="access_denied",
            message="The request does not satisfy gateway policy",
            request_id=request_id,
        )

    content_encoding = request.headers.get("Content-Encoding")
    if content_encoding and content_encoding.lower() != "identity":
        _audit(
            request,
            event="proxy",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason="encoded_request_body_not_supported",
            status=415,
            subject=context.subject,
            role=context.role,
        )
        return _error_response(
            status=415,
            code="unsupported_content_encoding",
            message="Encoded request bodies are not supported",
            request_id=request_id,
        )

    try:
        body = await request.read()
    except web.HTTPRequestEntityTooLarge:
        _audit(
            request,
            event="proxy",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason="request_body_too_large",
            status=413,
            subject=context.subject,
            role=context.role,
        )
        return _error_response(
            status=413,
            code="request_too_large",
            message="The request body exceeds the configured limit",
            request_id=request_id,
        )
    except RequestPayloadError:
        _audit(
            request,
            event="proxy",
            outcome="denied",
            request_id=request_id,
            client_ip=client_ip,
            reason="invalid_encoded_request_body",
            status=400,
            subject=context.subject,
            role=context.role,
        )
        return _error_response(
            status=400,
            code="invalid_request_body",
            message="The encoded request body is invalid",
            request_id=request_id,
        )
    target_url = f"{config.upstream_url}{request.rel_url.raw_path_qs}"
    forward_headers = build_forward_headers(
        request.headers, context.subject, context.role, request_id
    )

    try:
        async with request.app[SESSION_KEY].request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=body,
            allow_redirects=False,
        ) as upstream:
            response_buffer = bytearray()
            response_too_large = False
            async for chunk in upstream.content.iter_chunked(65_536):
                response_buffer.extend(chunk)
                if len(response_buffer) > config.max_response_bytes:
                    response_too_large = True
                    break
            if response_too_large:
                _audit(
                    request,
                    event="proxy",
                    outcome="failed",
                    request_id=request_id,
                    client_ip=client_ip,
                    reason="upstream_response_too_large",
                    status=502,
                    subject=context.subject,
                    role=context.role,
                )
                return _error_response(
                    status=502,
                    code="upstream_failure",
                    message="The upstream response could not be processed",
                    request_id=request_id,
                )
            response_body = bytes(response_buffer)
            response_headers = build_response_headers(upstream.headers, request_id)
            response = web.Response(
                body=response_body,
                status=upstream.status,
                headers=response_headers,
            )
    except (TimeoutError, aiohttp.ClientError, ValueError):
        _audit(
            request,
            event="proxy",
            outcome="failed",
            request_id=request_id,
            client_ip=client_ip,
            reason="upstream_unavailable",
            status=502,
            subject=context.subject,
            role=context.role,
        )
        return _error_response(
            status=502,
            code="upstream_unavailable",
            message="The upstream service is unavailable",
            request_id=request_id,
        )

    _audit(
        request,
        event="proxy",
        outcome="allowed",
        request_id=request_id,
        client_ip=client_ip,
        reason="policy_satisfied",
        status=response.status,
        subject=context.subject,
        role=context.role,
    )
    return response


async def _client_session_context(app: web.Application) -> AsyncIterator[None]:
    config = app[CONFIG_KEY]
    timeout = aiohttp.ClientTimeout(total=config.upstream_timeout_seconds)
    async with aiohttp.ClientSession(
        timeout=timeout,
        auto_decompress=False,
        raise_for_status=False,
        cookie_jar=aiohttp.DummyCookieJar(),
    ) as session:
        app[SESSION_KEY] = session
        yield


def create_app(
    config: GatewayConfig,
    *,
    keyring: JWKKeyRing | None = None,
    audit_sink: AuditSink | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> web.Application:
    """Build a configured application without starting network listeners."""

    ring = keyring or JWKKeyRing.from_json(
        config.jwks_text, allowed_algorithms=config.allowed_algorithms
    )
    app = web.Application(client_max_size=config.max_request_bytes)
    app[CONFIG_KEY] = config
    app[KEYRING_KEY] = ring
    app[AUDIT_KEY] = audit_sink or StructuredAuditLogger()
    app[RATE_LIMITER_KEY] = TokenBucketRateLimiter(
        capacity=config.rate_limit_capacity,
        refill_per_second=config.rate_limit_refill_per_second,
        max_entries=config.rate_limit_max_entries,
        idle_ttl_seconds=config.rate_limit_idle_ttl_seconds,
        clock=clock,
    )
    app.cleanup_ctx.append(_client_session_context)
    app.router.add_route("*", "/{tail:.*}", proxy_handler)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = GatewayConfig.from_env()
    web.run_app(
        create_app(config),
        host=config.host,
        port=config.port,
        access_log=None,
        auto_decompress=False,
    )
