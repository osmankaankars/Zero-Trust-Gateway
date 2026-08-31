import asyncio
import logging
import os
import sys

import aiohttp
import jwt
from aiohttp import web
from colorama import Fore, Style, init
from multidict import CIMultiDict

# Initialize Colorama for standardized output
init(autoreset=True)

# --- CONFIGURATION & CONSTANTS ---
# Local demonstration defaults. Override the shared secret through the
# environment before using the simulator outside a single-user workstation.
UPSTREAM_SERVICE_URL = "http://127.0.0.1:8080"  # Target: SAP Honeypot
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 9000
JWT_SECRET = os.getenv(
    "ZERO_TRUST_JWT_SECRET", "local-demo-only-secret-change-before-shared-use"
)
ALGORITHM = "HS256"

# Zero Trust Policies
ALLOWED_IPS = {"127.0.0.1", "::1"}
REQUIRED_ROLE = "admin"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
BLOCKED_FORWARD_HEADERS = HOP_BY_HOP_HEADERS | {
    "authorization",
    "content-length",
    "host",
    "x-authenticated-user",
}

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ZeroTrustGateway")


class SecurityContext:
    """
    Represents the security context of an incoming request,
    encapsulating identity and network attributes.
    """

    def __init__(self, ip: str, token_payload: dict | None = None):
        self.ip = ip
        self.identity = token_payload or {}
        self.is_authenticated = token_payload is not None

    @property
    def role(self) -> str:
        return self.identity.get("role", "guest")

    @property
    def user(self) -> str:
        return self.identity.get("sub", "anonymous")


class ZeroTrustEngine:
    """
    Core logic for evaluating access policies based on the Security Context.
    Implements the 'Never Trust, Always Verify' principle.
    """

    @staticmethod
    def evaluate_policy(ctx: SecurityContext) -> bool:
        """
        Evaluates the request against defined security policies.
        Returns True if access is granted, False otherwise.
        """
        # 1. Network Policy (Micro-segmentation check)
        if ctx.ip not in ALLOWED_IPS:
            logger.warning(f"Policy Violation: Unauthorized IP {ctx.ip}")
            return False

        # 2. Identity Policy (RBAC)
        if not ctx.is_authenticated:
            logger.warning("Policy Violation: Unauthenticated request")
            return False

        if ctx.role != REQUIRED_ROLE:
            logger.warning(
                f"Policy Violation: Insufficient privileges. User: {ctx.user}, Role: {ctx.role}"
            )
            return False

        logger.info(f"Access Granted: {ctx.user}@{ctx.ip} (Role: {ctx.role})")
        return True


def _filter_headers(headers, blocked_headers):
    connection_tokens = {
        token.strip().lower()
        for key, value in headers.items()
        if key.lower() == "connection"
        for token in value.split(",")
        if token.strip()
    }
    blocked = blocked_headers.union(connection_tokens)
    return CIMultiDict(
        (key, value) for key, value in headers.items() if key.lower() not in blocked
    )


def build_forward_headers(headers, authenticated_user):
    """Drop caller credentials and hop-by-hop headers before proxying."""
    forwarded = _filter_headers(headers, BLOCKED_FORWARD_HEADERS)
    forwarded["X-Authenticated-User"] = authenticated_user
    return forwarded


def build_response_headers(headers):
    """Drop upstream hop-by-hop headers before returning the response."""
    return _filter_headers(headers, HOP_BY_HOP_HEADERS)


async def proxy_handler(request: web.Request) -> web.Response:
    """
    Intercepts all incoming traffic, enforces security policies,
    and proxies valid requests to the upstream service.
    """
    client_ip = request.remote
    auth_header = request.headers.get("Authorization")
    token_payload = None

    # --- STEP 1: AUTHENTICATION (Stateless) ---
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            token_payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[ALGORITHM],
                options={"require": ["exp", "sub", "role"]},
            )
        except jwt.ExpiredSignatureError:
            return web.Response(text="Gateway Error: Token Expired", status=401)
        except jwt.InvalidTokenError:
            return web.Response(text="Gateway Error: Invalid Token", status=403)

    # --- STEP 2: AUTHORIZATION (Zero Trust Evaluation) ---
    context = SecurityContext(ip=client_ip, token_payload=token_payload)

    if not ZeroTrustEngine.evaluate_policy(context):
        return web.Response(text="Zero Trust Gateway: Access Denied", status=403)

    # --- STEP 3: REVERSE PROXYING (Asynchronous) ---
    # Forward the request to the upstream service (e.g., SAP Honeypot).
    target_url = f"{UPSTREAM_SERVICE_URL}{request.path_qs}"

    forward_headers = build_forward_headers(request.headers, context.user)

    try:
        async with (
            aiohttp.ClientSession(auto_decompress=False) as session,
            session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=await request.read(),
            ) as resp,
        ):
            body = await resp.read()
            response_headers = build_response_headers(resp.headers)
            return web.Response(body=body, status=resp.status, headers=response_headers)

    except aiohttp.ClientConnectorError:
        logger.error(f"Upstream Service Unreachable: {UPSTREAM_SERVICE_URL}")
        return web.Response(
            text="Gateway Error: Upstream Service Unavailable", status=502
        )


async def start_server():
    """Initializes and starts the AsyncIO web server."""
    app = web.Application()

    # Catch-all route to act as a transparent proxy
    app.router.add_route("*", "/{tail:.*}", proxy_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, GATEWAY_HOST, GATEWAY_PORT)

    print(Fore.CYAN + Style.BRIGHT + "=========================================")
    print(Fore.CYAN + Style.BRIGHT + "   ZERO TRUST IDENTITY AWARE GATEWAY     ")
    print(Fore.CYAN + Style.BRIGHT + "=========================================")
    print(Fore.GREEN + "[*] Status:    ONLINE")
    print(Fore.GREEN + f"[*] Listen:    {GATEWAY_HOST}:{GATEWAY_PORT}")
    print(Fore.GREEN + f"[*] Upstream:  {UPSTREAM_SERVICE_URL}")
    print(Fore.YELLOW + f"[*] Policy:    Role='{REQUIRED_ROLE}'")
    print(Style.RESET_ALL)

    # Keep the event loop running
    await site.start()
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Gateway shutting down...")
