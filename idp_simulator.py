import argparse
import datetime
import os

import jwt
from colorama import Fore, Style, init

init(autoreset=True)

# Must match the gateway's local demonstration secret.
JWT_SECRET = os.getenv(
    "ZERO_TRUST_JWT_SECRET", "local-demo-only-secret-change-before-shared-use"
)
ALGORITHM = "HS256"


def generate_token(username: str, role: str) -> str:
    """Generates a signed JWT for the given user and role."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + datetime.timedelta(hours=1),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


if __name__ == "__main__":
    print(Fore.BLUE + "--- Identity Provider Simulator ---")

    parser = argparse.ArgumentParser(description="Generate JWT for Zero Trust Testing")
    parser.add_argument("--user", default="engineer_osman", help="Username")
    parser.add_argument("--role", default="admin", help="Role (admin/guest)")

    args = parser.parse_args()

    token = generate_token(args.user, args.role)

    print(Fore.WHITE + f"User: {args.user}")
    print(Fore.WHITE + f"Role: {args.role}")
    print(Fore.GREEN + Style.BRIGHT + "\n[ACCESS TOKEN]:")
    print(token)
    print(Fore.YELLOW + "\nUsage:")
    print(f'curl -H "Authorization: Bearer {token}" http://localhost:9000/')
