"""PKCE (RFC 7636): code_verifier и code_challenge по методу S256."""

import base64
import hashlib
import secrets

CODE_CHALLENGE_METHOD = "S256"


def generate_code_verifier() -> str:
    # 64 случайных байта дают 86 символов base64url, в пределах 43-128 из RFC 7636.
    return secrets.token_urlsafe(64)


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
