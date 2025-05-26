import json
import time

import httpx
from cachetools import TTLCache, cached

from .algorithms import get_algorithm
from .exceptions import (
    JWKNotFoundError,
    JWTExpiredError,
    JWTInvalidFormatError,
    JWTInvalidSignatureError,
    JWTIssuedInFutureError,
    JWTNotValidYetError,
)


def extract_jwt_parts(token: str) -> tuple[dict, dict, bytes, bytes]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(signature_b64)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        return header, payload, signature, signing_input
    except (ValueError, json.JSONDecodeError) as e:
        raise JWTInvalidFormatError(f"Invalid JWT format: {str(e)}")


@cached(cache=TTLCache(maxsize=1000, ttl=3600))
def fetch_jwk(kid: str, jwks_url: str) -> dict | None:
    jwks = httpx.get(jwks_url).json()
    for key in jwks["keys"]:
        if key["kid"] == kid:
            return key
    raise JWKNotFoundError(f"JWK with kid '{kid}' not found")


def verify_temporal_claims(payload: dict):
    now = int(time.time())
    if "exp" in payload and now >= payload["exp"]:
        raise JWTExpiredError("Token expired")
    if "nbf" in payload and now < payload["nbf"]:
        raise JWTNotValidYetError("Token not valid yet (nbf)")
    if "iat" in payload and now < payload["iat"] - 60:
        raise JWTIssuedInFutureError("Token issued in the future (iat)")


def verify_signature(
    alg: str, key: dict, signing_input: bytes, signature: bytes
) -> bool:
    """
    Verify a JWT signature using the specified algorithm and key.

    Args:
        alg: The algorithm used for signing
        key: The verification key (JWK dict)
        signing_input: The data that was signed
        signature: The signature to verify

    Returns:
        bool: True if the signature is valid, False otherwise

    Raises:
        JWTInvalidSignatureError: If the signature verification fails
    """
    algorithm = get_algorithm(alg)
    if not algorithm.verify(signing_input, key, signature):
        raise JWTInvalidSignatureError("Invalid signature")
    return True
