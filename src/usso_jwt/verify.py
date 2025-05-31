import json
import time

import httpx
from cachetools import TTLCache, cached

from .algorithms import get_algorithm
from .core import b64url_decode, b64url_encode
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
        raise JWTInvalidFormatError()


@cached(cache=TTLCache(maxsize=1000, ttl=3600))
def fetch_jwk(*, jwks_url: str, kid: str) -> dict | None:
    jwks = httpx.get(jwks_url).json()
    for key in jwks["keys"]:
        if key["kid"] == kid:
            return key
    raise JWKNotFoundError()


def verify_temporal_claims(*, payload: dict):
    now = int(time.time())
    if "exp" in payload and now >= payload["exp"]:
        raise JWTExpiredError()
    if "nbf" in payload and now < payload["nbf"]:
        raise JWTNotValidYetError()
    if "iat" in payload and now < payload["iat"] - 60:
        raise JWTIssuedInFutureError()
    return True


def verify_signature(
    *, alg: str, key: dict, data: bytes | str | dict, signature: bytes
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
    if isinstance(data, dict):
        signing_input = b64url_encode(json.dumps(data)).encode()
    elif isinstance(data, str):
        signing_input = data.encode()
    else:
        signing_input = data

    algorithm = get_algorithm(alg)
    if not algorithm.verify(data=signing_input, signature=signature, key=key, alg=alg):
        raise JWTInvalidSignatureError()
    return True


def verify_jwt(
    *, token: str, jwks_url: str = None, kid: str = None, jwk: dict | None = None
) -> bool:
    header, payload, signature, signing_input = extract_jwt_parts(token)
    if jwk is None:
        jwk = fetch_jwk(jwks_url=jwks_url, kid=kid)

    if not verify_signature(
        alg=header["alg"], key=jwk, data=signing_input, signature=signature
    ):
        raise JWTInvalidSignatureError()

    return verify_temporal_claims(payload=payload)
