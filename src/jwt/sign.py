import base64
import time

import json_advanced as json

from .algorithms import get_algorithm


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_jwt_header(alg: str, kid: str | None = None, **kwargs) -> dict:
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header.update(kwargs)
    return header


def sign_jwt_parts(
    header: dict,
    payload: dict,
    key: dict | bytes,
    alg: str,
    password: bytes | None = None,
) -> str:
    """Sign JWT parts using the specified algorithm."""
    # Prepare signing input
    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Get algorithm and sign
    algorithm = get_algorithm(alg)
    signature = algorithm.sign(signing_input, key, alg, password)

    # Return complete JWT
    signature_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def sign_jwt(
    payload: dict,
    key: dict | bytes,
    alg: str,
    kid: str | None = None,
    exp: int | None = None,
    nbf: int | None = None,
    iat: int | None = None,
    password: bytes | None = None,
) -> str:
    """
    Sign a JWT token with the given payload and key.

    Args:
        payload: The JWT payload
        key: The signing key (JWK dict or raw key bytes)
        alg: The signing algorithm to use
        kid: Optional key ID
        exp: Optional expiration time (seconds since epoch)
        nbf: Optional not-before time (seconds since epoch)
        iat: Optional issued-at time (seconds since epoch)
        password: Optional password for encrypted keys

    Returns:
        The signed JWT token
    """
    now = int(time.time())

    # Add standard claims if provided
    if exp is not None:
        payload["exp"] = exp
    if nbf is not None:
        payload["nbf"] = nbf
    if iat is not None:
        payload["iat"] = iat
    elif "iat" not in payload:
        payload["iat"] = now

    header = create_jwt_header(alg, kid)
    return sign_jwt_parts(header, payload, key, alg, password)
