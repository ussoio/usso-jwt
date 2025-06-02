import json
import time

import httpx
from cachetools import TTLCache, cached

from .algorithms import get_algorithm
from .exceptions import (
    JWKNotFoundError,
    JWTExpiredError,
    JWTInvalidACRError,
    JWTInvalidAudienceError,
    JWTInvalidFormatError,
    JWTInvalidIssuerError,
    JWTInvalidSignatureError,
    JWTIssuedInFutureError,
    JWTMissingAudienceError,
    JWTNotValidYetError,
)
from .utils import b64url_decode, b64url_encode


def extract_jwt_parts(token: str) -> tuple[dict, dict, bytes, bytes]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(signature_b64)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        return header, payload, signature, signing_input
    except (ValueError, json.JSONDecodeError) as e:
        raise JWTInvalidFormatError() from e


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


def verify_claims(
    *,
    payload: dict,
    expected_audience: str | list[str] | None = None,
    expected_acr: str | list[str] | None = None,
    expected_issuer: str | list[str] | None = None,
) -> bool:
    """
    Verify additional JWT claims like audience, acr, and issuer if they
    are present.

    Args:
        payload: The JWT payload
        expected_audience: The expected audience value(s) to validate against.
                           Can be a single string or list of strings.
                           If provided, the token MUST have an aud claim
                           that matches one of the expected values.
        expected_acr:      The expected acr value(s) to validate against.
                           Can be a single string or list of strings.
        expected_issuer:   The expected issuer value(s) to validate against.
                           Can be a single string or list of strings.

    Returns:
        bool: True if all claims are valid

    Raises:
        JWTInvalidAudienceError: If the audience claim is invalid
        JWTMissingAudienceError: If the audience claim is missing
                                 and expected_audience is provided
        JWTInvalidACRError: If the acr claim is invalid
        JWTInvalidIssuerError: If the issuer claim is invalid
    """
    # Handle audience validation
    if expected_audience is not None:
        if "aud" not in payload:
            raise JWTMissingAudienceError()
        if isinstance(expected_audience, str):
            expected_audience = [expected_audience]
        if payload["aud"] not in expected_audience:
            raise JWTInvalidAudienceError()

    # Handle ACR validation
    if "acr" in payload and expected_acr is not None:
        if isinstance(expected_acr, str):
            expected_acr = [expected_acr]
        if payload["acr"] not in expected_acr:
            raise JWTInvalidACRError()

    # Handle issuer validation
    if "iss" in payload and expected_issuer is not None:
        if isinstance(expected_issuer, str):
            expected_issuer = [expected_issuer]
        if payload["iss"] not in expected_issuer:
            raise JWTInvalidIssuerError()

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
    if not algorithm.verify(
        data=signing_input, signature=signature, key=key, alg=alg
    ):
        raise JWTInvalidSignatureError()
    return True


def verify_jwt(
    *,
    token: str,
    jwks_url: str = None,
    kid: str = None,
    jwk: dict | None = None,
    expected_audience: str | list[str] | None = None,
    expected_acr: str | list[str] | None = None,
    expected_issuer: str | list[str] | None = None,
) -> bool:
    header, payload, signature, signing_input = extract_jwt_parts(token)
    if jwk is None:
        jwk = fetch_jwk(jwks_url=jwks_url, kid=kid)

    if not verify_signature(
        alg=header["alg"], key=jwk, data=signing_input, signature=signature
    ):
        raise JWTInvalidSignatureError()

    verify_temporal_claims(payload=payload)
    verify_claims(
        payload=payload,
        expected_audience=expected_audience,
        expected_acr=expected_acr,
        expected_issuer=expected_issuer,
    )

    return True
