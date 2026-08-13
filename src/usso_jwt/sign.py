"""JWT header construction and signing helpers."""

from dataclasses import dataclass

import json_advanced as json
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .algorithms import get_algorithm
from .algorithms.base import AbstractKey
from .utils import b64url_encode

PrivateKey = (
    dict
    | bytes
    | AbstractKey
    | rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
)


@dataclass(frozen=True, slots=True)
class SignInput:
    """Optional inputs for :func:`sign_jwt_parts`."""

    signing_input: str | bytes | None = None
    header: dict | None = None
    payload: dict | None = None
    password: bytes | None = None


def create_jwt_header(
    alg: str,
    kid: str | None = None,
    **kwargs: object,
) -> dict[str, object]:
    """Build a JWT header with algorithm and optional key id.

    Returns:
        The function result.

    """
    header: dict[str, object] = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header.update(kwargs)
    return header


def sign_jwt_parts(
    *,
    key: PrivateKey,
    alg: str,
    parts: SignInput | None = None,
) -> bytes:
    """Sign JWT parts using the specified algorithm.

    Returns:
        The function result.

    Raises:
        ValueError: If the value is invalid or unsupported.

    """
    options = parts or SignInput()
    signing_input = options.signing_input
    header = options.header
    payload = options.payload
    password = options.password

    # Prepare signing input
    if header is None and payload is None and signing_input is None:
        msg = "Either header, payload, or signing_input must be provided"
        raise ValueError(
            msg,
        )
    if signing_input is None:
        header_b64 = b64url_encode(json.dumps(header).encode())
        payload_b64 = b64url_encode(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
    elif isinstance(signing_input, str):
        signing_input = signing_input.encode()

    sign_key: object = key.key if isinstance(key, AbstractKey) else key

    # Get algorithm and sign
    algorithm = get_algorithm(alg)
    return algorithm.sign(
        data=signing_input,
        key=sign_key,
        alg=alg,
        password=password,
    )


def generate_jwt(
    header: dict,
    payload: dict,
    key: dict | bytes,
    alg: str,
    password: bytes | None = None,
) -> str:
    """Create a compact JWT from header, payload, and key.

    Returns:
        The function result.

    """
    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = sign_jwt_parts(
        key=key,
        alg=alg,
        parts=SignInput(
            signing_input=signing_input.encode(),
            password=password,
        ),
    )

    # Return complete JWT
    signature_b64 = b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"
