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


def create_jwt_header(
    alg: str, kid: str | None = None, **kwargs: object
) -> dict:
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header.update(kwargs)
    return header


def sign_jwt_parts(
    *,
    key: PrivateKey,
    alg: str,
    signing_input: str | bytes | None = None,
    header: dict | None = None,
    payload: dict | None = None,
    password: bytes | None = None,
) -> bytes:
    """Sign JWT parts using the specified algorithm."""
    # Prepare signing input
    if header is None and payload is None and signing_input is None:
        raise ValueError(
            "Either header, payload, or signing_input must be provided",
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
    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = sign_jwt_parts(
        key=key,
        alg=alg,
        signing_input=signing_input.encode(),
        password=password,
    )

    # Return complete JWT
    signature_b64 = b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"
