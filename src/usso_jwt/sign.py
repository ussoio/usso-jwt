import json_advanced as json
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .algorithms import get_algorithm
from .utils import b64url_encode


def create_jwt_header(alg: str, kid: str | None = None, **kwargs) -> dict:
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header.update(kwargs)
    return header


def sign_jwt_parts(
    header: dict,
    payload: dict,
    key: (
        dict
        | bytes
        | rsa.RSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
    ),
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
    signature = algorithm.sign(
        data=signing_input,
        key=key,
        alg=alg,
        password=password,
    )
    return signature


def generate_jwt(
    header: dict,
    payload: dict,
    key: dict | bytes,
    alg: str,
    password: bytes | None = None,
) -> str:
    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signature = sign_jwt_parts(header, payload, key, alg, password)

    # Return complete JWT
    signature_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"
