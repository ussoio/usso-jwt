"""Tests for JWT signing helpers."""

import json_advanced as json
import pytest

from usso_jwt import sign, verify
from usso_jwt.algorithms import AbstractKey
from usso_jwt.utils import b64url_encode


@pytest.fixture
def test_header(test_key: AbstractKey) -> dict:
    """JWT header fixture for the test key.

    Returns:
        The function result.

    """
    return sign.create_jwt_header(alg=test_key.algorithm, kid=test_key.kid)


def test_private_pem(
    test_key: AbstractKey,
    test_header: dict,
    test_valid_payload: dict,
) -> None:
    """Sign and verify using password-protected PEM."""
    pem = test_key.private_pem(password=b"123456")
    key = AbstractKey.load_pem(pem, password=b"123456")
    assert pem
    signature = sign.sign_jwt_parts(
        key=key,
        alg=test_key.algorithm,
        parts=sign.SignInput(header=test_header, payload=test_valid_payload),
    )
    assert signature is not None

    header_b64 = b64url_encode(json.dumps(test_header).encode())
    payload_b64 = b64url_encode(json.dumps(test_valid_payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    assert verify.verify_signature(
        alg=test_key.algorithm,
        key=test_key.public_der(),
        signature=signature,
        data=signing_input,
    )


def test_sign_verify(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Sign JWT parts and verify the signature."""
    signature = sign.sign_jwt_parts(
        key=test_key.private_der(),
        alg=test_key.algorithm,
        parts=sign.SignInput(header=test_header, payload=test_valid_payload),
    )
    header_b64 = b64url_encode(json.dumps(test_header).encode())
    payload_b64 = b64url_encode(json.dumps(test_valid_payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    assert signature is not None
    assert verify.verify_signature(
        alg=test_key.algorithm,
        key=test_key.public_der(),
        signature=signature,
        data=signing_input,
    )
    assert verify.verify_temporal_claims(payload=test_valid_payload)


def test_generate_jwt(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Generate a JWT and verify its parts."""
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    assert jwt is not None
    header, payload, signature, signing_input = verify.extract_jwt_parts(jwt)
    assert header == test_header
    assert payload == test_valid_payload
    assert signature is not None
    assert verify.verify_signature(
        alg=test_key.algorithm,
        key=test_key.public_der(),
        signature=signature,
        data=signing_input,
    )
    assert verify.verify_jwt(
        token=jwt,
        options=verify.VerifyOptions(jwk=test_key.jwk()),
    )
