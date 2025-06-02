import json_advanced as json
import pytest

from src.usso_jwt import sign, verify
from src.usso_jwt.algorithms import AbstractKey
from src.usso_jwt.utils import b64url_encode


@pytest.fixture
def test_header(test_key: AbstractKey) -> dict:
    return sign.create_jwt_header(alg=test_key.algorithm, kid=test_key.kid)


def test_sign_verify(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    signature = sign.sign_jwt_parts(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    # print(signature, test_key.algorithm)
    # print(test_key.public_pem().decode())
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
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
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
    # assert verify.verify_temporal_claims(payload=payload)
    assert verify.verify_jwt(token=jwt, jwk=test_key.jwk())
