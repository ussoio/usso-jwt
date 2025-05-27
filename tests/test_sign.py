import json_advanced as json
from src.usso_jwt import sign, verify
from src.usso_jwt.algorithms import EdDSAKey, RSAKey, ECDSAKey

import pytest
from src.usso_jwt.core import b64url_encode


@pytest.fixture
def test_key():
    return EdDSAKey.generate()
    # return RSAKey.generate(algorithm="PS256", key_size=2048)
    # return ECDSAKey.generate(algorithm="ES256")


@pytest.fixture
def test_header(test_key: RSAKey) -> dict:
    return {
        "alg": test_key.algorithm,
        "typ": "JWT",
    }


def test_sign_verify(test_valid_payload: dict, test_header: dict, test_key: RSAKey):
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
