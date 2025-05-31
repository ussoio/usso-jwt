import pytest
from pydantic import BaseModel

from src.usso_jwt import algorithms, exceptions, jwt, sign


@pytest.fixture
def test_key() -> algorithms.AbstractKey:
    return algorithms.EdDSAKey.generate()


@pytest.fixture
def test_token(
    test_valid_payload: dict, test_header: dict, test_key: algorithms.AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    return jwt


def test_jwt(
    test_token: str,
    test_key: algorithms.AbstractKey,
    test_header: dict,
    test_valid_payload: dict,
):
    jwt_obj = jwt.JWT(
        token=test_token,
        key=test_key.jwk(),
    )
    assert jwt_obj.header == test_header
    assert jwt_obj.payload == test_valid_payload
    assert jwt_obj.verify()


def test_invalid_token(test_token: str, test_key: algorithms.AbstractKey):
    with pytest.raises(exceptions.JWTInvalidFormatError):
        invalid_token = f"{test_token[:-2]}.{test_token[-1]}"
        jwt_obj = jwt.JWT(
            token=invalid_token,
            key=test_key.jwk(),
        )
        jwt_obj.verify()


def test_payload_class(
    test_token: str, test_key: algorithms.AbstractKey, test_valid_payload: dict
):
    class TestPayload(BaseModel):
        sub: str
        name: str
        iat: int
        exp: int

    jwt_obj = jwt.JWT(
        token=test_token,
        key=test_key.jwk(),
        payload_class=TestPayload,
    )

    print(jwt_obj._parts[1])
    assert jwt_obj.payload == TestPayload(
        **test_valid_payload,
    )


def test_not_verified_payload(test_token: str, test_key: algorithms.AbstractKey):
    jwt_obj = jwt.JWT(
        token=test_token[:-1],
        key=test_key.jwk(),
    )
    with pytest.raises(exceptions.JWTInvalidFormatError):
        print(jwt_obj.token, jwt_obj.payload)


def test_no_key(test_token: str):
    with pytest.raises(ValueError):
        jwt_obj = jwt.JWT(
            token=test_token,
        )
        jwt_obj.verify()
