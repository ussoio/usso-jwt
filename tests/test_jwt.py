"""Tests for JWT schema helpers."""

import time

import pytest
from pydantic import BaseModel

from usso_jwt import algorithms, exceptions, schemas, sign


@pytest.fixture
def test_key() -> algorithms.AbstractKey:
    """EdDSA test key fixture.

    Returns:
        The function result.

    """
    return algorithms.EdDSAKey.generate()


@pytest.fixture
def test_token(
    test_valid_payload: dict,
    test_header: dict,
    test_key: algorithms.AbstractKey,
) -> str:
    """Signed JWT string fixture.

    Returns:
        The function result.

    """
    return sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )


def test_jwt(
    test_token: str,
    test_key: algorithms.AbstractKey,
    test_header: dict,
    test_valid_payload: dict,
) -> None:
    """Verify JWT header, payload, and signature."""
    jwt_obj = schemas.JWT(
        token=test_token,
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    assert jwt_obj.header == test_header
    assert jwt_obj.payload == test_valid_payload
    assert jwt_obj.verify()


def test_invalid_token(
    test_token: str,
    test_key: algorithms.AbstractKey,
) -> None:
    """Reject tokens with invalid format."""
    invalid_token = f"{test_token[:-2]}.{test_token[-1]}"
    jwt_obj = schemas.JWT(
        token=invalid_token,
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    with pytest.raises(exceptions.JWTInvalidFormatError):
        jwt_obj.verify()


def test_payload_class(
    test_token: str,
    test_key: algorithms.AbstractKey,
    test_valid_payload: dict,
) -> None:
    """Parse payload into a Pydantic model."""

    class TestPayload(BaseModel):
        sub: str
        name: str
        iat: int
        exp: int

    jwt_obj = schemas.JWT(
        token=test_token,
        config=schemas.JWTConfig(key=test_key.jwk()),
        payload_class=TestPayload,
    )

    assert jwt_obj.payload == TestPayload(
        **test_valid_payload,
    )


def test_not_verified_payload(
    test_token: str,
    test_key: algorithms.AbstractKey,
) -> None:
    """Reject truncated tokens on verify."""
    jwt = schemas.JWT(
        token=test_token[:-1],
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    with pytest.raises(exceptions.JWTInvalidFormatError):
        jwt.verify()


def test_no_key(test_token: str) -> None:
    """Require a key when constructing JWT."""
    with pytest.raises(ValueError, match="Either jwks_url or key"):
        schemas.JWT(token=test_token)


def test_is_temporally_valid_true(
    test_token: str,
    test_key: algorithms.AbstractKey,
) -> None:
    """Accept tokens within validity window."""
    jwt_obj = schemas.JWT(
        token=test_token,
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    assert jwt_obj.is_temporally_valid() is True
    assert jwt_obj.is_expired is False
    assert str(jwt_obj) == test_token


def test_is_temporally_valid_false_missing_claims(
    test_header: dict,
    test_key: algorithms.AbstractKey,
) -> None:
    """Allow payloads missing temporal claims."""
    # Payload missing temporal claims
    payload = {"sub": "user1", "name": "Test User"}
    token = sign.generate_jwt(
        header=test_header,
        payload=payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    assert jwt_obj.is_temporally_valid()


def test_is_temporally_valid_false_invalid_claims(
    test_header: dict,
    test_key: algorithms.AbstractKey,
) -> None:
    """Reject temporally expired payloads."""
    # Payload with expired exp claim
    payload = {
        "sub": "user1",
        "name": "Test User",
        "exp": int(time.time()) - 100,
    }
    token = sign.generate_jwt(
        header=test_header,
        payload=payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=schemas.JWTConfig(key=test_key.jwk()),
    )
    assert jwt_obj.is_temporally_valid() is False
