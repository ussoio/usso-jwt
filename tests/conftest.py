"""Shared pytest fixtures for JWT testing."""

import time

import pytest

from src.usso_jwt.algorithms import AbstractKey, EdDSAKey


@pytest.fixture
def test_key() -> AbstractKey:
    return EdDSAKey.generate()


@pytest.fixture
def test_valid_payload() -> dict:
    """Create a test JWT payload."""
    now = int(time.time())
    return {
        "token_type": "access",
        "sub": "1234567890",
        "name": "John Doe",
        "aud": "test",
        "iss": "test",
        "iat": now - 600,
        "exp": now + 600,
        "acr": "pass",
    }


@pytest.fixture
def test_expired_payload() -> dict:
    """Create a test JWT payload with an expired timestamp."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": now - 7200,
        "exp": now - 3600,
    }


@pytest.fixture
def test_future_payload() -> dict:
    """Create a test JWT payload with an expired timestamp."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": now + 3600,
        "exp": now + 7200,
    }


@pytest.fixture
def test_future_nbf_payload() -> dict:
    """Create a test JWT payload with an expired timestamp."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "nbf": now + 3600,
        "iat": now,
        "exp": now + 7200,
    }


@pytest.fixture
def test_header(test_key: AbstractKey) -> dict:
    """Create a test JWT header."""
    return {
        "alg": test_key.algorithm,
        "typ": "JWT",
    }
