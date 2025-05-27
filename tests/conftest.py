"""Shared pytest fixtures for JWT testing."""

import time

import pytest


@pytest.fixture
def test_valid_payload() -> dict:
    """Create a test JWT payload."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": now - 600,
        "exp": now + 600,
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
def test_header() -> dict:
    """Create a test JWT header."""
    return {
        "alg": "HS256",
        "typ": "JWT",
    }
