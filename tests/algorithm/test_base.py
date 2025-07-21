"""Tests for base algorithm."""

from src.usso_jwt.algorithms import AbstractKey, convert_jwk_to_pem


def test_load_jwt(rsa_jwk: dict | bytes) -> None:
    """Test loading RSA key from PEM."""

    key = AbstractKey.load(rsa_jwk)

    assert hasattr(key, "key")
    key = key.key
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_jwt_to_pem(rsa_jwk: dict | bytes) -> None:
    """Test loading RSA key from PEM."""

    key = AbstractKey.load(rsa_jwk)
    pem = convert_jwk_to_pem(rsa_jwk)
    assert pem == key.public_pem()
