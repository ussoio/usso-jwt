"""Tests for base algorithm."""

from usso_jwt.algorithms import AbstractKey, convert_jwk_to_pem


def test_load_jwt(rsa_jwk: dict[str, object]) -> None:
    """Test loading RSA key from PEM."""
    loaded = AbstractKey.load(rsa_jwk)

    assert hasattr(loaded, "key")
    material = loaded.key
    assert hasattr(material, "sign")
    assert hasattr(material, "private_bytes")


def test_jwt_to_pem(rsa_jwk: dict[str, object]) -> None:
    """Test loading RSA key from PEM."""
    key = AbstractKey.load(rsa_jwk)
    pem = convert_jwk_to_pem(rsa_jwk)
    assert pem == key.public_pem()
