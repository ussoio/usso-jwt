"""Tests for ECDSA algorithm."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.usso_jwt.algorithms import ECDSAAlgorithm, ECDSAKey


def test_ecdsa_load_key_from_jwk(ecdsa_jwk: dict | bytes):
    """Test loading ECDSA key from JWK."""
    key = ECDSAAlgorithm.load_key(ecdsa_jwk, "ES256")
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_ecdsa_load_key_from_pem(ecdsa_private_key: ec.EllipticCurvePrivateKey):
    """Test loading ECDSA key from PEM."""
    der = ecdsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = ECDSAAlgorithm.load_key(der, "ES256")
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_ecdsa_sign_verify(ecdsa_jwk: dict | bytes):
    """Test ECDSA signing and verification."""
    signing_input = b"test"

    # Test ES256
    signature = ECDSAAlgorithm.sign(data=signing_input, key=ecdsa_jwk, alg="ES256")
    assert isinstance(signature, bytes)
    assert ECDSAAlgorithm.verify(data=signing_input, signature=signature, key=ecdsa_jwk, alg="ES256")

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not ECDSAAlgorithm.verify(
        data=signing_input, signature=invalid_signature, key=ecdsa_jwk, alg="ES256"
    )


def test_ecdsa_unsupported_algorithm():
    """Test ECDSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported ECDSA algorithm: ES128"):
        ECDSAAlgorithm.sign(data=b"test", key={}, alg="ES128")


def test_ecdsa_all_algorithms(
    ecdsa_jwk_256: dict | bytes,
    ecdsa_jwk_384: dict | bytes,
    ecdsa_jwk_512: dict | bytes,
):
    """Test all supported ECDSA algorithms."""
    signing_input = b"test"

    for alg, jwk in [
        ("ES256", ecdsa_jwk_256),
        ("ES384", ecdsa_jwk_384),
        ("ES512", ecdsa_jwk_512),
    ]:
        signature = ECDSAAlgorithm.sign(data=signing_input, key=jwk, alg=alg)
        assert ECDSAAlgorithm.verify(data=signing_input, signature=signature, key=jwk, alg=alg)


def test_ecdsa_key_generate():
    """Test ECDSA key generation."""
    key = ECDSAKey.generate(algorithm="ES256")
    assert key.jwk()["alg"] == "ES256"
    assert key.jwk()["crv"] == "P-256"
    assert key.jwk()["kty"] == "EC"
    assert key.jwk()["x"] is not None
    assert key.jwk()["y"] is not None
    assert key.jwk().get("d") is None


def test_ecdsa_key_load_jwk(ecdsa_jwk_256: dict | bytes):
    """Test ECDSA key loading from JWK."""
    key = ECDSAKey.load_jwk(ecdsa_jwk_256)
    for k, v in key.jwk().items():
        assert ecdsa_jwk_256[k] == v


def test_ecdsa_key_load_pem(ecdsa_private_key: ec.EllipticCurvePrivateKey):
    """Test ECDSA key loading from PEM."""
    pem = ecdsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    )
    key = ECDSAKey.load_pem(pem, algorithm="ES256", password=b"password")
    assert key.jwk()["alg"] == "ES256"
    assert key.jwk()["crv"] == "P-256"
    assert key.jwk()["kty"] == "EC"
    assert key.jwk()["x"] is not None
    assert key.jwk()["y"] is not None


def test_ecdsa_key_sign_verify(ecdsa_jwk_256: dict | bytes):
    """Test ECDSA key signing and verification."""
    key = ECDSAKey.generate(algorithm="ES256")
    signature = key.sign(data=b"test")
    assert key.verify(data=b"test", signature=signature)


def test_ecdsa_key_type(ecdsa_jwk_256: dict | bytes):
    """Test ECDSA key type."""
    key = ECDSAKey.load_jwk(ecdsa_jwk_256)
    assert key.type == "ECDSA"
