"""Tests for EdDSA algorithm."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.usso_jwt import schemas, sign
from src.usso_jwt.algorithms import EdDSAAlgorithm, EdDSAKey


def test_eddsa_load_key_from_jwk(eddsa_jwk: dict | bytes):
    """Test loading EdDSA key from JWK."""
    key = EdDSAAlgorithm.load_key(eddsa_jwk)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_eddsa_load_key_from_bytes(eddsa_private_key: ed25519.Ed25519PrivateKey):
    """Test loading EdDSA key from raw bytes."""
    key_bytes = eddsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = EdDSAAlgorithm.load_key(key_bytes)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_eddsa_sign_verify(eddsa_jwk: dict | bytes):
    """Test EdDSA signing and verification."""
    data = b"test"

    # Test EdDSA
    signature = EdDSAAlgorithm.sign(data=data, key=eddsa_jwk, alg="EdDSA")
    assert isinstance(signature, bytes)
    assert EdDSAAlgorithm.verify(
        data=data, signature=signature, key=eddsa_jwk, alg="EdDSA"
    )

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not EdDSAAlgorithm.verify(
        data=data, signature=invalid_signature, key=eddsa_jwk, alg="EdDSA"
    )


def test_eddsa_unsupported_algorithm():
    """Test EdDSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported EdDSA algorithm: Ed448"):
        EdDSAAlgorithm.sign(data=b"test", key={}, alg="Ed448")


def test_eddsa_key_generate():
    """Test EdDSA key generation."""
    key = EdDSAKey.generate(algorithm="EdDSA")
    assert key.jwk()["alg"] == "EdDSA"
    assert key.jwk()["crv"] == "Ed25519"
    assert key.jwk()["kty"] == "OKP"
    assert key.jwk()["x"] is not None
    assert key.jwk().get("d") is None


def test_eddsa_key_load_jwk(eddsa_jwk: dict | bytes):
    """Test EdDSA key loading from JWK."""
    key = EdDSAKey.load_jwk(eddsa_jwk)
    for k, v in key.jwk().items():
        assert eddsa_jwk[k] == v


def test_eddsa_key_load_pem(eddsa_private_key: ed25519.Ed25519PrivateKey):
    """Test EdDSA key loading from PEM."""
    der = eddsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    )
    key = EdDSAKey.load_der(der, algorithm="EdDSA", password=b"password")
    assert key.jwk()["alg"] == "EdDSA"
    assert key.jwk()["crv"] == "Ed25519"
    assert key.jwk()["kty"] == "OKP"
    assert key.jwk()["x"] is not None
    assert key.jwk().get("d") is None


def test_eddsa_key_sign_verify(eddsa_jwk: dict | bytes):
    """Test EdDSA key signing and verification."""
    key = EdDSAKey.generate(algorithm="EdDSA")
    signature = key.sign(data=b"test")
    assert key.verify(data=b"test", signature=signature)


def test_eddsa_key_type(eddsa_jwk: dict | bytes):
    """Test EdDSA key type."""
    key = EdDSAKey.load_jwk(eddsa_jwk)
    assert key.type == "EdDSA"


@pytest.fixture
def test_key() -> EdDSAKey:
    return EdDSAKey.generate()


@pytest.fixture
def test_token(test_valid_payload: dict, test_header: dict, test_key: EdDSAKey):
    from src.usso_jwt import sign

    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    return jwt


def test_pem_key(test_token: str, test_key: EdDSAKey):
    jwt_obj = schemas.JWT(
        token=test_token,
        config=schemas.JWTConfig(key=test_key.public_pem()),
    )
    assert jwt_obj.verify()


def test_ed25519_sign_verify():

    headers = {
        "alg": "Ed25519",
        "typ": "JWT",
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1717334400,
    }
    key = EdDSAKey.generate(algorithm="Ed25519")
    token = sign.generate_jwt(
        header=headers,
        payload=payload,
        key=key.private_der(),
        alg=key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=schemas.JWTConfig(key=key.public_pem()),
    )
    assert jwt_obj.verify()
