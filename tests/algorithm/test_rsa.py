"""Tests for RSA algorithm."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.usso_jwt.algorithms import RSAAlgorithm, RSAKey


def test_rsa_load_key_from_jwk(rsa_jwk: dict | bytes):
    """Test loading RSA key from JWK."""
    key = RSAAlgorithm.load_key(rsa_jwk)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_rsa_load_key_from_der(rsa_private_key: rsa.RSAPrivateKey):
    """Test loading RSA key from PEM."""
    der = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = RSAAlgorithm.load_key(der)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_rsa_sign_verify(rsa_jwk: dict | bytes):
    """Test RSA signing and verification."""
    data = b"test"

    # Test RS256
    signature = RSAAlgorithm.sign(data=data, key=rsa_jwk, alg="RS256")
    assert isinstance(signature, bytes)
    assert RSAAlgorithm.verify(
        data=data, signature=signature, key=rsa_jwk, alg="RS256"
    )

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not RSAAlgorithm.verify(
        data=data, signature=invalid_signature, key=rsa_jwk, alg="RS256"
    )


def test_rsa_unsupported_algorithm():
    """Test RSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported RSA algorithm: RS128"):
        RSAAlgorithm.sign(data=b"test", key={}, alg="RS128")


def test_rsa_all_algorithms(rsa_jwk: dict | bytes):
    """Test all supported RSA algorithms."""
    signing_input = b"test"

    for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
        rsa_jwk["alg"] = alg
        signature = RSAAlgorithm.sign(data=signing_input, key=rsa_jwk, alg=alg)
        assert RSAAlgorithm.verify(
            data=signing_input, signature=signature, key=rsa_jwk, alg=alg
        )


def test_rsa_key_generate():
    """Test RSA key generation."""
    key = RSAKey.generate(algorithm="RS256")
    assert key.jwk()["alg"] == "RS256"
    assert key.jwk()["kty"] == "RSA"
    assert key.jwk()["e"] is not None
    assert key.jwk()["n"] is not None
    assert key.jwk().get("d") is None
    assert key.jwk().get("p") is None
    assert key.jwk().get("q") is None
    assert key.jwk().get("dp") is None
    assert key.jwk().get("dq") is None
    assert key.jwk().get("qi") is None


def test_rsa_key_load_jwk(rsa_jwk: dict | bytes):
    """Test RSA key loading from JWK."""
    key = RSAKey.load_jwk(rsa_jwk)
    for k, v in key.jwk().items():
        assert rsa_jwk[k] == v, f"Key {k} mismatch"


def test_rsa_key_load_pem(rsa_private_key: rsa.RSAPrivateKey):
    """Test RSA key loading from PEM."""
    der = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            b"password"
        ),
    )
    key = RSAKey.load_der(der, algorithm="RS256", password=b"password")
    assert key.jwk()["alg"] == "RS256"
    assert key.jwk()["kty"] == "RSA"
    assert key.jwk()["e"] is not None
    assert key.jwk()["n"] is not None
    assert key.jwk().get("d") is None


def test_rsa_key_sign_verify(rsa_jwk: dict | bytes):
    """Test RSA key signing and verification."""
    key = RSAKey.generate(algorithm="RS256")
    signature = key.sign(data=b"test")
    assert key.verify(data=b"test", signature=signature)


def test_rsa_key_type(rsa_jwk: dict | bytes):
    """Test RSA key type."""
    key = RSAKey.load_jwk(rsa_jwk)
    assert key.type == "RSA"


@pytest.fixture
def test_key() -> RSAKey:
    return RSAKey.generate()


@pytest.fixture
def test_token(test_valid_payload: dict, test_header: dict, test_key: RSAKey):
    from src.usso_jwt import sign

    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    return jwt


def test_pem_key(test_token: str, test_key: RSAKey):
    from src.usso_jwt import schemas

    jwt_obj = schemas.JWT(
        token=test_token,
        config=schemas.JWTConfig(key=test_key.public_pem()),
    )
    assert jwt_obj.verify()
