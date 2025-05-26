"""Shared pytest fixtures for JWT testing."""

import base64
from typing import Dict

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def b64url_encode(data: bytes) -> str:
    """Base64url encode bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Base64url decode string."""
    # Add padding back
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


@pytest.fixture
def hmac_key() -> bytes:
    """Generate a test HMAC key."""
    return b"test_hmac_key_32_bytes_long!!"


@pytest.fixture
def hmac_jwk(hmac_key: bytes) -> Dict:
    """Create a JWK for HMAC key."""
    return {
        "kty": "oct",
        "k": b64url_encode(hmac_key),
        "alg": "HS256",
        "use": "sig",
    }


@pytest.fixture
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a test RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture
def rsa_jwk(rsa_private_key: rsa.RSAPrivateKey) -> Dict:
    """Create a JWK for RSA key."""
    public_numbers = rsa_private_key.public_key().public_numbers()
    private_numbers = rsa_private_key.private_numbers()

    return {
        "kty": "RSA",
        "n": b64url_encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        ),
        "e": b64url_encode(
            public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
        ),
        "d": b64url_encode(
            private_numbers.d.to_bytes((private_numbers.d.bit_length() + 7) // 8, "big")
        ),
        "p": b64url_encode(
            private_numbers.p.to_bytes((private_numbers.p.bit_length() + 7) // 8, "big")
        ),
        "q": b64url_encode(
            private_numbers.q.to_bytes((private_numbers.q.bit_length() + 7) // 8, "big")
        ),
        "dp": b64url_encode(
            private_numbers.dmp1.to_bytes(
                (private_numbers.dmp1.bit_length() + 7) // 8, "big"
            )
        ),
        "dq": b64url_encode(
            private_numbers.dmq1.to_bytes(
                (private_numbers.dmq1.bit_length() + 7) // 8, "big"
            )
        ),
        "qi": b64url_encode(
            private_numbers.iqmp.to_bytes(
                (private_numbers.iqmp.bit_length() + 7) // 8, "big"
            )
        ),
        "alg": "RS256",
        "use": "sig",
    }


@pytest.fixture
def ecdsa_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a test ECDSA private key."""
    return ec.generate_private_key(
        curve=ec.SECP256R1(),
    )


@pytest.fixture
def ecdsa_jwk(ecdsa_private_key: ec.EllipticCurvePrivateKey) -> Dict:
    """Create a JWK for ECDSA key."""
    public_numbers = ecdsa_private_key.public_key().public_numbers()
    private_numbers = ecdsa_private_key.private_numbers()

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(
            public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, "big")
        ),
        "y": b64url_encode(
            public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, "big")
        ),
        "d": b64url_encode(
            private_numbers.private_value.to_bytes(
                (private_numbers.private_value.bit_length() + 7) // 8, "big"
            )
        ),
        "alg": "ES256",
        "use": "sig",
    }


@pytest.fixture
def eddsa_private_key() -> ed25519.Ed25519PrivateKey:
    """Generate a test EdDSA private key."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def eddsa_jwk(eddsa_private_key: ed25519.Ed25519PrivateKey) -> Dict:
    """Create a JWK for EdDSA key."""
    public_key = eddsa_private_key.public_key()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode(public_key.public_bytes_raw()),
        "d": b64url_encode(eddsa_private_key.private_bytes_raw()),
        "alg": "EdDSA",
        "use": "sig",
    }


@pytest.fixture
def test_payload() -> Dict:
    """Create a test JWT payload."""
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022,
        "exp": 1516242622,
    }


@pytest.fixture
def test_header() -> Dict:
    """Create a test JWT header."""
    return {
        "alg": "HS256",
        "typ": "JWT",
    }
