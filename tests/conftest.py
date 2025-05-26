"""Shared pytest fixtures for JWT testing."""

import base64

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
    return b64url_decode(s)


@pytest.fixture
def hmac_key() -> bytes:
    """Generate a test HMAC key."""
    return b"test_key_32_bytes_long_for_hmac!"


@pytest.fixture
def hmac_jwk(hmac_key: bytes) -> dict:
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
def rsa_jwk(rsa_private_key: rsa.RSAPrivateKey) -> dict:
    """Generate a RSA JWK."""
    numbers = rsa_private_key.private_numbers()
    return {
        "kty": "RSA",
        "alg": "RS256",
        "n": b64url_encode(numbers.public_numbers.n.to_bytes(256, "big")),
        "e": b64url_encode(numbers.public_numbers.e.to_bytes(3, "big")),
        "d": b64url_encode(numbers.d.to_bytes(256, "big")),
        "p": b64url_encode(numbers.p.to_bytes(128, "big")),
        "q": b64url_encode(numbers.q.to_bytes(128, "big")),
        "dp": b64url_encode(numbers.dmp1.to_bytes(128, "big")),
        "dq": b64url_encode(numbers.dmq1.to_bytes(128, "big")),
        "qi": b64url_encode(numbers.iqmp.to_bytes(128, "big")),
    }


@pytest.fixture
def ecdsa_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a test ECDSA private key."""
    return ec.generate_private_key(
        curve=ec.SECP256R1(),
    )


@pytest.fixture
def ecdsa_jwk(ecdsa_private_key: ec.EllipticCurvePrivateKey) -> dict:
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
def ecdsa_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a ECDSA private key."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def ecdsa_jwk_256(ecdsa_private_key: ec.EllipticCurvePrivateKey) -> dict:
    """Generate a ECDSA JWK for P-256 curve."""
    numbers = ecdsa_private_key.private_numbers()
    return {
        "kty": "EC",
        "alg": "ES256",
        "crv": "P-256",
        "x": b64url_encode(numbers.public_numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.public_numbers.y.to_bytes(32, "big")),
        "d": b64url_encode(numbers.private_value.to_bytes(32, "big")),
    }


@pytest.fixture
def ecdsa_jwk_384() -> dict:
    """Generate a ECDSA JWK for P-384 curve."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    numbers = private_key.private_numbers()
    return {
        "kty": "EC",
        "alg": "ES384",
        "crv": "P-384",
        "x": b64url_encode(numbers.public_numbers.x.to_bytes(48, "big")),
        "y": b64url_encode(numbers.public_numbers.y.to_bytes(48, "big")),
        "d": b64url_encode(numbers.private_value.to_bytes(48, "big")),
    }


@pytest.fixture
def ecdsa_jwk_512() -> dict:
    """Generate a ECDSA JWK for P-521 curve."""
    private_key = ec.generate_private_key(ec.SECP521R1())
    numbers = private_key.private_numbers()
    return {
        "kty": "EC",
        "alg": "ES512",
        "crv": "P-521",
        "x": b64url_encode(numbers.public_numbers.x.to_bytes(66, "big")),
        "y": b64url_encode(numbers.public_numbers.y.to_bytes(66, "big")),
        "d": b64url_encode(numbers.private_value.to_bytes(66, "big")),
    }


@pytest.fixture
def eddsa_private_key() -> ed25519.Ed25519PrivateKey:
    """Generate a test EdDSA private key."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def eddsa_jwk(eddsa_private_key: ed25519.Ed25519PrivateKey) -> dict:
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
def test_payload() -> dict:
    """Create a test JWT payload."""
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022,
        "exp": 1516242622,
    }


@pytest.fixture
def test_header() -> dict:
    """Create a test JWT header."""
    return {
        "alg": "HS256",
        "typ": "JWT",
    }
