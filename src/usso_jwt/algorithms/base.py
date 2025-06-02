import hashlib
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ..utils import b64url_encode


def convert_key_to_jwk(key: bytes) -> dict:
    """Convert PEM to dict."""
    # Check if the key is not in PEM format (doesn't start with BEGIN)
    if not key.startswith(b"-----BEGIN"):
        return {
            "kty": "oct",
            "k": b64url_encode(key),
        }

    public_key = serialization.load_pem_public_key(
        key, backend=default_backend()
    )
    if isinstance(public_key, RSAPublicKey):
        return {
            "kty": "RSA",
            "n": b64url_encode(
                public_key.public_numbers().n.to_bytes(256, "big")
            ),
            "e": b64url_encode(
                public_key.public_numbers().e.to_bytes(256, "big")
            ),
        }
    elif isinstance(public_key, EllipticCurvePublicKey):
        return {
            "kty": "EC",
            "crv": public_key.curve.name,
            "x": b64url_encode(
                public_key.public_numbers().x.to_bytes(256, "big")
            ),
            "y": b64url_encode(
                public_key.public_numbers().y.to_bytes(256, "big")
            ),
        }
    elif isinstance(public_key, Ed25519PublicKey):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(public_key.public_bytes_raw()),
        }
    else:
        raise ValueError("Unsupported algorithm")


class KeyAlgorithm(ABC):
    """Abstract base class for JWT algorithms."""

    @property
    @abstractmethod
    def SUPPORTED_ALGORITHMS(self) -> set[str]:
        """Set of supported algorithms for this implementation."""

    @staticmethod
    @abstractmethod
    def load_key(key: dict | bytes, password: bytes | None = None):
        """Load key from JWK dict or raw bytes."""

    @classmethod
    @abstractmethod
    def sign(
        cls,
        *,
        data: bytes,
        key,
        alg: str,
        password: bytes | None = None,
    ) -> bytes:
        """Sign data using the specified algorithm."""

    @classmethod
    @abstractmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str,
        **kwargs,
    ) -> bool:
        """Verify signature using the specified algorithm."""


class AbstractKey(ABC):
    """Abstract base class for keys."""

    @classmethod
    @abstractmethod
    def generate(cls, **kwargs) -> "AbstractKey":
        """Generate a key."""

    @classmethod
    @abstractmethod
    def load_jwk(cls, key: dict) -> "AbstractKey":
        """Load a key from JWK dict."""

    @classmethod
    def load_pem(
        cls, key: bytes, password: bytes | None = None
    ) -> "AbstractKey":
        """Load a key from PEM."""
        return serialization.load_pem_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def load_der(
        cls, key: bytes, password: bytes | None = None
    ) -> "AbstractKey":
        """Load a key from DER."""
        return serialization.load_der_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def load(
        cls, key: dict | bytes, password: bytes | None = None
    ) -> "AbstractKey":
        """Load a key from JWK dict or PEM."""
        if isinstance(key, dict):
            return cls.load_jwk(key)
        if isinstance(key, bytes):
            return cls.load_der(key, password)

        raise ValueError("Invalid key data.")

    @abstractmethod
    def public_key(self):
        """Get the public key."""

    @abstractmethod
    def jwk(self) -> dict:
        """Get the JWK for the key."""

    def private_pem(self, password: bytes | None = None) -> bytes:
        """Get the private PEM for the key."""
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            (
                serialization.NoEncryption()
                if password is None
                else serialization.BestAvailableEncryption(password)
            ),
        )

    def private_der(self, password: bytes | None = None) -> bytes:
        """Get the private PEM for the key."""
        return self.key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            (
                serialization.NoEncryption()
                if password is None
                else serialization.BestAvailableEncryption(password)
            ),
        )

    def public_pem(self) -> bytes:
        """Get the public PEM for the key."""
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_der(self) -> bytes:
        """Get the public DER for the key."""
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    @abstractmethod
    def type(self) -> str:
        """Get the type of the key."""

    @property
    def kid(self) -> str:
        """Get the key ID for the key."""
        kid = hashlib.sha256(self.public_der()).hexdigest()
        return kid
