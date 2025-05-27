import hashlib
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


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
    def load_pem(cls, key: bytes, password: bytes | None = None) -> "AbstractKey":
        """Load a key from PEM."""
        return serialization.load_pem_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def load_der(cls, key: bytes, password: bytes | None = None) -> "AbstractKey":
        """Load a key from DER."""
        return serialization.load_der_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def load(cls, key: dict | bytes, password: bytes | None = None) -> "AbstractKey":
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

    def public_key(self):
        """Get the public key."""
        return self.key.public_key()

    @property
    @abstractmethod
    def type(self) -> str:
        """Get the type of the key."""

    @property
    def kid(self) -> str:
        """Get the key ID for the key."""
        kid = hashlib.sha256(self.public_der()).hexdigest()
        return kid
