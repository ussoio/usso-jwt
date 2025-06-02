import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from ..utils import b64url_decode, b64url_encode
from .base import AbstractKey, KeyAlgorithm


class HMACAlgorithm(KeyAlgorithm):
    """HMAC algorithm implementation (HS256, HS384, HS512)."""

    SUPPORTED_ALGORITHMS = {
        "HS256": hashes.SHA256,
        "HS384": hashes.SHA384,
        "HS512": hashes.SHA512,
    }

    @staticmethod
    def load_key(key: dict | bytes, password: bytes | None = None) -> bytes:
        """
        Load HMAC key from JWK dict or raw bytes.

        Args:
            key: Either a JWK dict or raw key bytes
            password: Optional password for encrypted keys

        Returns:
            HMAC key bytes
        """
        if isinstance(key, dict):
            return b64url_decode(key["k"])
        return key

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: dict | bytes,
        alg: str = "HS256",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using HMAC algorithms.

        Args:
            data: The data to sign
            key: Either a JWK dict or raw key bytes
            alg: The signing algorithm to use (HS256, HS384, HS512)
            password: Optional password for encrypted keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported HMAC algorithm: {alg}")

        key_bytes = cls.load_key(key, password)
        h = hmac.HMAC(
            key_bytes,
            cls.SUPPORTED_ALGORITHMS[alg](),
            backend=default_backend(),
        )
        h.update(data)
        return h.finalize()

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str = "HS256",
        password: bytes | None = None,
    ) -> bool:
        """
        Verify HMAC signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or raw key bytes
            alg: The signing algorithm used (HS256, HS384, HS512)
            password: Optional password for encrypted keys

        Returns:
            True if signature is valid, False otherwise
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported HMAC algorithm: {alg}")

        key_bytes = cls.load_key(key, password)
        h = hmac.HMAC(
            key_bytes,
            cls.SUPPORTED_ALGORITHMS[alg](),
            backend=default_backend(),
        )
        h.update(data)
        try:
            h.verify(signature)
            return True
        except Exception:
            return False


class HMACKey(AbstractKey):
    """HMAC key implementation."""

    def __init__(self, *, key: bytes, algorithm: str = "HS256"):
        self.key = key
        self.algorithm = algorithm

    @classmethod
    def generate(
        cls,
        *,
        algorithm: str = "HS256",
        key_size: int = 32,
    ) -> "HMACKey":
        """Generate a new HMAC key."""
        return cls(
            key=os.urandom(key_size),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict) -> "HMACKey":
        """Load a key from JWK dict."""
        algorithm = key.get("alg", "HS256")
        return cls(
            key=b64url_decode(key["k"]),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "HS256",
    ) -> "HMACKey":
        """Load a key from PEM."""
        key = super().load_pem(key, password)
        return cls(key=key, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "HS256",
    ) -> "HMACKey":
        """Load a key from DER."""
        key = super().load_der(key, password)
        return cls(key=key, algorithm=algorithm)

    def public_key(self) -> bytes:
        """Get the public key."""
        return self.key

    @property
    def jwk(self) -> dict:
        """Get the JWK for the key."""
        return {  # type: ignore
            "kty": "oct",
            "alg": self.algorithm,
            "k": b64url_encode(self.key),
        }

    @property
    def type(self) -> str:
        """Get the type of the key."""
        return "HMAC"

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return len(self.key)

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key."""
        return HMACAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key."""
        return HMACAlgorithm.verify(
            data=data, signature=signature, key=self.key, alg=self.algorithm
        )
