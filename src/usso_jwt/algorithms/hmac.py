from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from ..utils import (
    as_jwk_dict,
    b64url_decode,
    b64url_encode,
    jwk_b64_field,
    jwk_str_field,
)
from .base import AbstractKey, KeyAlgorithm


class HMACAlgorithm(KeyAlgorithm):
    """HMAC algorithm implementation (HS256, HS384, HS512)."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {"HS256", "HS384", "HS512"}
    _HASHES: ClassVar[dict[str, type[hashes.HashAlgorithm]]] = {
        "HS256": hashes.SHA256,
        "HS384": hashes.SHA384,
        "HS512": hashes.SHA512,
    }

    @classmethod
    def load_key(
        cls,
        key: object,
        password: bytes | None = None,
    ) -> bytes:
        """
        Load HMAC key from JWK dict or raw bytes.

        Args:
            key: Either a JWK dict or raw key bytes
            password: Optional password for encrypted keys

        Returns:
            HMAC key bytes
        """
        del password  # HMAC keys are not password-encrypted
        if isinstance(key, dict):
            return b64url_decode(jwk_b64_field(as_jwk_dict(key), "k"))
        if isinstance(key, bytes):
            return key
        raise TypeError(f"Unsupported HMAC key type: {type(key)}")

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: object,
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
            cls._HASHES[alg](),
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
        key: object,
        alg: str = "HS256",
        **kwargs: object,
    ) -> bool:
        """
        Verify HMAC signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or raw key bytes
            alg: The signing algorithm used (HS256, HS384, HS512)
            **kwargs: Optional extras (e.g. password)

        Returns:
            True if signature is valid, False otherwise
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported HMAC algorithm: {alg}")

        password = kwargs.get("password")
        password_bytes = password if isinstance(password, bytes) else None
        key_bytes = cls.load_key(key, password_bytes)
        h = hmac.HMAC(
            key_bytes,
            cls._HASHES[alg](),
            backend=default_backend(),
        )
        h.update(data)
        try:
            h.verify(signature)
        except Exception:
            return False

        return True


class HMACKey(AbstractKey):
    """HMAC key implementation."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {"HS256", "HS384", "HS512"}

    def __init__(self, *, key: bytes, algorithm: str = "HS256") -> None:
        self._key = key
        self.algorithm = algorithm

    @property
    def key(self) -> bytes:
        """Underlying HMAC key bytes."""
        return self._key

    @classmethod
    def generate(cls, **kwargs: object) -> "HMACKey":
        """Generate a new HMAC key."""
        import os

        algorithm = kwargs.get("algorithm", "HS256")
        key_size = kwargs.get("key_size", 32)
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        if not isinstance(key_size, int):
            raise TypeError("key_size must be an int")
        return cls(
            key=os.urandom(key_size),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> "HMACKey":
        """Load a key from JWK dict."""
        jwk = as_jwk_dict(key)
        algorithm = jwk_str_field(jwk, "alg", "HS256")
        return cls(
            key=b64url_decode(jwk_b64_field(jwk, "k")),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "HMACKey":
        """Load a raw octet key (PEM private keys are not used for HMAC)."""
        del password
        algorithm = kwargs.get("algorithm", "HS256")
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        return cls(key=key, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "HMACKey":
        """Load a raw octet key (DER private keys are not used for HMAC)."""
        del password
        algorithm = kwargs.get("algorithm", "HS256")
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        return cls(key=key, algorithm=algorithm)

    def public_key(self) -> bytes:
        """Get the public key."""
        return self.key

    def jwk(self, kid: str | None = None) -> dict:
        """Get the JWK for the key."""
        return {
            "kty": "oct",
            "alg": self.algorithm,
            "k": b64url_encode(self.key),
            "use": "sig",
            "kid": kid or self.kid,
        }

    @property
    def type(self) -> str:
        """Get the type of the key."""
        return "HMAC"

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return len(self.key)

    @property
    def kid(self) -> str:
        """Get the key ID for the key."""
        import hashlib

        return hashlib.sha256(self.key).hexdigest()

    def private_pem(self, password: bytes | None = None) -> bytes:
        """Return the raw key bytes (HMAC has no PEM private key)."""
        del password
        return self.key

    def private_der(self, password: bytes | None = None) -> bytes:
        """Return the raw key bytes (HMAC has no DER private key)."""
        del password
        return self.key

    def public_pem(self) -> bytes:
        """Return the raw key bytes (HMAC has no PEM public key)."""
        return self.key

    def public_der(self) -> bytes:
        """Return the raw key bytes (HMAC has no DER public key)."""
        return self.key

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key."""
        return HMACAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key."""
        return HMACAlgorithm.verify(
            data=data, signature=signature, key=self.key, alg=self.algorithm
        )
