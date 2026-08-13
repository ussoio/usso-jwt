import hashlib
from abc import ABC, abstractmethod
from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from ..utils import b64url_encode, jwk_str_field

AsymmetricPublicKey = (
    RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey
)
AsymmetricPrivateKey = (
    RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey
)


def convert_key_to_jwk(key: bytes) -> dict[str, object]:
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
    if isinstance(public_key, EllipticCurvePublicKey):
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
    if isinstance(public_key, Ed25519PublicKey):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(public_key.public_bytes_raw()),
        }
    raise TypeError("Unsupported algorithm")


def convert_jwk_to_pem(key: dict[str, object]) -> bytes:
    abstract_key = AbstractKey.load_jwk(key)
    return abstract_key.public_pem()


class KeyAlgorithm(ABC):
    """Abstract base class for JWT algorithms."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]]

    @classmethod
    @abstractmethod
    def load_key(
        cls,
        key: object,
        password: bytes | None = None,
    ) -> object:
        """Load key from JWK dict, raw bytes, or cryptography key object."""

    @classmethod
    @abstractmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: object,
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
        key: object,
        alg: str,
        **kwargs: object,
    ) -> bool:
        """Verify signature using the specified algorithm."""


class AbstractKey(ABC):
    """Abstract base class for keys."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]]
    algorithm: str

    @property
    @abstractmethod
    def key(self) -> bytes | AsymmetricPrivateKey:
        """Underlying key material."""

    @classmethod
    @abstractmethod
    def generate(cls, **kwargs: object) -> "AbstractKey":
        """Generate a key."""

    @classmethod
    def generate_algorithm(cls, alg: str, **kwargs: object) -> "AbstractKey":
        """Generate a random key for the given algorithm."""
        for child in cls.__subclasses__():
            if alg in child.SUPPORTED_ALGORITHMS:
                return child.generate(**kwargs)

        raise ValueError(f"Unsupported algorithm: {alg}")

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> "AbstractKey":
        """Load a key from JWK dict."""
        if "alg" not in key:
            raise ValueError("Missing algorithm in JWK")
        alg = jwk_str_field(key, "alg")
        for child in cls.__subclasses__():
            if alg in child.SUPPORTED_ALGORITHMS:
                return child.load_jwk(key)

        raise ValueError(f"Unsupported algorithm: {alg}")

    @staticmethod
    def load_cryptography_pem(
        key: bytes, password: bytes | None = None
    ) -> PrivateKeyTypes:
        """Load a cryptography private key from PEM bytes."""
        return serialization.load_pem_private_key(
            key, password=password, backend=default_backend()
        )

    @staticmethod
    def load_cryptography_der(
        key: bytes, password: bytes | None = None
    ) -> PrivateKeyTypes:
        """Load a cryptography private key from DER bytes."""
        return serialization.load_der_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def from_cryptography_key(
        cls,
        loaded: PrivateKeyTypes,
        algorithm: str | None = None,
    ) -> "AbstractKey":
        """Wrap a cryptography private key in the matching AbstractKey."""
        # Local imports avoid circular dependencies at module load time.
        from .ecdsa import ECDSAKey
        from .eddsa import EdDSAKey
        from .rsa import RSAKey

        if isinstance(loaded, RSAPrivateKey):
            return RSAKey(key=loaded, algorithm=algorithm or "RS256")
        if isinstance(loaded, EllipticCurvePrivateKey):
            return ECDSAKey(key=loaded, algorithm=algorithm or "ES256")
        if isinstance(loaded, Ed25519PrivateKey):
            return EdDSAKey(key=loaded, algorithm=algorithm or "EdDSA")
        raise TypeError(f"Unsupported private key type: {type(loaded)}")

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "AbstractKey":
        """Load a key from PEM."""
        del kwargs
        loaded = cls.load_cryptography_pem(key, password)
        return cls.from_cryptography_key(loaded)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "AbstractKey":
        """Load a key from DER."""
        del kwargs
        loaded = cls.load_cryptography_der(key, password)
        return cls.from_cryptography_key(loaded)

    @classmethod
    def load(
        cls, key: object, password: bytes | None = None
    ) -> "AbstractKey":
        """Load a key from JWK dict or PEM."""
        if isinstance(key, dict):
            return cls.load_jwk({str(k): v for k, v in key.items()})
        if isinstance(key, bytes):
            return cls.load_der(key, password)

        raise ValueError("Invalid key data.")

    @abstractmethod
    def public_key(self) -> bytes | AsymmetricPublicKey:
        """Get the public key."""

    @abstractmethod
    def jwk(self, kid: str | None = None) -> dict[str, object]:
        """Get the JWK for the key."""

    def private_pem(self, password: bytes | None = None) -> bytes:
        """Get the private PEM for the key."""
        private_key = self.key
        if isinstance(
            private_key,
            (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey),
        ):
            return private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                (
                    serialization.NoEncryption()
                    if password is None
                    else serialization.BestAvailableEncryption(password)
                ),
            )
        raise TypeError("Octet keys do not support PEM private encoding")

    def private_der(self, password: bytes | None = None) -> bytes:
        """Get the private DER for the key."""
        private_key = self.key
        if isinstance(
            private_key,
            (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey),
        ):
            return private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                (
                    serialization.NoEncryption()
                    if password is None
                    else serialization.BestAvailableEncryption(password)
                ),
            )
        raise TypeError("Octet keys do not support DER private encoding")

    def public_pem(self) -> bytes:
        """Get the public PEM for the key."""
        private_key = self.key
        if isinstance(
            private_key,
            (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey),
        ):
            return private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        raise TypeError("Octet keys do not support PEM public encoding")

    def public_der(self) -> bytes:
        """Get the public DER for the key."""
        private_key = self.key
        if isinstance(
            private_key,
            (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey),
        ):
            return private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        raise TypeError("Octet keys do not support DER public encoding")

    @property
    @abstractmethod
    def type(self) -> str:
        """Get the type of the key."""

    @property
    def kid(self) -> str:
        """Get the key ID for the key."""
        return hashlib.sha256(self.public_der()).hexdigest()
