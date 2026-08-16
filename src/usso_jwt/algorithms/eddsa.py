"""EdDSA (Ed25519) JWT algorithm and key types."""

from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from usso_jwt.utils import (
    as_jwk_dict,
    b64url_decode,
    b64url_encode,
    is_pem_key_material,
    jwk_b64_field,
)

from .base import AbstractKey, KeyAlgorithm, register_crypto_key_builder


class EdDSAAlgorithm(KeyAlgorithm):
    """EdDSA algorithm implementation (Ed25519)."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {
        "EDDSA",
        "ED25519",
        "EdDSA",
        "Ed25519",
    }

    @classmethod
    def load_key(
        cls,
        key: object,
        password: bytes | None = None,
    ) -> ed25519.Ed25519PrivateKey:
        """Load EdDSA private key from JWK dict or raw bytes.

        Args:
            key: Either a JWK dict or raw private key bytes
            password: Optional password for encrypted keys

        Returns:
            EdDSA private key object

        Raises:
            TypeError: If the argument type is invalid.

        """
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
        if isinstance(key, dict):
            return cls.load_jwk(as_jwk_dict(key))
        if isinstance(key, (str, bytes)) and is_pem_key_material(key):
            loaded = AbstractKey.load_cryptography_pem(key, password)
        elif isinstance(key, bytes):
            loaded = serialization.load_der_private_key(
                key,
                password=password,
                backend=default_backend(),
            )
        else:
            msg = f"Unsupported EdDSA key type: {type(key)}"
            raise TypeError(msg)

        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            msg = "Expected an Ed25519PrivateKey"
            raise TypeError(msg)
        return loaded

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> ed25519.Ed25519PrivateKey:
        """Load a key from JWK dict.

        Returns:
            The function result.

        """
        jwk = as_jwk_dict(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(
            b64url_decode(jwk_b64_field(jwk, "d")),
        )

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: object,
        alg: str = "EdDSA",
        password: bytes | None = None,
    ) -> bytes:
        """Sign using EdDSA algorithm.

        Args:
            data: The data to sign
            key: Either a JWK dict or raw private key bytes
            alg: The signing algorithm to use (must be "EdDSA")
            password: Optional password for encrypted keys

        Returns:
            The signature

        Raises:
            ValueError: If the value is invalid or unsupported.

        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            msg = f"Unsupported EdDSA algorithm: {alg}"
            raise ValueError(msg)

        privkey = cls.load_key(key, password)
        return privkey.sign(data)

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: object,
        alg: str = "EdDSA",
        **kwargs: object,
    ) -> bool:
        """Verify EdDSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or raw public key bytes
            alg: The signing algorithm used (must be "EdDSA")
            **kwargs: Optional extras

        Returns:
            True if signature is valid, False otherwise

        Raises:
            TypeError: If the argument type is invalid.
            ValueError: If the value is invalid or unsupported.

        """
        del kwargs
        if alg not in cls.SUPPORTED_ALGORITHMS:
            msg = f"Unsupported EdDSA algorithm: {alg}"
            raise ValueError(msg)

        if isinstance(key, dict):
            jwk = as_jwk_dict(key)
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(
                b64url_decode(jwk_b64_field(jwk, "x")),
            )
        elif isinstance(key, bytes):
            loaded = serialization.load_der_public_key(
                key,
                backend=default_backend(),
            )
            if not isinstance(loaded, ed25519.Ed25519PublicKey):
                msg = "Expected an Ed25519PublicKey"
                raise TypeError(msg)
            pubkey = loaded
        elif isinstance(key, ed25519.Ed25519PublicKey):
            pubkey = key
        else:
            msg = f"Unsupported EdDSA verify key type: {type(key)}"
            raise TypeError(msg)

        try:
            pubkey.verify(signature, data)
        except Exception:
            return False
        return True


class EdDSAKey(AbstractKey):
    """EdDSA key implementation."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {
        "EDDSA",
        "ED25519",
        "EdDSA",
        "Ed25519",
    }

    def __init__(
        self,
        *,
        key: ed25519.Ed25519PrivateKey,
        algorithm: str = "EdDSA",
    ) -> None:
        """Initialize an EdDSA key wrapper."""
        self._key = key
        self.algorithm = algorithm

    @property
    def key(self) -> ed25519.Ed25519PrivateKey:
        """Underlying Ed25519 private key.

        Returns:
            The function result.

        """
        return self._key

    @classmethod
    def generate(cls, **kwargs: object) -> "EdDSAKey":
        """Generate a new EdDSA key.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        algorithm = kwargs.get("algorithm", "EdDSA")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        return EdDSAKey(
            key=ed25519.Ed25519PrivateKey.generate(),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> "EdDSAKey":
        """Load a key from JWK dict.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        jwk = as_jwk_dict(key)
        algorithm = jwk.get("alg", "EdDSA")
        if not isinstance(algorithm, str):
            msg = "JWK field 'alg' must be str"
            raise TypeError(msg)
        return EdDSAKey(
            key=EdDSAAlgorithm.load_jwk(jwk),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "EdDSAKey":
        """Load a key from PEM.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        algorithm = kwargs.get("algorithm", "EdDSA")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        loaded = cls.load_cryptography_pem(key, password)
        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            msg = "Expected an Ed25519PrivateKey"
            raise TypeError(msg)
        return EdDSAKey(key=loaded, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "EdDSAKey":
        """Load a key from DER.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        algorithm = kwargs.get("algorithm", "EdDSA")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        loaded = cls.load_cryptography_der(key, password)
        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            msg = "Expected an Ed25519PrivateKey"
            raise TypeError(msg)
        return EdDSAKey(key=loaded, algorithm=algorithm)

    def jwk(self, kid: str | None = None) -> dict:
        """Get the JWK for the key.

        Returns:
            The function result.

        """
        public_key = self.key.public_key()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(public_key.public_bytes_raw()),
            "alg": "EdDSA",
            "use": "sig",
            "kid": kid or self.kid,
        }

    def public_key(self) -> ed25519.Ed25519PublicKey:
        """Get the public key.

        Returns:
            The function result.

        """
        return self.key.public_key()

    @property
    def type(self) -> str:
        """Key type identifier for EdDSA keys.

        Returns:
            The function result.

        """
        return "EdDSA"

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key.

        Returns:
            The function result.

        """
        return EdDSAAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key.

        Returns:
            The function result.

        """
        return EdDSAAlgorithm.verify(
            data=data,
            signature=signature,
            key=self.public_der(),
            alg=self.algorithm,
        )


def _build_eddsa_key(
    loaded: PrivateKeyTypes,
    algorithm: str | None,
) -> EdDSAKey:
    """Build an EdDSAKey from a cryptography private key.

    Returns:
        An EdDSAKey wrapping ``loaded``.

    Raises:
        TypeError: If ``loaded`` is not an Ed25519 private key.

    """
    if not isinstance(loaded, ed25519.Ed25519PrivateKey):
        msg = "Expected an Ed25519PrivateKey"
        raise TypeError(msg)
    return EdDSAKey(key=loaded, algorithm=algorithm or "EdDSA")


register_crypto_key_builder(ed25519.Ed25519PrivateKey, _build_eddsa_key)
