from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..utils import b64url_decode, b64url_encode
from .base import AbstractKey, KeyAlgorithm


class EdDSAAlgorithm(KeyAlgorithm):
    """EdDSA algorithm implementation (Ed25519)."""

    SUPPORTED_ALGORITHMS = {"EdDSA", "EDDSA", "Ed25519", "ED25519"}

    @staticmethod
    def load_key(
        key: dict | bytes | ed25519.Ed25519PrivateKey,
        password: bytes | None = None,
    ) -> ed25519.Ed25519PrivateKey:
        """
        Load EdDSA private key from JWK dict or raw bytes.

        Args:
            key: Either a JWK dict or raw private key bytes
            password: Optional password for encrypted keys

        Returns:
            EdDSA private key object
        """
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
        if isinstance(key, dict):
            return ed25519.Ed25519PrivateKey.from_private_bytes(
                b64url_decode(key["d"])
            )
        return serialization.load_der_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: dict | bytes | ed25519.Ed25519PrivateKey,
        alg: str = "EdDSA",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using EdDSA algorithm.

        Args:
            data: The data to sign
            key: Either a JWK dict or raw private key bytes
            alg: The signing algorithm to use (must be "EdDSA")
            password: Optional password for encrypted keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported EdDSA algorithm: {alg}")

        privkey = cls.load_key(key, password)
        return privkey.sign(data)

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: dict | bytes | ed25519.Ed25519PublicKey,
        alg: str = "EdDSA",
    ) -> bool:
        """
        Verify EdDSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or raw public key bytes
            alg: The signing algorithm used (must be "EdDSA")
            password: Optional password for encrypted keys

        Returns:
            True if signature is valid, False otherwise
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported EdDSA algorithm: {alg}")

        if isinstance(key, dict):
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(
                b64url_decode(key["x"])
            )
        else:
            pubkey = serialization.load_der_public_key(
                key, backend=default_backend()
            )

        try:
            pubkey.verify(signature, data)
            return True
        except Exception:
            return False


class EdDSAKey(AbstractKey):
    """EdDSA key implementation."""

    def __init__(
        self, *, key: ed25519.Ed25519PrivateKey, algorithm: str = "EdDSA"
    ):
        self.key = key
        self.algorithm = algorithm

    @classmethod
    def generate(
        cls,
        *,
        algorithm: str = "EdDSA",
    ) -> "EdDSAKey":
        """Generate a new EdDSA key."""
        return EdDSAKey(
            key=ed25519.Ed25519PrivateKey.generate(), algorithm=algorithm
        )

    @classmethod
    def load_jwk(cls, key: dict) -> "EdDSAKey":
        """Load a key from JWK dict."""
        algorithm = key.get("alg", "EdDSA")
        return EdDSAKey(
            key=ed25519.Ed25519PrivateKey.from_private_bytes(
                b64url_decode(key["d"])
            ),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "EdDSA",
    ) -> "EdDSAKey":
        """Load a key from PEM."""
        key = super().load_pem(key, password)
        return EdDSAKey(key=key, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "EdDSA",
    ) -> "EdDSAKey":
        """Load a key from DER."""
        key = super().load_der(key, password)
        return EdDSAKey(key=key, algorithm=algorithm)

    def jwk(self) -> dict:
        """Get the JWK for the key."""
        public_key = self.key.public_key()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(public_key.public_bytes_raw()),
            "alg": "EdDSA",
            "use": "sig",
        }

    def public_key(self) -> ed25519.Ed25519PublicKey:
        """Get the public key."""
        return self.key.public_key()

    @property
    def type(self) -> str:
        """Get the type of the key."""
        return "EdDSA"

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key."""
        return EdDSAAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key."""
        return EdDSAAlgorithm.verify(
            data=data,
            signature=signature,
            key=self.public_der(),
            alg=self.algorithm,
        )
