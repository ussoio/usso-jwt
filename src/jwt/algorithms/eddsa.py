from cryptography.hazmat.primitives.asymmetric import ed25519

from ..core import b64url_decode
from .base import Algorithm


class EdDSAAlgorithm(Algorithm):
    """EdDSA algorithm implementation (Ed25519)."""

    SUPPORTED_ALGORITHMS = {"EdDSA"}

    @staticmethod
    def load_key(
        key: dict | bytes, password: bytes | None = None
    ) -> ed25519.Ed25519PrivateKey:
        """
        Load EdDSA private key from JWK dict or raw bytes.

        Args:
            key: Either a JWK dict or raw private key bytes
            password: Optional password for encrypted keys

        Returns:
            EdDSA private key object
        """
        if isinstance(key, dict):
            return ed25519.Ed25519PrivateKey.from_private_bytes(b64url_decode(key["d"]))
        return ed25519.Ed25519PrivateKey.from_private_bytes(key)

    @classmethod
    def sign(
        cls,
        signing_input: bytes,
        key: dict | bytes,
        alg: str = "EdDSA",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using EdDSA algorithm.

        Args:
            signing_input: The data to sign
            key: Either a JWK dict or raw private key bytes
            alg: The signing algorithm to use (must be "EdDSA")
            password: Optional password for encrypted keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported EdDSA algorithm: {alg}")

        privkey = cls.load_key(key, password)
        return privkey.sign(signing_input)

    @classmethod
    def verify(
        cls,
        signing_input: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str = "EdDSA",
        password: bytes | None = None,
    ) -> bool:
        """
        Verify EdDSA signature.

        Args:
            signing_input: The data that was signed
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
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(key["x"]))
        else:
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(key)

        try:
            pubkey.verify(signature, signing_input)
            return True
        except Exception:
            return False
