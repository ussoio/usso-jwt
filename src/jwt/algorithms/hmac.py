import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from .base import Algorithm


class HMACAlgorithm(Algorithm):
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
            return base64.urlsafe_b64decode(key["k"])
        return key

    @classmethod
    def sign(
        cls,
        signing_input: bytes,
        key: dict | bytes,
        alg: str,
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using HMAC algorithms.

        Args:
            signing_input: The data to sign
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
            key_bytes, cls.SUPPORTED_ALGORITHMS[alg](), backend=default_backend()
        )
        h.update(signing_input)
        return h.finalize()

    @classmethod
    def verify(
        cls,
        signing_input: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str,
        password: bytes | None = None,
    ) -> bool:
        """
        Verify HMAC signature.

        Args:
            signing_input: The data that was signed
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
            key_bytes, cls.SUPPORTED_ALGORITHMS[alg](), backend=default_backend()
        )
        h.update(signing_input)
        try:
            h.verify(signature)
            return True
        except Exception:
            return False
