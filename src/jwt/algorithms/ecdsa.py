from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..core import b64url_decode
from .base import Algorithm


class ECDSAAlgorithm(Algorithm):
    """ECDSA algorithm implementation (ES256, ES384, ES512)."""

    SUPPORTED_ALGORITHMS = {
        "ES256": ec.SECP256R1,
        "ES384": ec.SECP384R1,
        "ES512": ec.SECP521R1,
    }

    @classmethod
    def load_key(
        cls, key: dict | bytes, alg: str, password: bytes | None = None
    ) -> ec.EllipticCurvePrivateKey:
        """
        Load ECDSA private key from JWK dict or PEM bytes.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            alg: The signing algorithm (ES256, ES384, ES512)
            password: Optional password for encrypted PEM keys

        Returns:
            ECDSA private key object
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported ECDSA algorithm: {alg}")

        if isinstance(key, dict):
            # Load from JWK
            curve = cls.SUPPORTED_ALGORITHMS[alg]()
            x = int.from_bytes(b64url_decode(key["x"]), "big")
            y = int.from_bytes(b64url_decode(key["y"]), "big")
            d = int.from_bytes(b64url_decode(key["d"]), "big")

            return ec.EllipticCurvePrivateNumbers(
                d, ec.EllipticCurvePublicNumbers(x, y, curve)
            ).private_key(default_backend())
        else:
            # Load from PEM
            return serialization.load_pem_private_key(
                key, password=password, backend=default_backend()
            )

    @classmethod
    def sign(
        cls,
        signing_input: bytes,
        key: dict | bytes,
        alg: str = "ES256",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using ECDSA algorithms.

        Args:
            signing_input: The data to sign
            key: Either a JWK dict or PEM-encoded private key bytes
            alg: The signing algorithm to use (ES256, ES384, ES512)
            password: Optional password for encrypted PEM keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported ECDSA algorithm: {alg}")

        privkey = cls.load_key(key, alg, password)

        # Sign and format signature
        signature = privkey.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        size = (privkey.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    @classmethod
    def verify(
        cls,
        signing_input: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str = "ES256",
        password: bytes | None = None,
    ) -> bool:
        """
        Verify ECDSA signature.

        Args:
            signing_input: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or PEM-encoded public key bytes
            alg: The signing algorithm used (ES256, ES384, ES512)
            password: Optional password for encrypted PEM keys

        Returns:
            True if signature is valid, False otherwise
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported ECDSA algorithm: {alg}")

        if isinstance(key, dict):
            # Load from JWK
            curve = cls.SUPPORTED_ALGORITHMS[alg]()
            x = int.from_bytes(b64url_decode(key["x"]), "big")
            y = int.from_bytes(b64url_decode(key["y"]), "big")
            pubkey = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(
                default_backend()
            )
        else:
            # Load from PEM
            pubkey = serialization.load_pem_public_key(key, backend=default_backend())

        try:
            # Reconstruct signature from r and s components
            size = (pubkey.curve.key_size + 7) // 8
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            sig = utils.encode_dss_signature(r, s)

            pubkey.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
