import base64
from typing import Dict, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .base import Algorithm


class ECDSAAlgorithm(Algorithm):
    """ECDSA algorithm implementation (ES256, ES384, ES512)."""

    SUPPORTED_ALGORITHMS = {
        "ES256": hashes.SHA256,
        "ES384": hashes.SHA384,
        "ES512": hashes.SHA512,
    }

    @classmethod
    def load_key(
        cls, key: Union[Dict, bytes], password: bytes | None = None
    ) -> ec.EllipticCurvePrivateKey:
        """
        Load ECDSA key from JWK or PEM.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            password: Optional password for encrypted PEM keys

        Returns:
            The ECDSA private key
        """
        if isinstance(key, dict):
            # Add padding back to base64url
            padding = 4 - (len(key["x"]) % 4)
            if padding != 4:
                key["x"] += "=" * padding
            x = int.from_bytes(base64.urlsafe_b64decode(key["x"]), "big")

            padding = 4 - (len(key["y"]) % 4)
            if padding != 4:
                key["y"] += "=" * padding
            y = int.from_bytes(base64.urlsafe_b64decode(key["y"]), "big")

            padding = 4 - (len(key["d"]) % 4)
            if padding != 4:
                key["d"] += "=" * padding
            d = int.from_bytes(base64.urlsafe_b64decode(key["d"]), "big")

            curve = {
                "P-256": ec.SECP256R1,
                "P-384": ec.SECP384R1,
                "P-521": ec.SECP521R1,
            }[key["crv"]]()

            private_numbers = ec.EllipticCurvePrivateNumbers(
                private_value=d,
                public_numbers=ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve),
            )
            return private_numbers.private_key()
        else:
            return serialization.load_pem_private_key(
                key,
                password=password,
            )

    @classmethod
    def sign(
        cls,
        signing_input: bytes,
        key: dict | bytes,
        alg: str,
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

        privkey = cls.load_key(key, password)

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
        alg: str,
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
            x = int.from_bytes(base64.urlsafe_b64decode(key["x"]), "big")
            y = int.from_bytes(base64.urlsafe_b64decode(key["y"]), "big")
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
