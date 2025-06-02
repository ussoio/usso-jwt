from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..utils import b64url_decode, b64url_encode
from .base import AbstractKey, KeyAlgorithm


class ECDSAAlgorithm(KeyAlgorithm):
    """ECDSA algorithm implementation (ES256, ES384, ES512)."""

    SUPPORTED_ALGORITHMS = {
        "ES256": ec.SECP256R1,
        "ES384": ec.SECP384R1,
        "ES512": ec.SECP521R1,
    }

    @classmethod
    def load_key(
        cls,
        key: dict | bytes | ec.EllipticCurvePrivateKey,
        alg: str,
        password: bytes | None = None,
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

        if isinstance(key, ec.EllipticCurvePrivateKey):
            return key
        if isinstance(key, dict):
            # Load from JWK
            curve = cls.SUPPORTED_ALGORITHMS[alg]()
            x = int.from_bytes(b64url_decode(key["x"]), "big")
            y = int.from_bytes(b64url_decode(key["y"]), "big")
            d = int.from_bytes(b64url_decode(key["d"]), "big")

            return ec.EllipticCurvePrivateNumbers(
                d, ec.EllipticCurvePublicNumbers(x, y, curve)
            ).private_key(default_backend())
        # Load from DER
        return serialization.load_der_private_key(
            key, password=password, backend=default_backend()
        )

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: dict | bytes | ec.EllipticCurvePrivateKey,
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
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        size = (privkey.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str = "ES256",
    ) -> bool:
        """
        Verify ECDSA signature.

        Args:
            data: The data that was signed
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
            # Load from DER
            pubkey = serialization.load_der_public_key(
                key, backend=default_backend()
            )

        try:
            # Reconstruct signature from r and s components
            size = (pubkey.curve.key_size + 7) // 8
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            sig = utils.encode_dss_signature(r, s)

            pubkey.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class ECDSAKey(AbstractKey):
    """ECDSA key implementation."""

    def __init__(
        self, *, key: ec.EllipticCurvePrivateKey, algorithm: str = "ES256"
    ):
        self.key = key
        self.algorithm = algorithm

    @classmethod
    def generate(
        cls,
        *,
        algorithm: str = "ES256",
    ) -> "ECDSAKey":
        """Generate a new ECDSA key."""
        if algorithm == "ES256":
            curve = ec.SECP256R1()
        elif algorithm == "ES384":
            curve = ec.SECP384R1()
        elif algorithm == "ES512":
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported ECDSA algorithm: {algorithm}")

        return ECDSAKey(
            key=ec.generate_private_key(curve, default_backend()),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict) -> "ECDSAKey":
        """Load a key from JWK dict."""
        algorithm = key.get("alg", "ES256")
        return ECDSAKey(
            key=ec.EllipticCurvePrivateNumbers(
                int.from_bytes(b64url_decode(key["d"]), "big"),
                ec.EllipticCurvePublicNumbers(
                    int.from_bytes(b64url_decode(key["x"]), "big"),
                    int.from_bytes(b64url_decode(key["y"]), "big"),
                    ec.SECP256R1(),
                ),
            ).private_key(default_backend()),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "ES256",
    ) -> "ECDSAKey":
        """Load a key from PEM."""
        key = super().load_pem(key, password)
        return ECDSAKey(key=key, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "ES256",
    ) -> "ECDSAKey":
        """Load a key from DER."""
        key = super().load_der(key, password)
        return ECDSAKey(key=key, algorithm=algorithm)

    def jwk(self) -> dict:
        """Get the JWK for the key."""
        public_key = self.key.public_key()
        CURVE_NAME_TO_JWK_CRV = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        return {
            "kty": "EC",
            "alg": self.algorithm,
            "crv": CURVE_NAME_TO_JWK_CRV[public_key.curve.name],
            "x": b64url_encode(
                public_key.public_numbers().x.to_bytes(
                    public_key.curve.key_size // 8, "big"
                )
            ),
            "y": b64url_encode(
                public_key.public_numbers().y.to_bytes(
                    public_key.curve.key_size // 8, "big"
                )
            ),
        }

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get the public key."""
        return self.key.public_key()

    @property
    def type(self) -> str:
        """Get the type of the key."""
        return "ECDSA"

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key."""
        return ECDSAAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key."""
        return ECDSAAlgorithm.verify(
            data=data,
            signature=signature,
            key=self.public_der(),
            alg=self.algorithm,
        )
