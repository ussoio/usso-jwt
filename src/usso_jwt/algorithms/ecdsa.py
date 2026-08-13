"""ECDSA (ES256/ES384/ES512) JWT algorithm and key types."""

from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from usso_jwt.utils import (
    as_jwk_dict,
    b64url_encode,
    jwk_int_field,
    jwk_str_field,
)

from .base import AbstractKey, KeyAlgorithm, register_crypto_key_builder


class ECDSAAlgorithm(KeyAlgorithm):
    """ECDSA algorithm implementation (ES256, ES384, ES512)."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {"ES256", "ES384", "ES512"}
    _CURVES: ClassVar[dict[str, type[ec.EllipticCurve]]] = {
        "ES256": ec.SECP256R1,
        "ES384": ec.SECP384R1,
        "ES512": ec.SECP521R1,
    }
    _HASHES: ClassVar[dict[str, type[hashes.HashAlgorithm]]] = {
        "ES256": hashes.SHA256,
        "ES384": hashes.SHA384,
        "ES512": hashes.SHA512,
    }

    @classmethod
    def load_key(
        cls,
        key: object,
        password: bytes | None = None,
    ) -> ec.EllipticCurvePrivateKey:
        """Load ECDSA private key from JWK dict or PEM bytes.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            password: Optional password for encrypted PEM keys

        Returns:
            ECDSA private key object

        Raises:
            TypeError: If the argument type is invalid.

        """
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return key
        if isinstance(key, dict):
            return cls.load_jwk(as_jwk_dict(key))
        if isinstance(key, bytes) and key.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_private_key(
                key,
                password=password,
                backend=default_backend(),
            )
        elif isinstance(key, bytes):
            loaded = serialization.load_der_private_key(
                key,
                password=password,
                backend=default_backend(),
            )
        else:
            msg = f"Unsupported ECDSA key type: {type(key)}"
            raise TypeError(msg)

        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            msg = "Expected an EllipticCurvePrivateKey"
            raise TypeError(msg)
        return loaded

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> ec.EllipticCurvePrivateKey:
        """Load a key from JWK dict.

        Returns:
            The function result.

        Raises:
            ValueError: If the value is invalid or unsupported.

        """
        jwk = as_jwk_dict(key)
        alg = jwk_str_field(jwk, "alg", "ES256")
        if alg not in cls._CURVES:
            msg = f"Unsupported ECDSA algorithm: {alg}"
            raise ValueError(msg)
        return ec.EllipticCurvePrivateNumbers(
            jwk_int_field(jwk, "d"),
            ec.EllipticCurvePublicNumbers(
                jwk_int_field(jwk, "x"),
                jwk_int_field(jwk, "y"),
                cls._CURVES[alg](),
            ),
        ).private_key(default_backend())

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: object,
        alg: str = "ES256",
        password: bytes | None = None,
    ) -> bytes:
        """Sign using ECDSA algorithms.

        Args:
            data: The data to sign
            key: Either a JWK dict or PEM-encoded private key bytes
            alg: The signing algorithm to use (ES256, ES384, ES512)
            password: Optional password for encrypted PEM keys

        Returns:
            The signature

        Raises:
            ValueError: If the value is invalid or unsupported.

        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            msg = f"Unsupported ECDSA algorithm: {alg}"
            raise ValueError(msg)

        privkey = cls.load_key(key, password)

        # Sign and format signature
        signature = privkey.sign(data, ec.ECDSA(cls._HASHES[alg]()))
        r, s = utils.decode_dss_signature(signature)
        size = (privkey.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: object,
        alg: str = "ES256",
        **kwargs: object,
    ) -> bool:
        """Verify ECDSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or PEM-encoded public key bytes
            alg: The signing algorithm used (ES256, ES384, ES512)
            **kwargs: Optional extras

        Returns:
            True if signature is valid, False otherwise

        Raises:
            TypeError: If the argument type is invalid.
            ValueError: If the value is invalid or unsupported.

        """
        del kwargs
        if alg not in cls.SUPPORTED_ALGORITHMS:
            msg = f"Unsupported ECDSA algorithm: {alg}"
            raise ValueError(msg)

        if isinstance(key, dict):
            jwk = as_jwk_dict(key)
            curve = cls._CURVES[alg]()
            x = jwk_int_field(jwk, "x")
            y = jwk_int_field(jwk, "y")
            pubkey = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(
                default_backend(),
            )
        elif isinstance(key, bytes):
            loaded = serialization.load_der_public_key(
                key,
                backend=default_backend(),
            )
            if not isinstance(loaded, ec.EllipticCurvePublicKey):
                msg = "Expected an EllipticCurvePublicKey"
                raise TypeError(msg)
            pubkey = loaded
        elif isinstance(key, ec.EllipticCurvePublicKey):
            pubkey = key
        else:
            msg = f"Unsupported ECDSA verify key type: {type(key)}"
            raise TypeError(msg)

        try:
            # Reconstruct signature from r and s components
            size = (pubkey.curve.key_size + 7) // 8
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            sig = utils.encode_dss_signature(r, s)

            pubkey.verify(sig, data, ec.ECDSA(cls._HASHES[alg]()))
        except Exception:
            return False
        return True


class ECDSAKey(AbstractKey):
    """ECDSA key implementation."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {"ES256", "ES384", "ES512"}

    def __init__(
        self,
        *,
        key: ec.EllipticCurvePrivateKey,
        algorithm: str = "ES256",
    ) -> None:
        """Initialize an ECDSA key wrapper."""
        self._key = key
        self.algorithm = algorithm

    @property
    def key(self) -> ec.EllipticCurvePrivateKey:
        """Underlying ECDSA private key.

        Returns:
            The function result.

        """
        return self._key

    @classmethod
    def generate(cls, **kwargs: object) -> "ECDSAKey":
        """Generate a new ECDSA key.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.
            ValueError: If the value is invalid or unsupported.

        """
        algorithm = kwargs.get("algorithm", "ES256")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        if algorithm == "ES256":
            curve: ec.EllipticCurve = ec.SECP256R1()
        elif algorithm == "ES384":
            curve = ec.SECP384R1()
        elif algorithm == "ES512":
            curve = ec.SECP521R1()
        else:
            msg = f"Unsupported ECDSA algorithm: {algorithm}"
            raise ValueError(msg)

        return ECDSAKey(
            key=ec.generate_private_key(curve, default_backend()),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> "ECDSAKey":
        """Load a key from JWK dict.

        Returns:
            The function result.

        """
        jwk = as_jwk_dict(key)
        algorithm = jwk_str_field(jwk, "alg", "ES256")
        return ECDSAKey(
            key=ECDSAAlgorithm.load_jwk(jwk),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "ECDSAKey":
        """Load a key from PEM.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        algorithm = kwargs.get("algorithm", "ES256")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        loaded = cls.load_cryptography_pem(key, password)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            msg = "Expected an EllipticCurvePrivateKey"
            raise TypeError(msg)
        return ECDSAKey(key=loaded, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "ECDSAKey":
        """Load a key from DER.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        algorithm = kwargs.get("algorithm", "ES256")
        if not isinstance(algorithm, str):
            msg = "algorithm must be a string"
            raise TypeError(msg)
        loaded = cls.load_cryptography_der(key, password)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            msg = "Expected an EllipticCurvePrivateKey"
            raise TypeError(msg)
        return ECDSAKey(key=loaded, algorithm=algorithm)

    def jwk(self, kid: str | None = None) -> dict:
        """Get the JWK for the key.

        Returns:
            The function result.

        """
        public_key = self.key.public_key()
        curve_name_to_jwk_crv = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        return {
            "kty": "EC",
            "alg": self.algorithm,
            "crv": curve_name_to_jwk_crv[public_key.curve.name],
            "x": b64url_encode(
                public_key.public_numbers().x.to_bytes(
                    public_key.curve.key_size // 8,
                    "big",
                ),
            ),
            "y": b64url_encode(
                public_key.public_numbers().y.to_bytes(
                    public_key.curve.key_size // 8,
                    "big",
                ),
            ),
            "use": "sig",
            "kid": kid or self.kid,
        }

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get the public key.

        Returns:
            The function result.

        """
        return self.key.public_key()

    @property
    def type(self) -> str:
        """Key type identifier for ECDSA keys.

        Returns:
            The function result.

        """
        return "ECDSA"

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key.

        Returns:
            The function result.

        """
        return ECDSAAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key.

        Returns:
            The function result.

        """
        return ECDSAAlgorithm.verify(
            data=data,
            signature=signature,
            key=self.public_der(),
            alg=self.algorithm,
        )


def _build_ecdsa_key(
    loaded: PrivateKeyTypes,
    algorithm: str | None,
) -> ECDSAKey:
    """Build an ECDSAKey from a cryptography private key.

    Returns:
        An ECDSAKey wrapping ``loaded``.

    Raises:
        TypeError: If ``loaded`` is not an elliptic-curve private key.

    """
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        msg = "Expected an EllipticCurvePrivateKey"
        raise TypeError(msg)
    return ECDSAKey(key=loaded, algorithm=algorithm or "ES256")


register_crypto_key_builder(ec.EllipticCurvePrivateKey, _build_ecdsa_key)
