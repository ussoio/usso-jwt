from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..utils import (
    as_jwk_dict,
    b64url_encode,
    jwk_int_field,
    jwk_str_field,
)
from .base import AbstractKey, KeyAlgorithm


class RSAAlgorithm(KeyAlgorithm):
    """RSA algorithm implementation
    (RS256, RS384, RS512, PS256, PS384, PS512)."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }
    _HASHES: ClassVar[dict[str, type[hashes.HashAlgorithm]]] = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "PS256": hashes.SHA256,
        "PS384": hashes.SHA384,
        "PS512": hashes.SHA512,
    }

    @classmethod
    def load_key(
        cls,
        key: object,
        password: bytes | None = None,
    ) -> rsa.RSAPrivateKey:
        """
        Load RSA private key from JWK dict or PEM bytes.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            password: Optional password for encrypted PEM keys

        Returns:
            RSA private key object
        """
        if isinstance(key, rsa.RSAPrivateKey):
            return key
        if isinstance(key, dict):
            return cls.load_jwk(as_jwk_dict(key))

        if isinstance(key, bytes) and key.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_private_key(
                key, password=password, backend=default_backend()
            )
        elif isinstance(key, bytes):
            loaded = serialization.load_der_private_key(
                key, password=password, backend=default_backend()
            )
        else:
            raise TypeError(f"Unsupported RSA key type: {type(key)}")

        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise TypeError("Expected an RSAPrivateKey")
        return loaded

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> rsa.RSAPrivateKey:
        """Load a key from JWK dict."""
        jwk = as_jwk_dict(key)
        return rsa.RSAPrivateNumbers(
            p=jwk_int_field(jwk, "p"),
            q=jwk_int_field(jwk, "q"),
            d=jwk_int_field(jwk, "d"),
            dmp1=jwk_int_field(jwk, "dp"),
            dmq1=jwk_int_field(jwk, "dq"),
            iqmp=jwk_int_field(jwk, "qi"),
            public_numbers=rsa.RSAPublicNumbers(
                jwk_int_field(jwk, "e"),
                jwk_int_field(jwk, "n"),
            ),
        ).private_key(default_backend())

    @classmethod
    def sign(
        cls,
        *,
        data: bytes,
        key: object,
        alg: str = "RS256",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using RSA algorithms.

        Args:
            data: The data to sign
            key: Either a JWK dict or PEM-encoded private key bytes
            alg: The signing algorithm to use
                 (RS256, RS384, RS512, PS256, PS384, PS512)
            password: Optional password for encrypted PEM keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported RSA algorithm: {alg}")

        privkey = cls.load_key(key, password)
        hash_alg = cls._HASHES[alg]

        if alg.startswith("RS"):
            return privkey.sign(data, padding.PKCS1v15(), hash_alg())
        return privkey.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_alg()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hash_alg(),
        )

    @classmethod
    def verify(
        cls,
        *,
        data: bytes,
        signature: bytes,
        key: object,
        alg: str = "RS256",
        **kwargs: object,
    ) -> bool:
        """
        Verify RSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or PEM-encoded public key bytes
            alg: The signing algorithm used
                 (RS256, RS384, RS512, PS256, PS384, PS512)
            **kwargs: Optional extras

        Returns:
            True if signature is valid, False otherwise
        """
        del kwargs
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported RSA algorithm: {alg}")

        if isinstance(key, dict):
            jwk = as_jwk_dict(key)
            n = jwk_int_field(jwk, "n")
            e = jwk_int_field(jwk, "e")
            pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        elif isinstance(key, bytes):
            loaded = serialization.load_der_public_key(
                key,
                backend=default_backend(),
            )
            if not isinstance(loaded, rsa.RSAPublicKey):
                raise TypeError("Expected an RSAPublicKey")
            pubkey = loaded
        elif isinstance(key, rsa.RSAPublicKey):
            pubkey = key
        else:
            raise TypeError(f"Unsupported RSA verify key type: {type(key)}")

        hash_alg = cls._HASHES[alg]

        try:
            if alg.startswith("RS"):
                pubkey.verify(signature, data, padding.PKCS1v15(), hash_alg())
            else:
                pubkey.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hash_alg(),
                )
        except Exception:
            return False

        return True


class RSAKey(AbstractKey):
    """RSA key implementation."""

    SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }

    def __init__(
        self, *, key: rsa.RSAPrivateKey, algorithm: str = "RS256"
    ) -> None:
        self._key = key
        self.algorithm = algorithm

    @property
    def key(self) -> rsa.RSAPrivateKey:
        """Underlying RSA private key."""
        return self._key

    @classmethod
    def generate(cls, **kwargs: object) -> "RSAKey":
        """Generate a new RSA key."""
        algorithm = kwargs.get("algorithm", "RS256")
        key_size = kwargs.get("key_size", 2048)
        public_exponent = kwargs.get("public_exponent", 65537)
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        if not isinstance(key_size, int):
            raise TypeError("key_size must be an int")
        if not isinstance(public_exponent, int):
            raise TypeError("public_exponent must be an int")
        return RSAKey(
            key=rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size,
                backend=default_backend(),
            ),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict[str, object]) -> "RSAKey":
        """Load a key from JWK dict."""
        jwk = as_jwk_dict(key)
        algorithm = jwk_str_field(jwk, "alg", "RS256")
        return RSAKey(
            key=RSAAlgorithm.load_jwk(jwk),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "RSAKey":
        """Load a key from PEM."""
        algorithm = kwargs.get("algorithm", "RS256")
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        loaded = cls.load_cryptography_pem(key, password)
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise TypeError("Expected an RSAPrivateKey")
        return RSAKey(key=loaded, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        **kwargs: object,
    ) -> "RSAKey":
        """Load a key from DER."""
        algorithm = kwargs.get("algorithm", "RS256")
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        loaded = cls.load_cryptography_der(key, password)
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise TypeError("Expected an RSAPrivateKey")
        return RSAKey(key=loaded, algorithm=algorithm)

    def jwk(self, kid: str | None = None) -> dict:
        """Get the JWK for the key."""
        public_key = self.key.public_key()
        return {
            "kty": "RSA",
            "alg": self.algorithm,
            "n": b64url_encode(
                public_key.public_numbers().n.to_bytes(
                    public_key.key_size // 8,
                    "big",
                )
            ),
            "e": b64url_encode(
                public_key.public_numbers().e.to_bytes(
                    (public_key.public_numbers().e.bit_length() + 7) // 8,
                    "big",
                )
            ),
            "use": "sig",
            "kid": kid or self.kid,
        }

    def public_key(self) -> rsa.RSAPublicKey:
        """Get the public key."""
        return self.key.public_key()

    @property
    def type(self) -> str:
        """Get the type of the key."""
        return "RSA"

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return self.key.key_size

    def sign(self, data: bytes) -> bytes:
        """Sign data using the key."""
        return RSAAlgorithm.sign(data=data, key=self.key, alg=self.algorithm)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using the key."""
        return RSAAlgorithm.verify(
            data=data,
            signature=signature,
            key=self.public_der(),
            alg=self.algorithm,
        )
