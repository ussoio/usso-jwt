from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..utils import b64url_decode, b64url_encode
from .base import AbstractKey, KeyAlgorithm


class RSAAlgorithm(KeyAlgorithm):
    """RSA algorithm implementation
    (RS256, RS384, RS512, PS256, PS384, PS512)."""

    SUPPORTED_ALGORITHMS = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "PS256": hashes.SHA256,
        "PS384": hashes.SHA384,
        "PS512": hashes.SHA512,
    }

    @staticmethod
    def load_key(
        key: dict | bytes | rsa.RSAPrivateKey, password: bytes | None = None
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
            # Load from JWK
            n = int.from_bytes(b64url_decode(key["n"]), "big")
            e = int.from_bytes(b64url_decode(key["e"]), "big")
            d = int.from_bytes(b64url_decode(key["d"]), "big")
            return rsa.RSAPrivateNumbers(
                p=int.from_bytes(b64url_decode(key["p"]), "big"),
                q=int.from_bytes(b64url_decode(key["q"]), "big"),
                d=d,
                dmp1=int.from_bytes(b64url_decode(key["dp"]), "big"),
                dmq1=int.from_bytes(b64url_decode(key["dq"]), "big"),
                iqmp=int.from_bytes(b64url_decode(key["qi"]), "big"),
                public_numbers=rsa.RSAPublicNumbers(e, n),
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
        key: dict | bytes | rsa.RSAPrivateKey,
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
        hash_alg = cls.SUPPORTED_ALGORITHMS[alg]

        if alg.startswith("RS"):
            return privkey.sign(data, padding.PKCS1v15(), hash_alg())
        else:  # PS
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
        key: dict | bytes,
        alg: str = "RS256",
    ) -> bool:
        """
        Verify RSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or PEM-encoded public key bytes
            alg: The signing algorithm used
                 (RS256, RS384, RS512, PS256, PS384, PS512)
            password: Optional password for encrypted PEM keys

        Returns:
            True if signature is valid, False otherwise
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported RSA algorithm: {alg}")

        if isinstance(key, dict):
            # Load from JWK
            n = int.from_bytes(b64url_decode(key["n"]), "big")
            e = int.from_bytes(b64url_decode(key["e"]), "big")
            pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        else:
            # Load from DER
            pubkey = serialization.load_der_public_key(
                key,
                backend=default_backend(),
            )

        hash_alg = cls.SUPPORTED_ALGORITHMS[alg]

        try:
            if alg.startswith("RS"):
                pubkey.verify(signature, data, padding.PKCS1v15(), hash_alg())
            else:  # PS
                pubkey.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hash_alg(),
                )
            return True
        except Exception:
            return False


class RSAKey(AbstractKey):
    """RSA key implementation."""

    def __init__(self, *, key: rsa.RSAPrivateKey, algorithm: str = "RS256"):
        self.key: rsa.RSAPrivateKey = key
        self.algorithm = algorithm

    @classmethod
    def generate(
        cls,
        *,
        algorithm: str = "RS256",
        key_size: int = 2048,
        public_exponent: int = 65537,
    ) -> "RSAKey":
        """Generate a new RSA key."""
        return RSAKey(
            key=rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size,
                backend=default_backend(),
            ),
            algorithm=algorithm,
        )

    @classmethod
    def load_jwk(cls, key: dict) -> "RSAKey":
        """Load a key from JWK dict."""
        algorithm = key.get("alg", "RS256")
        return RSAKey(
            key=rsa.RSAPrivateNumbers(
                p=int.from_bytes(b64url_decode(key["p"]), "big"),
                q=int.from_bytes(b64url_decode(key["q"]), "big"),
                d=int.from_bytes(b64url_decode(key["d"]), "big"),
                dmp1=int.from_bytes(b64url_decode(key["dp"]), "big"),
                dmq1=int.from_bytes(b64url_decode(key["dq"]), "big"),
                iqmp=int.from_bytes(b64url_decode(key["qi"]), "big"),
                public_numbers=rsa.RSAPublicNumbers(
                    int.from_bytes(b64url_decode(key["e"]), "big"),
                    int.from_bytes(b64url_decode(key["n"]), "big"),
                ),
            ).private_key(default_backend()),
            algorithm=algorithm,
        )

    @classmethod
    def load_pem(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "RS256",
    ) -> "RSAKey":
        """Load a key from PEM."""
        key = super().load_pem(key, password)
        return RSAKey(key=key, algorithm=algorithm)

    @classmethod
    def load_der(
        cls,
        key: bytes,
        password: bytes | None = None,
        algorithm: str = "RS256",
    ) -> "RSAKey":
        """Load a key from DER."""
        key = super().load_der(key, password)
        return RSAKey(key=key, algorithm=algorithm)

    def jwk(self) -> dict:
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
                    public_key.key_size // 8,
                    "big",
                )
            ),
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
