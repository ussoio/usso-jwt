from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..core import b64url_decode
from .base import Algorithm


class RSAAlgorithm(Algorithm):
    """RSA algorithm implementation (RS256, RS384, RS512, PS256, PS384, PS512)."""

    SUPPORTED_ALGORITHMS = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "PS256": hashes.SHA256,
        "PS384": hashes.SHA384,
        "PS512": hashes.SHA512,
    }

    @staticmethod
    def load_key(key: dict | bytes, password: bytes | None = None) -> rsa.RSAPrivateKey:
        """
        Load RSA private key from JWK dict or PEM bytes.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            password: Optional password for encrypted PEM keys

        Returns:
            RSA private key object
        """
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
        alg: str = "RS256",
        password: bytes | None = None,
    ) -> bytes:
        """
        Sign using RSA algorithms.

        Args:
            signing_input: The data to sign
            key: Either a JWK dict or PEM-encoded private key bytes
            alg: The signing algorithm to use (RS256, RS384, RS512, PS256, PS384, PS512)
            password: Optional password for encrypted PEM keys

        Returns:
            The signature
        """
        if alg not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported RSA algorithm: {alg}")

        privkey = cls.load_key(key, password)
        hash_alg = cls.SUPPORTED_ALGORITHMS[alg]

        if alg.startswith("RS"):
            return privkey.sign(signing_input, padding.PKCS1v15(), hash_alg())
        else:  # PS
            return privkey.sign(
                signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                hash_alg(),
            )

    @classmethod
    def verify(
        cls,
        signing_input: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str = "RS256",
        password: bytes | None = None,
    ) -> bool:
        """
        Verify RSA signature.

        Args:
            signing_input: The data that was signed
            signature: The signature to verify
            key: Either a JWK dict or PEM-encoded public key bytes
            alg: The signing algorithm used (RS256, RS384, RS512, PS256, PS384, PS512)
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
            # Load from PEM
            pubkey = serialization.load_pem_public_key(key, backend=default_backend())

        hash_alg = cls.SUPPORTED_ALGORITHMS[alg]

        try:
            if alg.startswith("RS"):
                pubkey.verify(signature, signing_input, padding.PKCS1v15(), hash_alg())
            else:  # PS
                pubkey.verify(
                    signature,
                    signing_input,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hash_alg(),
                )
            return True
        except Exception:
            return False
