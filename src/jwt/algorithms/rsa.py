import base64
from typing import Dict, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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

    @classmethod
    def load_key(
        cls, key: Union[Dict, bytes], password: bytes | None = None
    ) -> rsa.RSAPrivateKey:
        """
        Load RSA key from JWK or PEM.

        Args:
            key: Either a JWK dict or PEM-encoded private key bytes
            password: Optional password for encrypted PEM keys

        Returns:
            The RSA private key
        """
        if isinstance(key, dict):
            # Add padding back to base64url
            padding = 4 - (len(key["n"]) % 4)
            if padding != 4:
                key["n"] += "=" * padding
            n = int.from_bytes(base64.urlsafe_b64decode(key["n"]), "big")

            padding = 4 - (len(key["e"]) % 4)
            if padding != 4:
                key["e"] += "=" * padding
            e = int.from_bytes(base64.urlsafe_b64decode(key["e"]), "big")

            padding = 4 - (len(key["d"]) % 4)
            if padding != 4:
                key["d"] += "=" * padding
            d = int.from_bytes(base64.urlsafe_b64decode(key["d"]), "big")

            padding = 4 - (len(key["p"]) % 4)
            if padding != 4:
                key["p"] += "=" * padding
            p = int.from_bytes(base64.urlsafe_b64decode(key["p"]), "big")

            padding = 4 - (len(key["q"]) % 4)
            if padding != 4:
                key["q"] += "=" * padding
            q = int.from_bytes(base64.urlsafe_b64decode(key["q"]), "big")

            padding = 4 - (len(key["dp"]) % 4)
            if padding != 4:
                key["dp"] += "=" * padding
            dmp1 = int.from_bytes(base64.urlsafe_b64decode(key["dp"]), "big")

            padding = 4 - (len(key["dq"]) % 4)
            if padding != 4:
                key["dq"] += "=" * padding
            dmq1 = int.from_bytes(base64.urlsafe_b64decode(key["dq"]), "big")

            padding = 4 - (len(key["qi"]) % 4)
            if padding != 4:
                key["qi"] += "=" * padding
            iqmp = int.from_bytes(base64.urlsafe_b64decode(key["qi"]), "big")

            private_numbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=dmp1,
                dmq1=dmq1,
                iqmp=iqmp,
                public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
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
        alg: str,
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
            n = int.from_bytes(base64.urlsafe_b64decode(key["n"]), "big")
            e = int.from_bytes(base64.urlsafe_b64decode(key["e"]), "big")
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
