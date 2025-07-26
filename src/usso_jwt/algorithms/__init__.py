from .base import (
    AbstractKey,
    KeyAlgorithm,
    convert_jwk_to_pem,
    convert_key_to_jwk,
)
from .ecdsa import ECDSAAlgorithm, ECDSAKey
from .eddsa import EdDSAAlgorithm, EdDSAKey
from .hmac import HMACAlgorithm, HMACKey
from .rsa import RSAAlgorithm, RSAKey


def get_algorithm(alg: str) -> type[KeyAlgorithm]:
    """
    Get the appropriate algorithm manager for the given algorithm.

    Args:
        alg: The algorithm name
             (e.g., "HS256", "RS256", "ES256", "EdDSA", "Ed25519")

    Returns:
        The appropriate algorithm manager class

    Raises:
        ValueError: If the algorithm is not supported
    """
    for algo in KeyAlgorithm.__subclasses__():
        if alg.upper() in algo.SUPPORTED_ALGORITHMS:
            return algo

    raise ValueError(f"Unsupported algorithm: {alg}")


__all__ = [
    "AbstractKey",
    "ECDSAAlgorithm",
    "ECDSAKey",
    "EdDSAAlgorithm",
    "EdDSAKey",
    "HMACAlgorithm",
    "HMACKey",
    "KeyAlgorithm",
    "RSAAlgorithm",
    "RSAKey",
    "convert_jwk_to_pem",
    "convert_key_to_jwk",
    "get_algorithm",
]
