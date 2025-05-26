from typing import Type

from .base import Algorithm
from .ecdsa import ECDSAAlgorithm
from .eddsa import EdDSAAlgorithm
from .hmac import HMACAlgorithm
from .rsa import RSAAlgorithm


def get_algorithm(alg: str) -> Type[Algorithm]:
    """
    Get the appropriate algorithm manager for the given algorithm.

    Args:
        alg: The algorithm name (e.g., "HS256", "RS256", "ES256", "EdDSA")

    Returns:
        The appropriate algorithm manager class

    Raises:
        ValueError: If the algorithm is not supported
    """
    for algo in Algorithm.__subclasses__():
        if alg.upper() in algo.SUPPORTED_ALGORITHMS:
            return algo

    raise ValueError(f"Unsupported algorithm: {alg}")


__all__ = [
    "Algorithm",
    "HMACAlgorithm",
    "RSAAlgorithm",
    "ECDSAAlgorithm",
    "EdDSAAlgorithm",
    "get_algorithm",
]
