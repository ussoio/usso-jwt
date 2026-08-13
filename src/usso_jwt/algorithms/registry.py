"""Registry mapping JWT algorithm names to managers."""

from .base import KeyAlgorithm
from .ecdsa import ECDSAAlgorithm
from .eddsa import EdDSAAlgorithm
from .hmac import HMACAlgorithm
from .rsa import RSAAlgorithm

_ALGORITHM_MANAGERS: tuple[type[KeyAlgorithm], ...] = (
    ECDSAAlgorithm,
    EdDSAAlgorithm,
    HMACAlgorithm,
    RSAAlgorithm,
)


def get_algorithm(alg: str) -> type[KeyAlgorithm]:
    """Return the algorithm manager class for ``alg``.

    Args:
        alg: The algorithm name
             (e.g., "HS256", "RS256", "ES256", "EdDSA", "Ed25519")

    Returns:
        The appropriate algorithm manager class

    Raises:
        ValueError: If the algorithm is not supported

    """
    for algo in _ALGORITHM_MANAGERS:
        if alg.upper() in algo.SUPPORTED_ALGORITHMS:
            return algo

    msg = f"Unsupported algorithm: {alg}"
    raise ValueError(msg)
