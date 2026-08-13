from .base import KeyAlgorithm


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
    # Import subclasses so KeyAlgorithm.__subclasses__() is populated.
    from .ecdsa import ECDSAAlgorithm
    from .eddsa import EdDSAAlgorithm
    from .hmac import HMACAlgorithm
    from .rsa import RSAAlgorithm

    _ = (ECDSAAlgorithm, EdDSAAlgorithm, HMACAlgorithm, RSAAlgorithm)

    for algo in KeyAlgorithm.__subclasses__():
        if alg.upper() in algo.SUPPORTED_ALGORITHMS:
            return algo

    raise ValueError(f"Unsupported algorithm: {alg}")
