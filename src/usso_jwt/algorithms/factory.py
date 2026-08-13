"""Build AbstractKey wrappers from cryptography private keys."""

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .base import AbstractKey

# Import concrete keys so their crypto builders are registered.
from .ecdsa import ECDSAKey
from .eddsa import EdDSAKey
from .rsa import RSAKey

_ = (ECDSAKey, EdDSAKey, RSAKey)


def from_cryptography_key(
    loaded: PrivateKeyTypes,
    algorithm: str | None = None,
) -> AbstractKey:
    """Wrap a cryptography private key in the matching AbstractKey.

    Args:
        loaded: A cryptography private key instance.
        algorithm: Optional JWT algorithm name override.

    Returns:
        An AbstractKey subclass wrapping ``loaded``.

    """
    return AbstractKey.from_cryptography_key(loaded, algorithm)
