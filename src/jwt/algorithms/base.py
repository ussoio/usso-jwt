from abc import ABC, abstractmethod


class Algorithm(ABC):
    """Abstract base class for JWT algorithms."""

    @property
    @abstractmethod
    def SUPPORTED_ALGORITHMS(self) -> set[str]:
        """Set of supported algorithms for this implementation."""

    @staticmethod
    @abstractmethod
    def load_key(key: dict | bytes, password: bytes | None = None):
        """Load key from JWK dict or raw bytes."""

    @classmethod
    @abstractmethod
    def sign(
        cls,
        signing_input: bytes,
        key: dict | bytes,
        alg: str,
        password: bytes | None = None,
    ) -> bytes:
        """Sign data using the specified algorithm."""

    @classmethod
    @abstractmethod
    def verify(
        cls,
        signing_input: bytes,
        signature: bytes,
        key: dict | bytes,
        alg: str,
        password: bytes | None = None,
    ) -> bool:
        """Verify signature using the specified algorithm."""
