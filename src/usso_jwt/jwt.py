from typing import TypeVar

from cachetools import TTLCache, cached
from pydantic import BaseModel

from .core import Algorithm
from .verify import (
    extract_jwt_parts,
    fetch_jwk,
    verify_signature,
    verify_temporal_claims,
)

T = TypeVar("T", bound="BaseModel")


class JWT(BaseModel):
    token: str
    key: dict | None = None
    jwks_url: str | None = None

    def __init__(
        self,
        *,
        token: str,
        key: dict | None = None,
        jwks_url: str | None = None,
        payload_class: type[T] | None = None,
    ):
        super().__init__(token=token, key=key, jwks_url=jwks_url)
        self._payload_class = payload_class

    def __hash__(self) -> int:
        return hash(self.token)

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=300))
    def _parts(self) -> tuple[dict, dict, bytes, bytes]:
        return extract_jwt_parts(self.token)

    @property
    def unverified_header(self) -> dict[str, str]:
        return self._parts[0]

    @property
    def header(self) -> dict[str, str]:
        if self.verify():
            return self.unverified_header
        raise ValueError("JWT is not valid")

    @property
    def algorithm(self) -> Algorithm:
        return Algorithm(self.unverified_header["alg"].upper())

    @property
    def unverified_payload(self) -> dict | T:
        if self._payload_class is not None:
            return self._payload_class.model_validate(self._parts[1])
        return self._parts[1]

    @property
    def payload(self) -> dict | T:
        if self.verify():
            return self.unverified_payload
        raise ValueError("JWT is not valid")

    @property
    def signature(self) -> bytes:
        return self._parts[2]

    @property
    def signing_input(self) -> bytes:
        return self._parts[3]

    def verify(self) -> bool:
        if self.jwks_url is None and self.key is None:
            raise ValueError("Either jwks_url or key must be provided")

        if self.jwks_url is not None:
            self.key = fetch_jwk(self.unverified_header["kid"], self.jwks_url)

        if self.key is None:
            raise ValueError("Key must be provided")

        verification = verify_signature(
            alg=self.algorithm,
            key=self.key,
            data=self.signing_input,
            signature=self.signature,
        )
        if not verification:
            return False
        return verify_temporal_claims(payload=self.unverified_payload)
