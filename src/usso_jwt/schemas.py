from typing import TypeVar

from cachetools import TTLCache, cached
from pydantic import BaseModel, Field

from .config import JWTConfig
from .enums import Algorithm
from .verify import extract_jwt_parts, verify_jwt, verify_temporal_claims

T = TypeVar("T", bound="BaseModel")


class JWT(BaseModel):
    token: str
    config: JWTConfig = Field(default_factory=JWTConfig)

    def __init__(
        self,
        *,
        token: str,
        config: JWTConfig | None = None,
        payload_class: type[T] | None = None,
    ):
        super().__init__(token=token, config=config)
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

    def is_temporally_valid(self, *, raise_exception: bool = False) -> bool:
        try:
            if verify_temporal_claims(payload=self.unverified_payload):
                return True
            return False
        except Exception as e:
            if raise_exception:
                raise e
            return False

    def verify(self, expected_acr: str | list[str] | None = None) -> bool:
        return verify_jwt(
            token=self.token,
            jwk=self.config.key,
            expected_audience=self.config.audience,
            expected_issuer=self.config.issuer,
            expected_acr=expected_acr,
        )
