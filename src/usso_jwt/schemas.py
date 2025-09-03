from typing import TypeVar

from pydantic import BaseModel, Field

from .config import JWTConfig
from .enums import Algorithm
from .exceptions import JWTError
from .verify import extract_jwt_parts, verify_jwt, verify_temporal_claims

T = TypeVar("T", bound="BaseModel")


class UnverifiedJWT(BaseModel):
    token: str

    def __str__(self) -> str:
        return self.token

    def __hash__(self) -> int:
        return hash(self.token)

    @property
    def _parts(self) -> tuple[dict, dict, bytes, bytes]:
        if getattr(self, "__parts", None) is None:
            self.__parts = extract_jwt_parts(self.token)
        return self.__parts

    @property
    def unverified_header(self) -> dict[str, str]:
        return self._parts[0]

    @property
    def algorithm(self) -> Algorithm:
        return Algorithm(self.unverified_header["alg"].upper())

    @property
    def unverified_payload(self) -> dict | T:
        return self._parts[1]

    @property
    def signature(self) -> bytes:
        return self._parts[2]

    @property
    def signing_input(self) -> bytes:
        return self._parts[3]

    @property
    def is_expired(self) -> bool:
        return not self.is_temporally_valid(raise_exception=True)

    def is_temporally_valid(self, *, raise_exception: bool = False) -> bool:
        try:
            return bool(
                verify_temporal_claims(payload=self.unverified_payload)
            )
        except Exception:
            if raise_exception:
                raise
            return False


class JWT(UnverifiedJWT):
    config: JWTConfig = Field(default_factory=JWTConfig)

    def __init__(
        self,
        *,
        token: str,
        config: JWTConfig | None = None,
        payload_class: type[T] | None = None,
    ) -> None:
        super().__init__(token=token, config=config)
        self._payload_class = payload_class

    def __hash__(self) -> int:
        return hash(self.token)

    @property
    def header(self) -> dict[str, str]:
        if self.verify():
            return self.unverified_header
        raise JWTError("JWT is not valid")

    @property
    def unverified_payload(self) -> dict | T:
        if self._payload_class is not None:
            return self._payload_class.model_validate(self._parts[1])
        return self._parts[1]

    @property
    def payload(self) -> dict | T:
        if self.verify():
            return self.unverified_payload
        raise JWTError("JWT is not valid")

    def verify(
        self,
        expected_acr: str | list[str] | None = None,
        expected_token_type: str | list[str] | None = None,
        **kwargs: object,
    ) -> bool:
        return verify_jwt(
            token=self.token,
            jwk=self.config.key,
            jwks_url=self.config.jwks_url,
            kid=self.unverified_header.get("kid"),
            expected_audience=self.config.audience,
            expected_issuer=self.config.issuer,
            expected_acr=expected_acr,
            expected_token_type=expected_token_type,
            maximum_age=self.config.maximum_age,
        )
