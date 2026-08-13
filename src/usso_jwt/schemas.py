"""Pydantic models for unverified and verified JWTs."""

from typing import TypeVar

from pydantic import BaseModel, Field

from .config import JWTConfig
from .enums import Algorithm
from .exceptions import JWTError
from .verify import (
    VerifyOptions,
    extract_jwt_parts,
    verify_jwt,
    verify_temporal_claims,
)

T = TypeVar("T", bound=BaseModel)


class UnverifiedJWT(BaseModel):
    """JWT wrapper that exposes unverified header and payload parts."""

    token: str

    def __str__(self) -> str:
        """Return the compact JWT string.

        Returns:
            The function result.

        """
        return self.token

    def __hash__(self) -> int:
        """Hash the compact JWT string.

        Returns:
            The function result.

        """
        return hash(self.token)

    @property
    def _parts(self) -> tuple[dict, dict, bytes, bytes]:
        if getattr(self, "__parts", None) is None:
            self.__parts = extract_jwt_parts(self.token)
        return self.__parts

    @property
    def unverified_header(self) -> dict[str, str]:
        """Decoded JWT header without signature verification.

        Returns:
            The function result.

        """
        return self._parts[0]

    @property
    def algorithm(self) -> Algorithm:
        """Signing algorithm declared in the unverified header.

        Returns:
            The function result.

        """
        return Algorithm(self.unverified_header["alg"].upper())

    @property
    def unverified_payload(self) -> dict | BaseModel:
        """Decoded JWT payload without signature verification.

        Returns:
            The function result.

        """
        return self._parts[1]

    @property
    def signature(self) -> bytes:
        """Raw JWT signature bytes.

        Returns:
            The function result.

        """
        return self._parts[2]

    @property
    def signing_input(self) -> bytes:
        """Bytes that were signed (header.payload).

        Returns:
            The function result.

        """
        return self._parts[3]

    @property
    def is_expired(self) -> bool:
        """Whether temporal claims indicate the token is invalid.

        Returns:
            The function result.

        """
        return not self.is_temporally_valid(raise_exception=False)

    def is_temporally_valid(self, *, raise_exception: bool = False) -> bool:
        """Check exp/nbf/iat claims without verifying the signature.

        Returns:
            The function result.

        """
        try:
            return bool(verify_temporal_claims(payload=self._parts[1]))
        except Exception:
            if raise_exception:
                raise
            return False


class JWT(UnverifiedJWT):
    """Verified JWT with config-driven claim and signature checks."""

    config: JWTConfig = Field(default_factory=JWTConfig)

    def __init__(
        self,
        *,
        token: str,
        config: JWTConfig | None = None,
        payload_class: type[BaseModel] | None = None,
    ) -> None:
        """Initialize a JWT with optional config and payload class."""
        init_data: dict[str, object] = {"token": token}
        if config is not None:
            init_data["config"] = config
        BaseModel.__init__(self, **init_data)
        self._payload_class = payload_class

    def __hash__(self) -> int:
        """Hash the compact JWT string.

        Returns:
            The function result.

        """
        return hash(self.token)

    @property
    def header(self) -> dict[str, str]:
        """Verified JWT header.

        Returns:
            The function result.

        Raises:
            JWTError: If the JWT is not valid.

        """
        if self.verify():
            return self.unverified_header
        msg = "JWT is not valid"
        raise JWTError(msg)

    @property
    def unverified_payload(self) -> dict | BaseModel:
        """Decoded payload, optionally validated as ``payload_class``.

        Returns:
            The function result.

        """
        if self._payload_class is not None:
            return self._payload_class.model_validate(self._parts[1])
        return self._parts[1]

    @property
    def payload(self) -> dict | BaseModel:
        """Verified JWT payload.

        Returns:
            The function result.

        Raises:
            JWTError: If the JWT is not valid.

        """
        if self.verify():
            return self.unverified_payload
        msg = "JWT is not valid"
        raise JWTError(msg)

    def verify(
        self,
        expected_acr: str | list[str] | None = None,
        expected_token_type: str | list[str] | None = None,
        **kwargs: object,
    ) -> bool:
        """Verify signature and configured claims for this token.

        Returns:
            The function result.

        """
        del kwargs
        return verify_jwt(
            token=self.token,
            options=VerifyOptions(
                jwk=self.config.jwk,
                jwks_url=self.config.jwks_url,
                kid=self.unverified_header.get("kid"),
                expected_audience=self.config.audience,
                expected_issuer=self.config.issuer,
                expected_acr=expected_acr,
                expected_token_type=expected_token_type,
                maximum_age=self.config.maximum_age,
            ),
        )
