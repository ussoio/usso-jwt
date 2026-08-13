"""JWT configuration models and validation."""

import json
import os
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator

from .algorithms.base import convert_key_to_jwk
from .enums import Algorithm


class JWTConfig(BaseModel):
    """Configuration for JWT processing."""

    jwks_url: str | None = Field(
        default=None,
        description="URL to fetch JWK from. Required if key is not provided.",
    )
    key: str | bytes | dict | None = Field(
        default=None,
        description="""Key for signing/verification. Can be a PEM string,
        bytes, or JWK dict. If PEM string, it will be converted to JWK.
        If JWK dict, it will be used as is.
        If bytes, it will be converted to JWK.
        """,
    )
    issuer: str | list[str] | None = Field(
        default=None,
        description="Expected issuer(s) of the JWT.",
    )
    audience: str | list[str] | None = Field(
        default=None,
        description="Expected audience(s) of the JWT.",
    )
    type: Annotated[
        Algorithm,
        Field(description="Algorithm to use for signing/verification."),
    ] = Algorithm.EdDSA
    maximum_age: int | None = Field(
        default=None,
        description="Maximum age of the JWT in seconds.",
    )

    def __init__(self, **data: object) -> None:
        """Build config from kwargs or ``JWT_CONFIG`` env JSON."""
        if os.getenv("JWT_CONFIG") and not data:
            data = json.loads(os.getenv("JWT_CONFIG", "{}"))

        super().__init__(**data)

    @classmethod
    def init_by_json(cls, json_data: object) -> "JWTConfig":
        """Create a config from a JSON string or mapping.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        parsed: object = json_data
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if not isinstance(parsed, dict):
            msg = "json_data must be a str or dict"
            raise TypeError(msg)
        payload = {str(key): value for key, value in parsed.items()}
        return cls(**payload)

    def __hash__(self) -> int:
        """Hash config from its JSON serialization.

        Returns:
            The function result.

        """
        return hash(self.model_dump_json())

    @model_validator(mode="after")
    def validate_config(self) -> "JWTConfig":
        """Ensure either ``jwks_url`` or ``key`` is set.

        Returns:
            The function result.

        Raises:
            ValueError: If the value is invalid or unsupported.

        """
        if not self.jwks_url and not self.key:
            msg = "Either jwks_url or key must be provided"
            raise ValueError(msg)
        return self

    @field_validator("key", mode="before")
    @classmethod
    def validate_key(cls, v: object) -> dict | None:
        """Normalize key input into a JWK dict.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        if v is None:
            return None
        if isinstance(v, str):
            return convert_key_to_jwk(v.encode())
        if isinstance(v, bytes):
            return convert_key_to_jwk(v)
        if isinstance(v, dict):
            return v
        msg = "key must be str, bytes, dict, or None"
        raise TypeError(msg)

    @property
    def jwk(self) -> dict | None:
        """Configured signing/verification key as a JWK dict.

        Returns:
            The function result.

        Raises:
            TypeError: If the argument type is invalid.

        """
        if self.key is None:
            return None
        if isinstance(self.key, dict):
            return self.key
        msg = "JWTConfig.key was not normalized to a JWK dict"
        raise TypeError(msg)
