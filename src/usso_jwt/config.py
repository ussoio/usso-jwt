import json
import os
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator

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
        if os.getenv("JWT_CONFIG") and not data:
            data = json.loads(os.getenv("JWT_CONFIG", "{}"))

        super().__init__(**data)

    @classmethod
    def init_by_json(cls, json_data: object) -> "JWTConfig":
        parsed: object = json_data
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if not isinstance(parsed, dict):
            raise TypeError("json_data must be a str or dict")
        payload = {str(key): value for key, value in parsed.items()}
        return cls(**payload)

    def __hash__(self) -> int:
        return hash(self.model_dump_json())

    @model_validator(mode="after")
    def validate_config(self) -> "JWTConfig":
        if not self.jwks_url and not self.key:
            raise ValueError("Either jwks_url or key must be provided")
        return self

    @field_validator("key", mode="before")
    @classmethod
    def validate_key(cls, v: object) -> dict | None:
        from .algorithms.base import convert_key_to_jwk

        if v is None:
            return None
        if isinstance(v, str):
            return convert_key_to_jwk(v.encode())
        if isinstance(v, bytes):
            return convert_key_to_jwk(v)
        if isinstance(v, dict):
            return v
        raise TypeError("key must be str, bytes, dict, or None")

    @property
    def jwk(self) -> dict | None:
        """Return the configured key as a JWK dict when present."""
        if self.key is None:
            return None
        if isinstance(self.key, dict):
            return self.key
        raise TypeError("JWTConfig.key was not normalized to a JWK dict")
