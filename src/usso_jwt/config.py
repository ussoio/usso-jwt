import json
import os
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import Algorithm


class JWTConfig(BaseModel):
    """Configuration for JWT processing."""

    jwk_url: str | None = Field(
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
    type: Algorithm = Field(
        default=Algorithm.EdDSA,
        description="Algorithm to use for signing/verification.",
    )

    def __init__(self, **data: Any):
        if os.getenv("JWT_CONFIG") and not data:
            data = json.loads(os.getenv("JWT_CONFIG", "{}"))

        super().__init__(**data)

    @classmethod
    def init_by_json(cls, json_data: str | dict) -> "JWTConfig":
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        return cls(**json_data)

    def __hash__(self) -> int:
        return hash(self.model_dump_json())

    @model_validator(mode="after")
    def validate_config(cls, data: "JWTConfig") -> "JWTConfig":
        if not data.jwk_url and not data.key:
            raise ValueError("Either jwk_url or key must be provided")
        return data

    @field_validator("key", mode="after")
    def validate_key(cls, v: dict | str | bytes | None) -> dict | None:
        from .algorithms.base import convert_key_to_jwk

        if v is None:
            return None
        if isinstance(v, str):
            return convert_key_to_jwk(v.encode())
        if isinstance(v, bytes):
            return convert_key_to_jwk(v)
        return v
