import base64


def b64url_decode(data: str | bytes) -> bytes:
    if isinstance(data, bytes):
        padding = b"=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: str | bytes) -> str:
    """Base64url encode bytes."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def as_jwk_dict(key: object) -> dict[str, object]:
    """Narrow an arbitrary object to a JWK mapping."""
    if not isinstance(key, dict):
        raise TypeError(f"Expected a JWK dict, got {type(key)}")
    return {str(k): v for k, v in key.items()}


def jwk_b64_field(jwk: dict[str, object], field: str) -> str | bytes:
    """Read a base64url JWK field as str or bytes."""
    value = jwk.get(field)
    if not isinstance(value, (str, bytes)):
        raise TypeError(
            f"JWK field {field!r} must be str or bytes, got {type(value)}"
        )
    return value


def jwk_int_field(jwk: dict[str, object], field: str) -> int:
    """Decode a base64url JWK field to an integer."""
    return int.from_bytes(b64url_decode(jwk_b64_field(jwk, field)), "big")


def jwk_str_field(
    jwk: dict[str, object], field: str, default: str | None = None
) -> str:
    """Read a string JWK field, optionally with default."""
    if field not in jwk:
        if default is None:
            raise KeyError(field)
        return default
    value = jwk[field]
    if not isinstance(value, str):
        raise TypeError(
            f"JWK field {field!r} must be str, got {type(value)}"
        )
    return value
