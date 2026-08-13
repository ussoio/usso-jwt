"""Base64url and JWK field helpers."""

import base64


def b64url_decode(data: str | bytes) -> bytes:
    """Decode base64url data.

    Returns:
        The function result.

    """
    if isinstance(data, bytes):
        return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64url_encode(data: str | bytes) -> str:
    """Encode bytes or text as base64url without padding.

    Returns:
        The function result.

    """
    raw = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def as_jwk_dict(key: object) -> dict[str, object]:
    """Narrow an arbitrary object to a JWK mapping.

    Returns:
        The function result.

    Raises:
        TypeError: If the argument type is invalid.

    """
    if not isinstance(key, dict):
        msg = f"Expected a JWK dict, got {type(key)}"
        raise TypeError(msg)
    return {str(k): v for k, v in key.items()}


def jwk_b64_field(jwk: dict[str, object], field: str) -> str | bytes:
    """Read a base64url JWK field as str or bytes.

    Returns:
        The function result.

    Raises:
        TypeError: If the argument type is invalid.

    """
    value = jwk.get(field)
    if not isinstance(value, (str, bytes)):
        msg = f"JWK field {field!r} must be str or bytes, got {type(value)}"
        raise TypeError(
            msg,
        )
    return value


def jwk_int_field(jwk: dict[str, object], field: str) -> int:
    """Decode a base64url JWK field to an integer.

    Returns:
        The function result.

    """
    return int.from_bytes(b64url_decode(jwk_b64_field(jwk, field)), "big")


def jwk_str_field(
    jwk: dict[str, object],
    field: str,
    default: str | None = None,
) -> str:
    """Read a string JWK field, optionally with default.

    Returns:
        The function result.

    Raises:
        KeyError: If the required field is missing.
        TypeError: If the argument type is invalid.

    """
    if field not in jwk:
        if default is None:
            raise KeyError(field)
        return default
    value = jwk[field]
    if not isinstance(value, str):
        msg = f"JWK field {field!r} must be str, got {type(value)}"
        raise TypeError(
            msg,
        )
    return value
