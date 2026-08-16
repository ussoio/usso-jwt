"""Base64url and JWK field helpers."""

import base64


def _pem_text_preview(key: str | bytes) -> str:
    """Strip whitespace/quotes from PEM-like text for inspection.

    Returns:
        Normalized text used only for PEM detection and unescape decisions.

    """
    text = key.decode("utf-8") if isinstance(key, bytes) else key
    text = text.strip()
    quote = text[:1]
    if quote in "\"'" and text.endswith(quote):
        text = text[1:-1].strip()
    return text


def is_pem_key_material(key: object) -> bool:
    """Return whether ``key`` looks like PEM text (str or bytes).

    Binary DER keys are not treated as PEM (non-UTF-8 bytes return False).

    Returns:
        True when the value (after strip/quote strip) starts with
        ``-----BEGIN``.

    """
    if not isinstance(key, (str, bytes)):
        return False
    try:
        return _pem_text_preview(key).startswith("-----BEGIN")
    except UnicodeDecodeError:
        return False


def normalize_pem_key_material(key: str | bytes) -> bytes:
    r"""Normalize PEM key material for cryptography PEM loaders.

    Handles env/vault values that store literal escaped newlines (``\\n``)
    instead of real newlines. Already-valid multiline PEM is unchanged
    because it does not contain backslash-n sequences.

    Args:
        key: PEM text as ``str`` or ``bytes``.

    Returns:
        UTF-8 PEM bytes suitable for ``load_pem_private_key`` /
        ``load_pem_public_key``.

    """
    text = _pem_text_preview(key)
    if text.startswith("-----BEGIN") and ("\\n" in text or "\\r" in text):
        text = (
            text.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\r", "\n")
            .strip()
        )
    return text.encode("utf-8")


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
