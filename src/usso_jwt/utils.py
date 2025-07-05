import base64


def b64url_decode(data: str | bytes) -> bytes:
    padding = "=" * (-len(data) % 4)
    if isinstance(data, bytes):
        padding = padding.encode()
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: str | bytes) -> str:
    """Base64url encode bytes."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
