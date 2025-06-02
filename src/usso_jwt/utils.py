import base64


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    """Base64url encode bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
