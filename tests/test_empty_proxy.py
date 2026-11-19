"""An empty PROXY setting must mean "no proxy"."""

from unittest.mock import MagicMock

import pytest

from usso_jwt import verify


def test_fetch_jwk_treats_empty_proxy_as_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``PROXY=`` in .env must not break JWKS fetching."""
    monkeypatch.setenv("PROXY", "")
    seen: dict = {}

    def fake_get(_url: str, **kwargs: object) -> MagicMock:
        seen.update(kwargs)
        resp = MagicMock()
        resp.json.return_value = {"keys": [{"kid": "k1", "kty": "oct"}]}
        return resp

    monkeypatch.setattr(verify.httpx, "get", fake_get)
    key = verify.fetch_jwk(jwks_url="https://empty-proxy.test/jwks", kid="k1")
    assert key["kid"] == "k1"
    assert seen["proxy"] is None
