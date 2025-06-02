import httpx
import pytest

from src.usso_jwt import exceptions, sign, verify
from src.usso_jwt.algorithms import AbstractKey


def test_fetch_jwk():
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    jwks = httpx.get(jwks_url).json()
    jwk = jwks["keys"][0]
    fetched_jwk = verify.fetch_jwk(jwks_url=jwks_url, kid=jwk["kid"])
    assert fetched_jwk is not None
    assert fetched_jwk["kid"] == jwk["kid"]
    assert fetched_jwk["alg"] == jwk["alg"]
    assert fetched_jwk["kty"] == jwk["kty"]
    assert fetched_jwk["n"] is not None
    assert fetched_jwk["e"] is not None


def test_fetch_failed_jwk():
    with pytest.raises(exceptions.JWKNotFoundError):
        verify.fetch_jwk(
            jwks_url="https://www.googleapis.com/oauth2/v3/certs", kid="123"
        )


def test_invalid_signature(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt = jwt[:-1]  # + chr(ord(jwt[-1]) + 1)
    with pytest.raises(exceptions.JWTInvalidFormatError):
        verify.verify_jwt(token=jwt, jwk=test_key.jwk())


def test_expired_payload(
    test_expired_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_expired_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTExpiredError):
        verify.verify_jwt(token=jwt, jwk=test_key.jwk())


def test_nbf_future_payload(
    test_future_nbf_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_future_nbf_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTNotValidYetError):
        verify.verify_jwt(token=jwt, jwk=test_key.jwk())


def test_future_payload(
    test_future_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_future_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTIssuedInFutureError):
        verify.verify_jwt(token=jwt, jwk=test_key.jwk())


def test_missing_audience(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    payload = test_valid_payload.copy()
    payload.pop("aud", None)
    jwt = sign.generate_jwt(
        header=test_header,
        payload=payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTMissingAudienceError):
        verify.verify_jwt(
            token=jwt, jwk=test_key.jwk(), expected_audience="test_jwt"
        )


def test_invalid_audience(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTInvalidAudienceError):
        verify.verify_jwt(
            token=jwt, jwk=test_key.jwk(), expected_audience="test_jwt"
        )


def test_invalid_acr_audience(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTInvalidACRError):
        verify.verify_jwt(
            token=jwt,
            jwk=test_key.jwk(),
            expected_acr="refresh",
        )


def test_invalid_issuer(
    test_valid_payload: dict, test_header: dict, test_key: AbstractKey
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTInvalidIssuerError):
        verify.verify_jwt(
            token=jwt,
            jwk=test_key.jwk(),
            expected_issuer="test_jwt",
        )
