"""Coverage-focused unit tests for remaining branches."""

import json
import time
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from pydantic import BaseModel, ValidationError

from usso_jwt import (
    config,
    enums,
    exceptions,
    schemas,
    sign,
    utils,
    verify,
)
from usso_jwt.algorithms import (
    AbstractKey,
    ECDSAAlgorithm,
    ECDSAKey,
    EdDSAAlgorithm,
    EdDSAKey,
    HMACAlgorithm,
    HMACKey,
    RSAAlgorithm,
    RSAKey,
    convert_key_to_jwk,
    from_cryptography_key,
    get_algorithm,
)
from usso_jwt.algorithms import ecdsa as ecdsa_mod
from usso_jwt.algorithms import eddsa as eddsa_mod
from usso_jwt.algorithms import rsa as rsa_mod


@pytest.fixture
def rsa_key() -> RSAKey:
    """RSA test key fixture.

    Returns:
        The function result.

    """
    return RSAKey.generate(algorithm="RS256", key_size=2048)


@pytest.fixture
def ecdsa_key() -> ECDSAKey:
    """ECDSA test key fixture.

    Returns:
        The function result.

    """
    return ECDSAKey.generate(algorithm="ES256")


@pytest.fixture
def eddsa_key() -> EdDSAKey:
    """EdDSA test key fixture.

    Returns:
        The function result.

    """
    return EdDSAKey.generate(algorithm="EdDSA")


@pytest.fixture
def hmac_key_bytes() -> bytes:
    """Raw HMAC key bytes fixture.

    Returns:
        The function result.

    """
    return b"test_key_32_bytes_long_for_hmac!"


def test_convert_key_to_jwk_unsupported() -> None:
    """Reject unsupported PEM keys in convert_key_to_jwk."""
    with (
        patch(
            "usso_jwt.algorithms.base.serialization.load_pem_public_key",
            return_value=MagicMock(),
        ),
        pytest.raises(TypeError, match="Unsupported algorithm"),
    ):
        convert_key_to_jwk(
            b"-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
        )


def test_generate_algorithm_and_load_jwk_errors() -> None:
    """Cover generate_algorithm and load_jwk error paths."""
    assert isinstance(AbstractKey.generate_algorithm("EdDSA"), EdDSAKey)
    assert isinstance(AbstractKey.generate_algorithm("RS256"), RSAKey)
    assert isinstance(AbstractKey.generate_algorithm("ES256"), ECDSAKey)
    assert isinstance(AbstractKey.generate_algorithm("HS256"), HMACKey)

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        AbstractKey.generate_algorithm("NOPE")

    with pytest.raises(ValueError, match="Missing algorithm"):
        AbstractKey.load_jwk({"kty": "oct", "k": "YQ"})

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        AbstractKey.load_jwk({"alg": "NOPE", "kty": "oct", "k": "YQ"})


def test_from_cryptography_and_load_paths(
    rsa_key: RSAKey,
    ecdsa_key: ECDSAKey,
    eddsa_key: EdDSAKey,
) -> None:
    """Cover from_cryptography_key and load helpers."""
    assert isinstance(
        AbstractKey.from_cryptography_key(rsa_key.key),
        RSAKey,
    )
    assert isinstance(
        AbstractKey.from_cryptography_key(ecdsa_key.key),
        ECDSAKey,
    )
    assert isinstance(
        from_cryptography_key(eddsa_key.key),
        EdDSAKey,
    )

    with pytest.raises(TypeError, match="Unsupported private key type"):
        AbstractKey.from_cryptography_key(MagicMock())

    with pytest.raises(TypeError, match="Expected an RSAPrivateKey"):
        rsa_mod._build_rsa_key(MagicMock(), None)
    with pytest.raises(TypeError, match="Expected an EllipticCurvePrivateKey"):
        ecdsa_mod._build_ecdsa_key(MagicMock(), None)
    with pytest.raises(TypeError, match="Expected an Ed25519PrivateKey"):
        eddsa_mod._build_eddsa_key(MagicMock(), None)

    loaded = AbstractKey.load(rsa_key.private_der())
    assert isinstance(loaded, RSAKey)

    bad: object = 123
    with pytest.raises(ValueError, match="Invalid key data"):
        AbstractKey.load(bad)


def test_octet_key_encoding_errors() -> None:
    """Reject PEM/DER encoding for octet keys."""

    class OctetKey(AbstractKey):
        SUPPORTED_ALGORITHMS: ClassVar[set[str]] = {"OCT"}

        def __init__(self) -> None:
            self._key = b"secret"
            self.algorithm = "OCT"

        @property
        def key(self) -> bytes:
            """Raw octet key material.

            Returns:
                The function result.

            """
            return self._key

        @classmethod
        def generate(cls, **kwargs: object) -> "OctetKey":
            """Create a new OctetKey instance.

            Returns:
                The function result.

            """
            del kwargs
            return cls()

        def public_key(self) -> bytes:
            """Return the public octet key bytes.

            Returns:
                The function result.

            """
            return self._key

        def jwk(self, kid: str | None = None) -> dict:
            """Return a minimal octet JWK dict.

            Returns:
                The function result.

            """
            return {"kty": "oct", "alg": self.algorithm, "kid": kid}

        @property
        def type(self) -> str:
            """Key type identifier.

            Returns:
                The function result.

            """
            return "OCT"

    key = OctetKey()
    with pytest.raises(TypeError, match="PEM private"):
        AbstractKey.private_pem(key)
    with pytest.raises(TypeError, match="DER private"):
        AbstractKey.private_der(key)
    with pytest.raises(TypeError, match="PEM public"):
        AbstractKey.public_pem(key)
    with pytest.raises(TypeError, match="DER public"):
        AbstractKey.public_der(key)


def test_ecdsa_error_and_extra_paths(
    ecdsa_key: ECDSAKey,
    rsa_key: RSAKey,
) -> None:
    """Cover ECDSA load, verify, and generate error paths."""
    pem = ecdsa_key.private_pem()
    assert isinstance(ECDSAAlgorithm.load_key(pem), ec.EllipticCurvePrivateKey)

    with pytest.raises(TypeError, match="Unsupported ECDSA key type"):
        ECDSAAlgorithm.load_key(123)

    with pytest.raises(TypeError, match="Expected an EllipticCurvePrivateKey"):
        ECDSAAlgorithm.load_key(rsa_key.private_pem())

    with pytest.raises(ValueError, match="Unsupported ECDSA algorithm"):
        ECDSAAlgorithm.load_jwk(
            {"alg": "ES128", "d": "AQ", "x": "AQ", "y": "AQ"},
        )

    with pytest.raises(ValueError, match="Unsupported ECDSA algorithm"):
        ECDSAAlgorithm.verify(
            data=b"x",
            signature=b"y",
            key={"x": "AQ", "y": "AQ"},
            alg="ES128",
        )

    with pytest.raises(TypeError, match="Expected an EllipticCurvePublicKey"):
        ECDSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 64,
            key=rsa_key.public_der(),
            alg="ES256",
        )

    assert (
        ECDSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 64,
            key=ecdsa_key.key.public_key(),
            alg="ES256",
        )
        is False
    )

    with pytest.raises(TypeError, match="Unsupported ECDSA verify key type"):
        ECDSAAlgorithm.verify(data=b"x", signature=b"y", key=123, alg="ES256")

    with pytest.raises(TypeError, match="algorithm must be a string"):
        ECDSAKey.generate(algorithm=123)

    for alg in ("ES384", "ES512"):
        generated = ECDSAKey.generate(algorithm=alg)
        assert generated.algorithm == alg
        assert generated.public_key() is not None

    with pytest.raises(ValueError, match="Unsupported ECDSA algorithm"):
        ECDSAKey.generate(algorithm="ES128")

    with pytest.raises(TypeError, match="algorithm must be a string"):
        ECDSAKey.load_pem(pem, algorithm=1)

    with pytest.raises(TypeError, match="Expected an EllipticCurvePrivateKey"):
        ECDSAKey.load_pem(rsa_key.private_pem())

    with pytest.raises(TypeError, match="algorithm must be a string"):
        ECDSAKey.load_der(ecdsa_key.private_der(), algorithm=1)

    with pytest.raises(TypeError, match="Expected an EllipticCurvePrivateKey"):
        ECDSAKey.load_der(rsa_key.private_der())


def test_eddsa_error_and_extra_paths(
    eddsa_key: EdDSAKey,
    rsa_key: RSAKey,
) -> None:
    """Cover EdDSA load, verify, and generate error paths."""
    pem = eddsa_key.private_pem()
    assert isinstance(
        EdDSAAlgorithm.load_key(pem),
        ed25519.Ed25519PrivateKey,
    )

    with pytest.raises(TypeError, match="Unsupported EdDSA key type"):
        EdDSAAlgorithm.load_key(123)

    with pytest.raises(TypeError, match="Expected an Ed25519PrivateKey"):
        EdDSAAlgorithm.load_key(rsa_key.private_pem())

    with pytest.raises(ValueError, match="Unsupported EdDSA algorithm"):
        EdDSAAlgorithm.verify(
            data=b"x",
            signature=b"y",
            key={"x": "AQ"},
            alg="HS256",
        )

    with pytest.raises(TypeError, match="Expected an Ed25519PublicKey"):
        EdDSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 64,
            key=rsa_key.public_der(),
            alg="EdDSA",
        )

    assert (
        EdDSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 64,
            key=eddsa_key.key.public_key(),
            alg="EdDSA",
        )
        is False
    )

    with pytest.raises(TypeError, match="Unsupported EdDSA verify key type"):
        EdDSAAlgorithm.verify(data=b"x", signature=b"y", key=123, alg="EdDSA")

    with pytest.raises(TypeError, match="algorithm must be a string"):
        EdDSAKey.generate(algorithm=123)

    with pytest.raises(TypeError, match="algorithm must be a string"):
        EdDSAKey.load_pem(pem, algorithm=1)

    with pytest.raises(TypeError, match="Expected an Ed25519PrivateKey"):
        EdDSAKey.load_pem(rsa_key.private_pem())

    with pytest.raises(TypeError, match="algorithm must be a string"):
        EdDSAKey.load_der(eddsa_key.private_der(), algorithm=1)

    with pytest.raises(TypeError, match="Expected an Ed25519PrivateKey"):
        EdDSAKey.load_der(rsa_key.private_der())


def test_hmac_error_and_extra_paths(hmac_key_bytes: bytes) -> None:
    """Cover HMAC load, verify, and key helper paths."""
    with pytest.raises(TypeError, match="Unsupported HMAC key type"):
        HMACAlgorithm.load_key(123)

    with pytest.raises(ValueError, match="Unsupported HMAC algorithm"):
        HMACAlgorithm.verify(
            data=b"x",
            signature=b"y",
            key=hmac_key_bytes,
            alg="HS128",
        )

    with pytest.raises(TypeError, match="algorithm must be a string"):
        HMACKey.generate(algorithm=123)

    with pytest.raises(TypeError, match="key_size must be an int"):
        HMACKey.generate(key_size="big")

    key = HMACKey.load_pem(hmac_key_bytes, algorithm="HS384")
    assert key.algorithm == "HS384"
    assert key.public_key() == hmac_key_bytes
    assert key.key_size == len(hmac_key_bytes)
    assert key.private_pem() == hmac_key_bytes
    assert key.private_der() == hmac_key_bytes
    assert key.public_pem() == hmac_key_bytes
    assert key.public_der() == hmac_key_bytes
    assert "kty" in key.jwk()
    assert isinstance(key.kid, str)

    with pytest.raises(TypeError, match="algorithm must be a string"):
        HMACKey.load_pem(hmac_key_bytes, algorithm=1)

    assert HMACKey.load_der(hmac_key_bytes).key == hmac_key_bytes

    with pytest.raises(TypeError, match="algorithm must be a string"):
        HMACKey.load_der(hmac_key_bytes, algorithm=1)


def test_rsa_error_and_extra_paths(
    rsa_key: RSAKey,
    ecdsa_key: ECDSAKey,
) -> None:
    """Cover RSA load, verify, and generate error paths."""
    pem = rsa_key.private_pem()
    assert isinstance(RSAAlgorithm.load_key(pem), rsa.RSAPrivateKey)

    with pytest.raises(TypeError, match="Unsupported RSA key type"):
        RSAAlgorithm.load_key(123)

    with pytest.raises(TypeError, match="Expected an RSAPrivateKey"):
        RSAAlgorithm.load_key(ecdsa_key.private_pem())

    with pytest.raises(ValueError, match="Unsupported RSA algorithm"):
        RSAAlgorithm.verify(
            data=b"x",
            signature=b"y",
            key={"n": "AQ", "e": "AQ"},
            alg="RS128",
        )

    with pytest.raises(TypeError, match="Expected an RSAPublicKey"):
        RSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 64,
            key=ecdsa_key.public_der(),
            alg="RS256",
        )

    assert (
        RSAAlgorithm.verify(
            data=b"x",
            signature=b"y" * 256,
            key=rsa_key.key.public_key(),
            alg="RS256",
        )
        is False
    )

    with pytest.raises(TypeError, match="Unsupported RSA verify key type"):
        RSAAlgorithm.verify(data=b"x", signature=b"y", key=123, alg="RS256")

    ps_key = RSAKey.generate(algorithm="PS256", key_size=2048)
    data = b"payload"
    sig = RSAAlgorithm.sign(data=data, key=ps_key.key, alg="PS256")
    assert RSAAlgorithm.verify(
        data=data,
        signature=sig,
        key=ps_key.public_der(),
        alg="PS256",
    )

    with pytest.raises(TypeError, match="algorithm must be a string"):
        RSAKey.generate(algorithm=123)

    with pytest.raises(TypeError, match="key_size must be an int"):
        RSAKey.generate(key_size="x")

    with pytest.raises(TypeError, match="public_exponent must be an int"):
        RSAKey.generate(public_exponent="x")

    with pytest.raises(TypeError, match="algorithm must be a string"):
        RSAKey.load_pem(pem, algorithm=1)

    with pytest.raises(TypeError, match="Expected an RSAPrivateKey"):
        RSAKey.load_pem(ecdsa_key.private_pem())

    with pytest.raises(TypeError, match="algorithm must be a string"):
        RSAKey.load_der(rsa_key.private_der(), algorithm=1)

    with pytest.raises(TypeError, match="Expected an RSAPrivateKey"):
        RSAKey.load_der(ecdsa_key.private_der())

    assert rsa_key.key_size == rsa_key.key.key_size
    assert rsa_key.public_key() is not None


def test_get_algorithm_unsupported() -> None:
    """Reject unsupported algorithm names."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        get_algorithm("none")


def test_config_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise JWTConfig construction helpers."""
    monkeypatch.setenv(
        "JWT_CONFIG",
        json.dumps({"jwks_url": "https://example.com/jwks.json"}),
    )
    cfg = config.JWTConfig()
    assert cfg.jwks_url == "https://example.com/jwks.json"
    assert hash(cfg)

    cfg2 = config.JWTConfig.init_by_json(
        {"key": {"kty": "oct", "k": "YQ", "alg": "HS256"}},
    )
    assert cfg2.jwk is not None

    cfg3 = config.JWTConfig.init_by_json(
        json.dumps({"jwks_url": "https://example.com/jwks.json"}),
    )
    assert cfg3.jwks_url is not None

    with pytest.raises(TypeError, match="json_data must be a str or dict"):
        config.JWTConfig.init_by_json([1, 2, 3])

    with pytest.raises(ValueError, match="Either jwks_url or key"):
        config.JWTConfig(type=enums.Algorithm.HS256)

    cfg4 = config.JWTConfig(key=None, jwks_url="https://example.com/jwks.json")
    assert cfg4.jwk is None

    cfg5 = config.JWTConfig(key="not-a-pem-key-raw-secret")
    assert isinstance(cfg5.key, dict)

    with pytest.raises(TypeError, match="key must be str, bytes, dict"):
        config.JWTConfig(key=123)

    broken = config.JWTConfig.model_construct(
        key="still-a-string",
        jwks_url="x",
    )
    with pytest.raises(TypeError, match="not normalized"):
        _ = broken.jwk


def test_algorithm_kty_and_token_type() -> None:
    """Check Algorithm kty and TokenType values."""
    assert enums.Algorithm.HS256.kty == "oct"
    assert enums.Algorithm.RS256.kty == "RSA"
    assert enums.Algorithm.ES256.kty == "EC"
    assert enums.Algorithm.EdDSA.kty == "OKP"
    assert enums.TokenType.REFRESH == "refresh"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Ed25519", enums.Algorithm.Ed25519),
        ("ED25519", enums.Algorithm.Ed25519),
        ("ed25519", enums.Algorithm.Ed25519),
        ("EdDSA", enums.Algorithm.EdDSA),
        ("EDDSA", enums.Algorithm.EdDSA),
        ("eddsa", enums.Algorithm.EdDSA),
        ("hs256", enums.Algorithm.HS256),
    ],
)
def test_algorithm_accepts_jose_and_uppercase_names(
    raw: str,
    expected: enums.Algorithm,
) -> None:
    """Match get_algorithm case-folding for enum and Pydantic."""

    class AlgModel(BaseModel):
        alg: enums.Algorithm

    assert enums.Algorithm(raw) is expected
    assert AlgModel.model_validate({"alg": raw}).alg is expected


def test_algorithm_rejects_unknown_and_non_string() -> None:
    """Keep invalid algorithm names as ValueError / ValidationError."""
    with pytest.raises(ValueError, match="Ed448"):
        enums.Algorithm("Ed448")
    with pytest.raises(ValueError, match="25519"):
        enums.Algorithm(25519)  # type: ignore[arg-type]

    class AlgModel(BaseModel):
        alg: enums.Algorithm

    with pytest.raises(ValidationError):
        AlgModel.model_validate({"alg": "Ed448"})


def test_exception_message_branches() -> None:
    """Cover JWT exception message formatting."""
    assert "maximum age" in str(exceptions.JWTMaximumAgeError())
    assert "signature is invalid" in str(exceptions.JWTInvalidSignatureError())
    expected = [
        str(enums.TokenType.ACCESS),
        str(enums.TokenType.REFRESH),
    ]
    provided = "id"
    err = exceptions.JWTInvalidTokenTypeError(
        expected_token_type=expected,
        provided_token_type=provided,
    )
    assert "access, refresh" in str(err)
    expected_one = str(enums.TokenType.ACCESS)
    err2 = exceptions.JWTInvalidTokenTypeError(
        expected_token_type=expected_one,
    )
    assert "expected: access" in str(err2)
    err3 = exceptions.JWTInvalidTokenTypeError(provided_token_type=provided)
    assert "provided: id" in str(err3)
    assert "invalid" in str(exceptions.JWTInvalidTokenTypeError())


def test_schemas_extra_paths(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Cover JWT schema properties and verify failures."""
    token = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=config.JWTConfig(key=test_key.jwk()),
    )
    assert hash(jwt_obj)
    assert jwt_obj.algorithm == enums.Algorithm(test_key.algorithm.upper())
    payload = jwt_obj.unverified_payload
    assert isinstance(payload, dict)
    assert payload["sub"] == test_valid_payload["sub"]
    assert isinstance(jwt_obj.signature, bytes)
    assert isinstance(jwt_obj.signing_input, bytes)

    other = EdDSAKey.generate()
    bad = schemas.JWT(
        token=token,
        config=config.JWTConfig(key=other.jwk()),
    )
    with pytest.raises(exceptions.JWTError):
        _ = bad.header
    with pytest.raises(exceptions.JWTError):
        _ = bad.payload


def test_schemas_temporally_valid_raise(
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Raise when temporal validity check fails."""
    payload = {
        "sub": "user1",
        "exp": int(time.time()) - 100,
    }
    token = sign.generate_jwt(
        header=test_header,
        payload=payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=config.JWTConfig(key=test_key.jwk()),
    )
    with pytest.raises(exceptions.JWTExpiredError):
        jwt_obj.is_temporally_valid(raise_exception=True)


def test_sign_errors_and_str_input(test_key: AbstractKey) -> None:
    """Cover sign_jwt_parts errors and string input."""
    with pytest.raises(ValueError, match="must be provided"):
        sign.sign_jwt_parts(key=test_key, alg=test_key.algorithm)

    header = {"alg": test_key.algorithm, "typ": "JWT"}
    payload = {"sub": "1"}
    header_b64 = utils.b64url_encode(json.dumps(header).encode())
    payload_b64 = utils.b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = sign.sign_jwt_parts(
        key=test_key,
        alg=test_key.algorithm,
        parts=sign.SignInput(signing_input=signing_input),
    )
    assert isinstance(signature, bytes)


def test_utils_bytes_and_str_encode() -> None:
    """Encode and decode base64url bytes and strings."""
    assert utils.b64url_decode(b"YQ") == b"a"
    assert utils.b64url_encode("a") == "YQ"


def test_verify_signature_variants_and_jwt_paths(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Cover verify_signature and verify_jwt edge paths."""
    token = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    header, payload, signature, signing_input = verify.extract_jwt_parts(token)

    with pytest.raises(exceptions.JWTInvalidSignatureError):
        verify.verify_signature(
            alg=header["alg"],
            key=test_key.jwk(),
            data=payload,
            signature=signature,
        )

    assert verify.verify_signature(
        alg=header["alg"],
        key=test_key.jwk(),
        data=signing_input.decode(),
        signature=signature,
    )

    with pytest.raises(exceptions.JWTInvalidSignatureError):
        verify.verify_signature(
            alg=header["alg"],
            key=test_key.jwk(),
            data=signing_input,
            signature=b"\x00" * len(signature),
        )

    with pytest.raises(exceptions.JWKNotFoundError):
        verify.verify_jwt(token=token)

    with patch("usso_jwt.verify.fetch_jwk", return_value=test_key.jwk()):
        assert verify.verify_jwt(
            token=token,
            options=verify.VerifyOptions(
                jwks_url="https://example.com/jwks.json",
                kid="kid",
                maximum_age=10_000,
            ),
        )

    old_payload = dict(test_valid_payload)
    old_payload["iat"] = int(time.time()) - 10_000
    old_token = sign.generate_jwt(
        header=test_header,
        payload=old_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with pytest.raises(exceptions.JWTMaximumAgeError):
        verify.verify_jwt(
            token=old_token,
            options=verify.VerifyOptions(jwk=test_key.jwk(), maximum_age=60),
        )


def test_config_key_bytes(hmac_key_bytes: bytes) -> None:
    """Accept raw bytes as JWTConfig key."""
    cfg = config.JWTConfig(key=hmac_key_bytes)
    assert isinstance(cfg.key, dict)


def test_unverified_jwt_hash_and_payload(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Hash UnverifiedJWT and read unverified payload."""
    token = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    unverified = schemas.UnverifiedJWT(token=token)
    assert hash(unverified) == hash(token)
    payload = unverified.unverified_payload
    assert isinstance(payload, dict)
    assert payload["sub"] == test_valid_payload["sub"]


def test_jwt_header_payload_when_verify_returns_false(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Raise when verify returns False for header/payload."""
    token = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    jwt_obj = schemas.JWT(
        token=token,
        config=config.JWTConfig(key=test_key.jwk()),
    )
    with patch.object(schemas.JWT, "verify", return_value=False):
        with pytest.raises(exceptions.JWTError, match="not valid"):
            _ = jwt_obj.header
        with pytest.raises(exceptions.JWTError, match="not valid"):
            _ = jwt_obj.payload


def test_verify_jwt_raises_when_signature_helper_returns_false(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> None:
    """Raise when verify_signature helper returns False."""
    token = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    with (
        patch("usso_jwt.verify.verify_signature", return_value=False),
        pytest.raises(exceptions.JWTInvalidSignatureError),
    ):
        verify.verify_jwt(
            token=token,
            options=verify.VerifyOptions(jwk=test_key.jwk()),
        )


def test_eddsa_public_key_method(eddsa_key: EdDSAKey) -> None:
    """Return Ed25519 public key object."""
    public = eddsa_key.public_key()
    assert isinstance(public, ed25519.Ed25519PublicKey)


def test_utils_jwk_helpers(eddsa_key: EdDSAKey) -> None:
    """Exercise JWK field helper utilities."""
    jwk = eddsa_key.jwk()
    assert utils.as_jwk_dict(jwk)["kty"] == "OKP"
    with pytest.raises(TypeError, match="Expected a JWK dict"):
        utils.as_jwk_dict(123)

    assert isinstance(utils.jwk_b64_field(jwk, "x"), str)
    with pytest.raises(TypeError, match="must be str or bytes"):
        utils.jwk_b64_field({"x": 1}, "x")

    rsa_jwk = RSAKey.generate().jwk()
    assert isinstance(utils.jwk_int_field(rsa_jwk, "n"), int)

    assert utils.jwk_str_field(jwk, "alg") == "EdDSA"
    assert utils.jwk_str_field(jwk, "missing", "fallback") == "fallback"
    with pytest.raises(KeyError):
        utils.jwk_str_field(jwk, "missing")
    with pytest.raises(TypeError, match="must be str"):
        utils.jwk_str_field({"alg": 1}, "alg")


def test_eddsa_load_jwk_rejects_non_str_alg(eddsa_key: EdDSAKey) -> None:
    """Reject non-string alg when loading EdDSA JWK."""
    public_x = eddsa_key.key.public_key().public_bytes_raw()
    private_d = eddsa_key.key.private_bytes_raw()
    jwk: dict[str, object] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": utils.b64url_encode(public_x),
        "d": utils.b64url_encode(private_d),
        "alg": 123,
    }
    with pytest.raises(TypeError, match="alg"):
        EdDSAKey.load_jwk(jwk)
