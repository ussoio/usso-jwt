"""Algorithm names are accepted in any casing."""

import pytest

from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey, get_algorithm, normalize_alg
from usso_jwt.enums import Algorithm
from usso_jwt.schemas import JWT, JWTConfig

SPELLINGS = [
    ("Ed25519", "ED25519"),
    ("ed25519", "ED25519"),
    ("ED25519", "ED25519"),
    ("EdDSA", "EDDSA"),
    ("eddsa", "EDDSA"),
    ("es256", "ES256"),
    ("rs256", "RS256"),
    ("Ps384", "PS384"),
    ("hs512", "HS512"),
]


@pytest.mark.parametrize(("alg", "expected"), SPELLINGS)
def test_normalize_alg(alg: str, expected: str) -> None:
    """Every spelling maps to one canonical upper-case name."""
    assert normalize_alg(alg) == expected
    assert normalize_alg(f" {alg} ") == expected
    assert Algorithm(alg) == Algorithm(expected)


@pytest.mark.parametrize(("alg", "_expected"), SPELLINGS)
def test_any_casing_signs_and_verifies(alg: str, _expected: str) -> None:
    """generate, sign and verify accept the name in any casing."""
    key = AbstractKey.generate_algorithm(alg)
    assert get_algorithm(alg)
    token = sign.generate_jwt(
        header={"alg": alg, "typ": "JWT"},
        payload={"sub": "s"},
        key=key.private_der()
        if hasattr(key, "private_der")
        else key.private_pem(),
        alg=alg,
    )
    jwt = JWT(token=token, config=JWTConfig(key=key.jwk()))
    assert jwt.verify()


def test_unknown_alg_still_rejected() -> None:
    """Case-insensitivity does not widen the accepted set."""
    with pytest.raises(ValueError, match="Unsupported"):
        AbstractKey.generate_algorithm("none")
