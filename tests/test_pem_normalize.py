"""Tests for PEM key material normalization (escaped newlines)."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from usso_jwt.algorithms import (
    AbstractKey,
    EdDSAAlgorithm,
    RSAAlgorithm,
)
from usso_jwt.utils import (
    is_pem_key_material,
    normalize_pem_key_material,
)


def _ed25519_pem() -> bytes:
    """Return a valid Ed25519 PKCS8 PEM private key.

    Returns:
        PEM-encoded private key bytes.

    """
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_pem() -> bytes:
    """Return a valid RSA PKCS8 PEM private key.

    Returns:
        PEM-encoded private key bytes.

    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_normalize_multiline_pem_unchanged() -> None:
    """Valid multiline PEM bytes are unchanged aside from strip."""
    pem = _ed25519_pem()
    assert normalize_pem_key_material(pem) == pem.strip()
    assert normalize_pem_key_material(pem.decode()) == pem.strip()


def test_normalize_literal_escaped_newlines() -> None:
    r"""Single-line PEM with literal ``\\n`` becomes real newlines."""
    pem = _ed25519_pem()
    escaped = pem.replace(b"\n", b"\\n")
    assert b"\\n" in escaped
    assert b"\n" not in escaped
    assert normalize_pem_key_material(escaped) == pem.strip()


def test_normalize_literal_escaped_crlf_and_cr() -> None:
    r"""Literal ``\\r\\n`` and ``\\r`` are converted to newlines."""
    pem = _ed25519_pem().strip().decode()
    escaped_crlf = pem.replace("\n", "\\r\\n")
    assert normalize_pem_key_material(escaped_crlf) == pem.encode()

    escaped_cr = pem.replace("\n", "\\r")
    assert normalize_pem_key_material(escaped_cr) == pem.encode()


def test_normalize_strips_whitespace_and_quotes() -> None:
    """Leading/trailing whitespace and surrounding quotes are stripped."""
    pem = _ed25519_pem().strip().decode()
    escaped = pem.replace("\n", "\\n")
    wrapped = f'  "{escaped}"  \n'
    assert normalize_pem_key_material(wrapped) == pem.encode()
    assert normalize_pem_key_material(f"'{escaped}'") == pem.encode()


def test_is_pem_key_material() -> None:
    """Detect PEM text even when newlines are escaped."""
    pem = _ed25519_pem()
    assert is_pem_key_material(pem)
    assert is_pem_key_material(pem.decode())
    assert is_pem_key_material(pem.replace(b"\n", b"\\n"))
    assert is_pem_key_material(f'  "{pem.decode()}"  ')
    assert not is_pem_key_material(b"\x30\x82")
    assert not is_pem_key_material(123)


def test_eddsa_load_key_multiline_pem() -> None:
    """EdDSA load_key accepts valid multiline PEM bytes."""
    pem = _ed25519_pem()
    loaded = EdDSAAlgorithm.load_key(pem)
    assert isinstance(loaded, ed25519.Ed25519PrivateKey)


def test_eddsa_load_key_escaped_newline_bytes() -> None:
    r"""EdDSA load_key accepts single-line PEM with literal ``\\n``."""
    pem = _ed25519_pem()
    escaped = pem.replace(b"\n", b"\\n")
    loaded = EdDSAAlgorithm.load_key(escaped)
    assert isinstance(loaded, ed25519.Ed25519PrivateKey)


def test_eddsa_load_key_escaped_newline_str_with_whitespace() -> None:
    """EdDSA load_key accepts str PEM with whitespace and quotes."""
    pem = _ed25519_pem().strip().decode()
    escaped = pem.replace("\n", "\\n")
    loaded = EdDSAAlgorithm.load_key(f"  '{escaped}'  ")
    assert isinstance(loaded, ed25519.Ed25519PrivateKey)


def test_rsa_load_key_escaped_newline_pem() -> None:
    """RSA load_key uses the same PEM normalization path."""
    pem = _rsa_pem()
    escaped = pem.replace(b"\n", b"\\n")
    loaded = RSAAlgorithm.load_key(escaped)
    assert isinstance(loaded, rsa.RSAPrivateKey)
    loaded_str = RSAAlgorithm.load_key(escaped.decode())
    assert isinstance(loaded_str, rsa.RSAPrivateKey)


def test_abstract_load_pem_escaped_newlines() -> None:
    """AbstractKey.load_pem normalizes escaped newlines via shared helper."""
    pem = _ed25519_pem()
    escaped = pem.replace(b"\n", b"\\n")
    key = AbstractKey.load_pem(escaped)
    assert key.type == "EdDSA"
