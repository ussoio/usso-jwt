# USSO-JWT

A secure and flexible JWT (JSON Web Token) implementation for Python, designed to work seamlessly with the USSO authentication system. This library provides a robust set of tools for creating, signing, verifying, and managing JWTs with support for multiple cryptographic algorithms.

## Features

- **Multiple Algorithm Support**:
  - HMAC (HS256, HS384, HS512)
  - RSA (RS256, RS384, RS512, PS256, PS384, PS512)
  - ECDSA (ES256, ES384, ES512)
  - EdDSA (Ed25519)

- **JWK Support**: Full support for JSON Web Keys (JWK) format
- **PEM Support**: Load keys from PEM-encoded files
- **Type Safety**: Built with type hints for better IDE support and code safety
- **Comprehensive Testing**: Thorough test coverage for all algorithms and features

## Installation

Install using pip:

```bash
pip install usso-jwt
```

## Quick Start

### Creating and Signing a JWT

```python
from usso_jwt import JWT

# Create a JWT with a payload
jwt = JWT(
    payload={
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022
    }
)

# Sign with HMAC
token = jwt.sign(hmac_key, "HS256")

# Sign with RSA
token = jwt.sign(rsa_private_key, "RS256")

# Sign with ECDSA
token = jwt.sign(ecdsa_private_key, "ES256")

# Sign with EdDSA
token = jwt.sign(eddsa_private_key, "Ed25519")
```

### Verifying a JWT

```python
from usso_jwt import JWT

# Verify with HMAC
jwt = JWT.verify(token, hmac_key, "HS256")

# Verify with RSA
jwt = JWT.verify(token, rsa_public_key, "RS256")

# Verify with ECDSA
jwt = JWT.verify(token, ecdsa_public_key, "ES256")

# Verify with EdDSA
jwt = JWT.verify(token, eddsa_public_key, "Ed25519")
```

### Working with JWKs

```python
from usso_jwt import JWT

# Create a JWT with a JWK
jwt = JWT(payload={"sub": "1234567890"})

# Sign with a JWK
token = jwt.sign(jwk, "RS256")

# Verify with a JWK
jwt = JWT.verify(token, jwk, "RS256")
```

## Supported Algorithms

### HMAC (Symmetric)
- HS256: HMAC with SHA-256
- HS384: HMAC with SHA-384
- HS512: HMAC with SHA-512

### RSA (Asymmetric)
- RS256: RSA with SHA-256
- RS384: RSA with SHA-384
- RS512: RSA with SHA-512
- PS256: RSA-PSS with SHA-256
- PS384: RSA-PSS with SHA-384
- PS512: RSA-PSS with SHA-512

### ECDSA (Asymmetric)
- ES256: ECDSA with P-256 and SHA-256
- ES384: ECDSA with P-384 and SHA-384
- ES512: ECDSA with P-521 and SHA-512

### EdDSA (Asymmetric)
- EdDSA: Ed25519

## Security Considerations

- Always use strong keys appropriate for your chosen algorithm
- For HMAC, use keys at least as long as the hash output (e.g., 32 bytes for HS256)
- For RSA, use keys of at least 2048 bits
- For ECDSA, use the recommended curves (P-256, P-384, P-521)
- Store private keys securely and never expose them
- Use appropriate key rotation policies

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the LICENSE file for details.