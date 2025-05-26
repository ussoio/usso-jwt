"""JWT-related exceptions."""


class JWTError(Exception):
    """Base exception for JWT-related errors."""


class JWTExpiredError(JWTError):
    """Raised when a JWT has expired."""


class JWTNotValidYetError(JWTError):
    """Raised when a JWT's 'nbf' claim indicates it's not valid yet."""


class JWTIssuedInFutureError(JWTError):
    """Raised when a JWT's 'iat' claim is in the future."""


class JWTInvalidSignatureError(JWTError):
    """Raised when a JWT's signature is invalid."""


class JWTInvalidFormatError(JWTError):
    """Raised when a JWT has an invalid format."""


class JWKNotFoundError(JWTError):
    """Raised when a JWK with the specified kid is not found."""
