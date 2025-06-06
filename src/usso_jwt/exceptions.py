"""JWT-related exceptions."""


class JWTError(Exception):
    """Base exception for JWT-related errors."""

    def __init__(self, message: str = None, *args):
        self.message = message
        super().__init__(message, *args)


class JWTExpiredError(JWTError):
    """Raised when a JWT has expired."""

    def __init__(self):
        self.message = "JWT has expired"
        super().__init__(self.message)


class JWTNotValidYetError(JWTError):
    """Raised when a JWT's 'nbf' claim indicates it's not valid yet."""

    def __init__(self):
        self.message = "JWT is not valid yet"
        super().__init__(self.message)


class JWTIssuedInFutureError(JWTError):
    """Raised when a JWT's 'iat' claim is in the future."""

    def __init__(self):
        self.message = "JWT is issued in the future"
        super().__init__(self.message)


class JWTInvalidSignatureError(JWTError):
    """Raised when a JWT's signature is invalid."""

    def __init__(self):
        self.message = "JWT signature is invalid"
        super().__init__(self.message)


class JWTInvalidFormatError(JWTError):
    """Raised when a JWT has an invalid format."""

    def __init__(self):
        self.message = "JWT has an invalid format"
        super().__init__(self.message)


class JWKNotFoundError(JWTError):
    """Raised when a JWK with the specified kid is not found."""

    def __init__(self):
        self.message = "JWK with the specified kid is not found"
        super().__init__(self.message)


class JWTInvalidAudienceError(JWTError):
    """Raised when a JWT's audience claim is invalid."""

    def __init__(self):
        self.message = "JWT audience claim is invalid"
        super().__init__(self.message)


class JWTInvalidTokenTypeError(JWTError):
    """Raised when a JWT's token type claim is invalid."""

    def __init__(
        self,
        expected_token_type: str | None = None,
        provided_token_type: str | None = None,
    ):
        self.message = "JWT token type claim is invalid"
        if expected_token_type and provided_token_type:
            self.message += (
                f" (expected: {expected_token_type},"
                f" provided: {provided_token_type})"
            )
        elif expected_token_type:
            self.message += f" (expected: {expected_token_type})"
        elif provided_token_type:
            self.message += f" (provided: {provided_token_type})"
        super().__init__(self.message)


class JWTInvalidACRError(JWTError):
    """Raised when a JWT's acr claim is invalid."""

    def __init__(self):
        self.message = "JWT acr claim is invalid"
        super().__init__(self.message)


class JWTInvalidIssuerError(JWTError):
    """Raised when a JWT's issuer claim is invalid."""

    def __init__(self):
        self.message = "JWT issuer claim is invalid"
        super().__init__(self.message)


class JWTMissingAudienceError(JWTError):
    """Raised when a JWT's audience claim is required but missing."""

    def __init__(self):
        self.message = "JWT audience claim is required but missing"
        super().__init__(self.message)
