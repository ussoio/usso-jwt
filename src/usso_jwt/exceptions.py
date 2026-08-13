"""JWT-related exceptions."""


class JWTError(Exception):
    """Base exception for JWT-related errors."""

    def __init__(self, message: str | None = None, *args: object) -> None:
        """Initialize with an optional error message."""
        self.message = message
        super().__init__(message, *args)


class JWTExpiredError(JWTError):
    """Raised when a JWT has expired."""

    def __init__(self) -> None:
        """Initialize with a fixed expired-token message."""
        self.message = "JWT has expired"
        super().__init__(self.message)


class JWTNotValidYetError(JWTError):
    """Raised when a JWT's 'nbf' claim indicates it's not valid yet."""

    def __init__(self) -> None:
        """Initialize with a fixed not-yet-valid message."""
        self.message = "JWT is not valid yet"
        super().__init__(self.message)


class JWTMaximumAgeError(JWTError):
    """Raised when a JWT's 'iat' claim is older than the maximum age."""

    def __init__(self) -> None:
        """Initialize with a fixed maximum-age message."""
        self.message = "JWT is older than the maximum age"
        super().__init__(self.message)


class JWTIssuedInFutureError(JWTError):
    """Raised when a JWT's 'iat' claim is in the future."""

    def __init__(self) -> None:
        """Initialize with a fixed future-issued message."""
        self.message = "JWT is issued in the future"
        super().__init__(self.message)


class JWTInvalidSignatureError(JWTError):
    """Raised when a JWT's signature is invalid."""

    def __init__(self) -> None:
        """Initialize with a fixed invalid-signature message."""
        self.message = "JWT signature is invalid"
        super().__init__(self.message)


class JWTInvalidFormatError(JWTError):
    """Raised when a JWT has an invalid format."""

    def __init__(self) -> None:
        """Initialize with a fixed invalid-format message."""
        self.message = "JWT has an invalid format"
        super().__init__(self.message)


class JWKNotFoundError(JWTError):
    """Raised when a JWK with the specified kid is not found."""

    def __init__(self) -> None:
        """Initialize with a fixed missing-JWK message."""
        self.message = "JWK with the specified kid is not found"
        super().__init__(self.message)


class JWTInvalidAudienceError(JWTError):
    """Raised when a JWT's audience claim is invalid."""

    def __init__(self) -> None:
        """Initialize with a fixed invalid-audience message."""
        self.message = "JWT audience claim is invalid"
        super().__init__(self.message)


class JWTInvalidTokenTypeError(JWTError):
    """Raised when a JWT's token type claim is invalid."""

    def __init__(
        self,
        expected_token_type: str | list[str] | None = None,
        provided_token_type: str | None = None,
    ) -> None:
        """Initialize with expected/provided token type details."""
        self.message = "JWT token type claim is invalid"
        if isinstance(expected_token_type, list):
            expected_display: str | None = ", ".join(
                str(item) for item in expected_token_type
            )
        elif expected_token_type is not None:
            expected_display = str(expected_token_type)
        else:
            expected_display = None
        if expected_display and provided_token_type:
            self.message += (
                f" (expected: {expected_display},"
                f" provided: {provided_token_type})"
            )
        elif expected_display:
            self.message += f" (expected: {expected_display})"
        elif provided_token_type:
            self.message += f" (provided: {provided_token_type})"
        super().__init__(self.message)


class JWTInvalidACRError(JWTError):
    """Raised when a JWT's acr claim is invalid."""

    def __init__(self) -> None:
        """Initialize with a fixed invalid-ACR message."""
        self.message = "JWT acr claim is invalid"
        super().__init__(self.message)


class JWTInvalidIssuerError(JWTError):
    """Raised when a JWT's issuer claim is invalid."""

    def __init__(self) -> None:
        """Initialize with a fixed invalid-issuer message."""
        self.message = "JWT issuer claim is invalid"
        super().__init__(self.message)


class JWTMissingAudienceError(JWTError):
    """Raised when a JWT's audience claim is required but missing."""

    def __init__(self) -> None:
        """Initialize with a fixed missing-audience message."""
        self.message = "JWT audience claim is required but missing"
        super().__init__(self.message)
