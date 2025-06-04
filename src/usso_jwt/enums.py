from enum import StrEnum


class Algorithm(StrEnum):
    # HMAC with SHA-2
    HS256 = "HS256"  # HMAC with SHA-256
    HS384 = "HS384"  # HMAC with SHA-384
    HS512 = "HS512"  # HMAC with SHA-512

    # RSA with SHA-2
    RS256 = "RS256"  # RSA with SHA-256
    RS384 = "RS384"  # RSA with SHA-384
    RS512 = "RS512"  # RSA with SHA-512

    # ECDSA with SHA-2
    ES256 = "ES256"  # ECDSA with SHA-256
    ES384 = "ES384"  # ECDSA with SHA-384
    ES512 = "ES512"  # ECDSA with SHA-512

    # RSASSA-PSS with SHA-2
    PS256 = "PS256"  # RSASSA-PSS with SHA-256
    PS384 = "PS384"  # RSASSA-PSS with SHA-384
    PS512 = "PS512"  # RSASSA-PSS with SHA-512

    # EdDSA with SHA-2
    EdDSA = "EDDSA"  # EdDSA with SHA-512
    Ed25519 = "ED25519"  # EdDSA with SHA-512

    @property
    def kty(self) -> str:
        return {
            Algorithm.HS256: "oct",
            Algorithm.HS384: "oct",
            Algorithm.HS512: "oct",
            Algorithm.RS256: "RSA",
            Algorithm.RS384: "RSA",
            Algorithm.RS512: "RSA",
            Algorithm.ES256: "EC",
            Algorithm.ES384: "EC",
            Algorithm.ES512: "EC",
            Algorithm.PS256: "RSA",
            Algorithm.PS384: "RSA",
            Algorithm.PS512: "RSA",
            Algorithm.EdDSA: "OKP",
            Algorithm.Ed25519: "OKP",
        }[self]
