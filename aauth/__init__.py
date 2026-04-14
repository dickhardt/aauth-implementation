"""AAuth - Agent Authentication Protocol implementation for Python."""

__version__ = "0.1.0"

# Errors and error codes
from .errors import (
    AAuthError,
    SignatureError,
    TokenError,
    ChallengeError,
    MetadataError,
    JWKSError,
    build_error_response,
    # Signature-Error header codes (draft-hardt-httpbis-signature-key)
    ERROR_INVALID_REQUEST,
    ERROR_INVALID_INPUT,
    ERROR_INVALID_SIGNATURE,
    ERROR_UNSUPPORTED_ALGORITHM,
    ERROR_INVALID_KEY,
    ERROR_UNKNOWN_KEY,
    ERROR_INVALID_JWT,
    ERROR_EXPIRED_JWT,
    # Token endpoint error codes (draft-hardt-aauth-protocol)
    ERROR_INVALID_AGENT_TOKEN,
    ERROR_EXPIRED_AGENT_TOKEN,
    ERROR_INVALID_RESOURCE_TOKEN,
    ERROR_EXPIRED_RESOURCE_TOKEN,
    ERROR_INVALID_AUTH_TOKEN,
    ERROR_SERVER_ERROR,
    # Polling error codes (draft-hardt-aauth-protocol)
    ERROR_DENIED,
    ERROR_ABANDONED,
    ERROR_EXPIRED,
    ERROR_INVALID_CODE,
    ERROR_SLOW_DOWN,
    ERROR_INTERACTION_REQUIRED,
)

# Identifiers
from .identifiers import (
    validate_server_identifier,
    validate_endpoint_url,
    validate_other_url,
)

# Debug
from .debug import (
    _is_debug_enabled,
    _is_http_debug_enabled,
    _is_jwt_token_debug_enabled,
)

# HTTP abstraction
from .http.request import AAuthRequest
from .http.response import AAuthResponse

# Key management
from .keys.keypair import generate_ed25519_keypair
from .keys.jwk import (
    public_key_to_jwk,
    jwk_to_public_key,
    calculate_jwk_thumbprint,
    generate_jwks
)
from .keys.jwks import JWKSFetcher, JWKSCache, DefaultHTTPClient

# HTTP Message Signing
from .signing.signer import sign_request
from .signing.verifier import verify_signature
from .signing.algorithms import (
    ED25519,
    RSA_PSS_SHA512,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    SUPPORTED_ALGORITHMS,
    is_supported
)

# Token handling
from .tokens.agent_token import create_agent_token, verify_agent_token
from .tokens.auth_token import create_auth_token, parse_token_claims, verify_token
from .tokens.resource_token import create_resource_token

# Header handling — Accept-Signature (signature-level challenges)
from .headers.accept_signature import (
    build_accept_signature,
    parse_accept_signature,
    SIGKEY_JKT,
    SIGKEY_URI,
    SIGKEY_X509,
)

# Header handling — AAuth-Requirement (protocol-level requirements)
from .headers.signature_key import build_signature_key_header, parse_signature_key
from .headers.signature_input import build_signature_input_header, parse_signature_input
from .headers.signature import build_signature_header, parse_signature
from .headers.agent_auth import parse_agent_auth_header, build_agent_auth_challenge
from .headers.aauth_mission import build_aauth_mission, parse_aauth_mission, mission_from_header
from .headers.aauth_header import (
    parse_aauth_header,
    parse_aauth_requirement,
    parse_signature_requirement,
    build_pseudonym_challenge,
    build_pseudonym_requirement,
    build_identity_challenge,
    build_identity_requirement,
    build_auth_token_challenge,
    build_auth_token_requirement,
    build_interaction_challenge,
    build_interaction_requirement,
    build_approval_challenge,
    build_approval_requirement,
    build_aauth_error,
    build_signature_error,
    parse_aauth_error,
    parse_signature_error,
    REQUIRE_PSEUDONYM,
    REQUIRE_IDENTITY,
    REQUIRE_AUTH_TOKEN,
    REQUIRE_INTERACTION,
    REQUIRE_APPROVAL,
    REQUIRE_CLARIFICATION,
    REQUIRE_CLAIMS,
    build_clarification_requirement,
    build_claims_requirement,
)

# Header handling — AAuth-Capabilities and AAuth-Access
from .headers.aauth_capabilities import (
    build_aauth_capabilities,
    parse_aauth_capabilities,
    CAPABILITY_INTERACTION,
    CAPABILITY_CLARIFICATION,
    CAPABILITY_PAYMENT,
)
from .headers.aauth_access import build_aauth_access, parse_aauth_access

# Metadata
from .metadata.agent import generate_agent_metadata
from .metadata.resource import generate_resource_metadata
from .metadata.auth_server import (
    generate_ps_metadata,
    generate_mm_metadata,
    generate_as_metadata,
    generate_auth_metadata,
    fetch_auth_metadata,
    fetch_metadata,
)

# Agent role
from .agent.signer import AgentRequestSigner
from .agent.challenge_handler import ChallengeHandler

# Resource role
from .resource.verifier import RequestVerifier
from .resource.challenge_builder import ChallengeBuilder
from .resource.token_issuer import ResourceTokenIssuer

__all__ = [
    # Version
    "__version__",

    # Errors and error codes
    "AAuthError",
    "SignatureError",
    "TokenError",
    "ChallengeError",
    "MetadataError",
    "JWKSError",
    "build_error_response",
    "ERROR_INVALID_REQUEST",
    "ERROR_INVALID_INPUT",
    "ERROR_INVALID_SIGNATURE",
    "ERROR_UNSUPPORTED_ALGORITHM",
    "ERROR_INVALID_KEY",
    "ERROR_UNKNOWN_KEY",
    "ERROR_INVALID_JWT",
    "ERROR_EXPIRED_JWT",
    "ERROR_INVALID_AGENT_TOKEN",
    "ERROR_EXPIRED_AGENT_TOKEN",
    "ERROR_INVALID_RESOURCE_TOKEN",
    "ERROR_EXPIRED_RESOURCE_TOKEN",
    "ERROR_INVALID_AUTH_TOKEN",
    "ERROR_SERVER_ERROR",
    "ERROR_DENIED",
    "ERROR_ABANDONED",
    "ERROR_EXPIRED",
    "ERROR_INVALID_CODE",
    "ERROR_SLOW_DOWN",
    "ERROR_INTERACTION_REQUIRED",

    # Identifiers
    "validate_server_identifier",
    "validate_endpoint_url",
    "validate_other_url",

    # Debug
    "_is_debug_enabled",
    "_is_http_debug_enabled",
    "_is_jwt_token_debug_enabled",

    # HTTP abstraction
    "AAuthRequest",
    "AAuthResponse",

    # Key management
    "generate_ed25519_keypair",
    "public_key_to_jwk",
    "jwk_to_public_key",
    "calculate_jwk_thumbprint",
    "generate_jwks",
    "JWKSFetcher",
    "JWKSCache",
    "DefaultHTTPClient",

    # HTTP Message Signing
    "sign_request",
    "verify_signature",
    "ED25519",
    "RSA_PSS_SHA512",
    "RSA_PSS_SHA256",
    "ECDSA_P256_SHA256",
    "ECDSA_P384_SHA384",
    "SUPPORTED_ALGORITHMS",
    "is_supported",

    # Token handling
    "create_agent_token",
    "verify_agent_token",
    "create_auth_token",
    "parse_token_claims",
    "verify_token",
    "create_resource_token",

    # Accept-Signature header
    "build_accept_signature",
    "parse_accept_signature",
    "SIGKEY_JKT",
    "SIGKEY_URI",
    "SIGKEY_X509",

    # AAuth-Requirement header
    "parse_aauth_header",
    "parse_aauth_requirement",
    "parse_signature_requirement",
    "build_pseudonym_requirement",
    "build_identity_requirement",
    "build_auth_token_requirement",
    "build_interaction_requirement",
    "build_approval_requirement",
    "build_clarification_requirement",
    "build_claims_requirement",

    # Signature-Key / Signature-Input / Signature headers
    "build_signature_key_header",
    "parse_signature_key",
    "build_signature_input_header",
    "parse_signature_input",
    "build_signature_header",
    "parse_signature",

    # AAuth-Mission header
    "build_aauth_mission",
    "parse_aauth_mission",
    "mission_from_header",

    # AAuth-Capabilities header
    "build_aauth_capabilities",
    "parse_aauth_capabilities",
    "CAPABILITY_INTERACTION",
    "CAPABILITY_CLARIFICATION",
    "CAPABILITY_PAYMENT",

    # AAuth-Access header
    "build_aauth_access",
    "parse_aauth_access",

    # Signature-Error header
    "build_aauth_error",
    "build_signature_error",
    "parse_aauth_error",
    "parse_signature_error",

    # Requirement constants
    "REQUIRE_PSEUDONYM",
    "REQUIRE_IDENTITY",
    "REQUIRE_AUTH_TOKEN",
    "REQUIRE_INTERACTION",
    "REQUIRE_APPROVAL",
    "REQUIRE_CLARIFICATION",
    "REQUIRE_CLAIMS",

    # Backward-compatible aliases
    "parse_agent_auth_header",
    "build_agent_auth_challenge",

    # Metadata
    "generate_agent_metadata",
    "generate_resource_metadata",
    "generate_ps_metadata",
    "generate_mm_metadata",
    "generate_as_metadata",
    "generate_auth_metadata",
    "fetch_auth_metadata",
    "fetch_metadata",

    # Agent role
    "AgentRequestSigner",
    "ChallengeHandler",

    # Resource role
    "RequestVerifier",
    "ChallengeBuilder",
    "ResourceTokenIssuer",
]
