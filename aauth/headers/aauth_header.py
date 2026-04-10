"""AAuth-Requirement and Signature-Error HTTP response header parsing and building.

The AAuth-Requirement header (from the AAuth protocol spec) conveys protocol-level
requirements: auth-token, interaction, approval, clarification, claims.

Signature-level challenges (pseudonym/identity) are now handled by the
Accept-Signature header with the `sigkey` parameter (see accept_signature.py).

The Signature-Error header (from draft-hardt-httpbis-signature-key) conveys
signature verification errors.
"""

import re
from typing import Dict, Any, Optional, List
from ..errors import ChallengeError


# AAuth protocol requirement levels (from AAuth protocol spec)
REQUIRE_AUTH_TOKEN = "auth-token"
REQUIRE_INTERACTION = "interaction"
REQUIRE_APPROVAL = "approval"
REQUIRE_CLARIFICATION = "clarification"
REQUIRE_CLAIMS = "claims"

# Kept for backward compatibility — now handled by Accept-Signature sigkey values
REQUIRE_PSEUDONYM = "pseudonym"
REQUIRE_IDENTITY = "identity"

# Signature-Error codes (from draft-hardt-httpbis-signature-key)
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INVALID_INPUT = "invalid_input"
ERROR_INVALID_SIGNATURE = "invalid_signature"
ERROR_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
ERROR_INVALID_KEY = "invalid_key"
ERROR_UNKNOWN_KEY = "unknown_key"
ERROR_INVALID_JWT = "invalid_jwt"
ERROR_EXPIRED_JWT = "expired_jwt"


def parse_aauth_requirement(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement response header.

    Formats:
        AAuth-Requirement: requirement=auth-token; resource-token="..."
        AAuth-Requirement: requirement=interaction; url="..."; code="ABCD1234"
        AAuth-Requirement: requirement=approval
        AAuth-Requirement: requirement=clarification
        AAuth-Requirement: requirement=claims

    Args:
        header_value: AAuth-Requirement header value

    Returns:
        Dictionary with:
        - requirement: str
        - resource_token: Optional[str]
        - url: Optional[str]
        - code: Optional[str]
        - algorithms: Optional[List[str]]
        - required_input: Optional[List[str]]

    Raises:
        ChallengeError: If header format is invalid
    """
    try:
        result = {
            "requirement": None,
            "resource_token": None,
            "url": None,
            "code": None,
            "algorithms": None,
            "required_input": None,
        }

        # Extract requirement value
        require_match = re.search(r'requirement=([\w-]+)', header_value)
        if not require_match:
            raise ChallengeError("AAuth-Requirement header must include 'requirement' parameter")

        result["requirement"] = require_match.group(1)

        # Extract resource-token parameter
        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        # Extract url parameter
        url_match = re.search(r'url="([^"]+)"', header_value)
        if url_match:
            result["url"] = url_match.group(1)

        # Extract code parameter
        code_match = re.search(r'code="([^"]+)"', header_value)
        if code_match:
            result["code"] = code_match.group(1)

        # Extract inner list parameters (algorithms, required_input)
        for param_name in ("algorithms", "required_input"):
            list_match = re.search(rf'{param_name}=\(([^)]+)\)', header_value)
            if list_match:
                inner = list_match.group(1)
                result[param_name] = re.findall(r'"([^"]+)"', inner)

        return result

    except ChallengeError:
        raise
    except Exception as e:
        raise ChallengeError(f"Failed to parse AAuth-Requirement header: {e}") from e

# Backward-compatible alias
parse_signature_requirement = parse_aauth_requirement


def build_auth_token_requirement(
    resource_token: str,
) -> str:
    """Build AAuth-Requirement requiring an auth token.

    The PS is discovered from the resource token's aud claim.

    Args:
        resource_token: Resource token JWT string

    Returns:
        AAuth-Requirement header value with resource-token
    """
    return f'requirement=auth-token; resource-token="{resource_token}"'


def build_interaction_requirement(url: str, code: str) -> str:
    """Build AAuth-Requirement indicating user interaction is required.

    Args:
        url: Interaction URL (HTTPS, no query or fragment)
        code: Interaction code (short alphanumeric)

    Returns:
        AAuth-Requirement header value with url and interaction code
    """
    return f'requirement=interaction; url="{url}"; code="{code}"'


def build_approval_requirement() -> str:
    """Build AAuth-Requirement indicating approval is pending.

    Returns:
        AAuth-Requirement header value: requirement=approval
    """
    return "requirement=approval"


def build_clarification_requirement() -> str:
    """Build AAuth-Requirement indicating a clarification question.

    The clarification text, timeout, and options are in the response body.

    Returns:
        AAuth-Requirement header value: requirement=clarification
    """
    return "requirement=clarification"


def build_claims_requirement() -> str:
    """Build AAuth-Requirement indicating identity claims are required.

    The required_claims array is in the response body.
    Used by ASes to request identity claims from PSes during token issuance.

    Returns:
        AAuth-Requirement header value: requirement=claims
    """
    return "requirement=claims"


# --- Signature-Error header ---

def build_signature_error(
    error: str,
    required_input: Optional[List[str]] = None,
    supported_algorithms: Optional[List[str]] = None,
) -> str:
    """Build Signature-Error header value per draft-hardt-httpbis-signature-key.

    Args:
        error: Error code (one of the ERROR_* constants)
        required_input: For invalid_input - list of required covered components
        supported_algorithms: For unsupported_algorithm - list of supported algorithms

    Returns:
        Signature-Error header value
    """
    parts = [f"error={error}"]

    if required_input and error == ERROR_INVALID_INPUT:
        inner = " ".join(f'"{c}"' for c in required_input)
        parts.append(f"required_input=({inner})")

    if supported_algorithms and error == ERROR_UNSUPPORTED_ALGORITHM:
        inner = " ".join(f'"{a}"' for a in supported_algorithms)
        parts.append(f"supported_algorithms=({inner})")

    return ", ".join(parts)


def parse_signature_error(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Error header value.

    Args:
        header_value: Signature-Error header value

    Returns:
        Dictionary with:
        - error: str (error code)
        - required_input: Optional[List[str]]
        - supported_algorithms: Optional[List[str]]
    """
    result: Dict[str, Any] = {
        "error": None,
        "required_input": None,
        "supported_algorithms": None,
    }

    error_match = re.search(r'error=([\w_]+)', header_value)
    if error_match:
        result["error"] = error_match.group(1)

    for param_name in ("required_input", "supported_algorithms"):
        list_match = re.search(rf'{param_name}=\(([^)]+)\)', header_value)
        if list_match:
            inner = list_match.group(1)
            result[param_name] = re.findall(r'"([^"]+)"', inner)

    return result


# --- Backward compatibility aliases ---

# Old name aliases (deprecated — use Accept-Signature for pseudonym/identity)
parse_aauth_error = parse_signature_error
build_aauth_error = build_signature_error
build_auth_token_challenge = build_auth_token_requirement
build_approval_challenge = build_approval_requirement


def build_pseudonym_requirement(
    algorithms: Optional[List[str]] = None,
    required_input: Optional[List[str]] = None,
) -> str:
    """Deprecated: Use build_accept_signature(sigkey="jkt") instead.

    Kept for backward compatibility during transition.
    """
    from .accept_signature import build_accept_signature, SIGKEY_JKT
    return build_accept_signature(sigkey=SIGKEY_JKT, algs=algorithms)

build_pseudonym_challenge = build_pseudonym_requirement


def build_identity_requirement(
    algorithms: Optional[List[str]] = None,
    required_input: Optional[List[str]] = None,
) -> str:
    """Deprecated: Use build_accept_signature(sigkey="uri") instead.

    Kept for backward compatibility during transition.
    """
    from .accept_signature import build_accept_signature, SIGKEY_URI
    return build_accept_signature(sigkey=SIGKEY_URI, algs=algorithms)

build_identity_challenge = build_identity_requirement


def build_interaction_challenge(code: str, url: Optional[str] = None) -> str:
    """Build interaction requirement (backward-compatible signature)."""
    if url:
        return build_interaction_requirement(url, code)
    return f'requirement=interaction; code="{code}"'


def parse_aauth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement header (backward-compatible name).

    Accepts old 'require=', 'requirement=' formats.
    """
    if "requirement=" in header_value:
        parsed = parse_aauth_requirement(header_value)
        parsed["require"] = parsed["requirement"]
        return parsed
    elif "require=" in header_value:
        result = {
            "requirement": None,
            "require": None,
            "resource_token": None,
            "url": None,
            "code": None,
        }
        require_match = re.search(r'require=([\w-]+)', header_value)
        if require_match:
            result["requirement"] = require_match.group(1)
            result["require"] = require_match.group(1)

        rt_match = re.search(r'resource-token="([^"]+)"', header_value)
        if rt_match:
            result["resource_token"] = rt_match.group(1)

        url_match = re.search(r'url="([^"]+)"', header_value)
        if url_match:
            result["url"] = url_match.group(1)

        code_match = re.search(r'code="([^"]+)"', header_value)
        if code_match:
            result["code"] = code_match.group(1)

        return result
    else:
        raise ChallengeError("Header must include 'requirement' or 'require' parameter")


def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    **kwargs
) -> str:
    """Build challenge header value (backward-compatible API).

    Note: For pseudonym/identity, this now returns Accept-Signature format.
    For auth-token, returns AAuth-Requirement format.
    """
    if require_auth_token and resource_token:
        return build_auth_token_requirement(resource_token)
    elif require_identity:
        return build_identity_requirement()
    else:
        return build_pseudonym_requirement()


def parse_agent_auth_header(header_value: str) -> Dict[str, Any]:
    """Parse AAuth-Requirement header with backward-compatible result format."""
    parsed = parse_aauth_header(header_value)

    result = {
        "httpsig": True,
        "identity": parsed["requirement"] == REQUIRE_IDENTITY,
        "auth_token": parsed["requirement"] == REQUIRE_AUTH_TOKEN,
        "resource_token": parsed.get("resource_token"),
        "require": parsed["requirement"],
        "requirement": parsed["requirement"],
        "url": parsed.get("url"),
        "code": parsed.get("code"),
    }
    return result
