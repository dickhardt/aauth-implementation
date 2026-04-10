"""AAuth challenge handling for agent role.

Handles both:
  - Accept-Signature headers (signature-level: sigkey=jkt/uri/x509)
  - AAuth-Requirement headers (protocol-level: auth-token, interaction, etc.)
"""

from typing import Dict, Any, Optional
from ..headers.aauth_header import parse_aauth_header, REQUIRE_AUTH_TOKEN, REQUIRE_IDENTITY, REQUIRE_INTERACTION, REQUIRE_APPROVAL
from ..headers.accept_signature import parse_accept_signature, SIGKEY_JKT, SIGKEY_URI, SIGKEY_X509
from ..errors import ChallengeError


class ChallengeHandler:
    """Handles AAuth challenges from resources and auth servers."""

    def parse_challenge(self, aauth_header: str) -> Dict[str, Any]:
        """Parse AAuth-Requirement challenge header.

        Args:
            aauth_header: AAuth-Requirement header value

        Returns:
            Parsed challenge parameters

        Raises:
            ChallengeError: If parsing fails
        """
        return parse_aauth_header(aauth_header)

    def parse_accept_signature(self, header_value: str) -> Dict[str, Any]:
        """Parse Accept-Signature challenge header.

        Args:
            header_value: Accept-Signature header value

        Returns:
            Parsed Accept-Signature parameters with sigkey, label, components, algs

        Raises:
            ValueError: If parsing fails
        """
        return parse_accept_signature(header_value)

    def determine_response_scheme(
        self,
        challenge: Dict[str, Any],
        has_agent_token: bool = False,
        has_auth_token: bool = False
    ) -> str:
        """Determine which signature scheme to use in response to challenge.

        Works with both AAuth-Requirement parsed results and Accept-Signature parsed results.

        Args:
            challenge: Parsed challenge parameters (from either header type)
            has_agent_token: Whether agent has an agent token
            has_auth_token: Whether agent has an auth token

        Returns:
            Signature scheme to use ("hwk", "jwks_uri", or "jwt")

        Raises:
            ChallengeError: If challenge cannot be satisfied
        """
        # Handle Accept-Signature challenges (sigkey parameter)
        sigkey = challenge.get("sigkey")
        if sigkey:
            if sigkey == SIGKEY_JKT:
                return "hwk"
            elif sigkey == SIGKEY_URI:
                if has_agent_token:
                    return "jwt"
                return "jwks_uri"
            elif sigkey == SIGKEY_X509:
                raise ChallengeError("x509 signature key type not supported")
            else:
                raise ChallengeError(f"Unknown sigkey value: {sigkey}")

        # Handle AAuth-Requirement challenges (requirement parameter)
        require = challenge.get("require") or challenge.get("requirement")

        if require == REQUIRE_AUTH_TOKEN:
            if has_auth_token:
                return "jwt"
            else:
                raise ChallengeError(
                    "Challenge requires auth token but agent doesn't have one",
                    challenge_type="auth-token"
                )

        if require == REQUIRE_IDENTITY:
            if has_agent_token:
                return "jwt"
            else:
                return "jwks_uri"

        # Pseudonym or other — just sign with hwk
        return "hwk"
