"""AAuth-Capabilities request header building and parsing.

Per AAuth protocol spec, the AAuth-Capabilities header is a List (RFC 8941
Section 3.1) of Tokens declaring which protocol capabilities the agent supports.

Capability values:
  - interaction: Agent can handle user interaction flows
  - clarification: Agent can handle clarification chat
  - payment: Agent can handle payment flows
"""

from typing import List


# Capability values
CAPABILITY_INTERACTION = "interaction"
CAPABILITY_CLARIFICATION = "clarification"
CAPABILITY_PAYMENT = "payment"


def build_aauth_capabilities(capabilities: List[str]) -> str:
    """Build AAuth-Capabilities request header value.

    Args:
        capabilities: List of capability tokens (e.g., ["interaction", "clarification"])

    Returns:
        AAuth-Capabilities header value (e.g., "interaction, clarification")
    """
    return ", ".join(capabilities)


def parse_aauth_capabilities(header_value: str) -> List[str]:
    """Parse AAuth-Capabilities request header value.

    Args:
        header_value: AAuth-Capabilities header value

    Returns:
        List of capability token strings
    """
    return [c.strip() for c in header_value.split(",") if c.strip()]
