"""AAuth-Access response header handling.

Per AAuth protocol spec, the AAuth-Access header carries an opaque access token
from a resource to an agent. The agent passes it back via Authorization: Bearer
on subsequent requests. The token is opaque to the agent.
"""


def build_aauth_access(access_token: str) -> str:
    """Build AAuth-Access response header value.

    Args:
        access_token: Opaque access token string

    Returns:
        AAuth-Access header value
    """
    return access_token


def parse_aauth_access(header_value: str) -> str:
    """Parse AAuth-Access response header value.

    Args:
        header_value: AAuth-Access header value

    Returns:
        Opaque access token string
    """
    return header_value.strip()
