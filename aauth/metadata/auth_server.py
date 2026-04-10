"""Person Server (PS) and Access Server (AS) metadata handling for AAuth.

PS metadata published at /.well-known/aauth-person.json
AS metadata published at /.well-known/aauth-access.json
"""

from typing import Dict, Any, Optional


def generate_ps_metadata(
    ps_id: str,
    jwks_uri: str,
    token_endpoint: str,
    mission_endpoint: Optional[str] = None,
    mission_control_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate Person Server (PS) metadata JSON.

    Published at /.well-known/aauth-person.json.
    Agents send token requests to their PS.

    Args:
        ps_id: PS identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to PS's JSON Web Key Set - REQUIRED
        token_endpoint: URL where agents send token requests - REQUIRED
        mission_endpoint: URL for mission lifecycle operations (optional)
        mission_control_endpoint: URL for mission administrative interface (optional)

    Returns:
        PS metadata dictionary
    """
    metadata = {
        "issuer": ps_id,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
    }
    if mission_endpoint is not None:
        metadata["mission_endpoint"] = mission_endpoint
    if mission_control_endpoint is not None:
        metadata["mission_control_endpoint"] = mission_control_endpoint
    return metadata

# Backward-compatible alias
generate_mm_metadata = generate_ps_metadata


def generate_as_metadata(
    as_id: str,
    jwks_uri: str,
    token_endpoint: str,
) -> Dict[str, Any]:
    """Generate Access Server (AS) metadata JSON.

    Published at /.well-known/aauth-access.json.
    Only PSes call ASes directly.

    Args:
        as_id: Access Server identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to Access Server's JSON Web Key Set - REQUIRED
        token_endpoint: URL where PSes send token requests - REQUIRED

    Returns:
        Access Server metadata dictionary
    """
    return {
        "issuer": as_id,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
    }

# Backward-compatible alias
generate_auth_metadata = generate_as_metadata


def fetch_metadata(url: str) -> Dict[str, Any]:
    """Fetch metadata document from URL via HTTPS (sync version).

    Args:
        url: HTTPS URL to metadata document (HTTP allowed for localhost development)

    Returns:
        Parsed metadata dictionary

    Raises:
        ValueError: If URL is not HTTPS (except localhost for development)
        MetadataError: If HTTP request fails
    """
    import httpx
    from ..errors import MetadataError

    if not url.startswith("https://"):
        parsed = httpx.URL(url)
        if parsed.host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(f"Metadata URL must use HTTPS (except localhost): {url}")

    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise MetadataError(
            f"Failed to fetch metadata from {url}: {e}",
            metadata_url=url
        ) from e


async def fetch_auth_metadata(url: str, http_client=None) -> Dict[str, Any]:
    """Fetch auth server metadata from URL (async version).

    Args:
        url: URL to auth server metadata document
        http_client: Optional HTTP client

    Returns:
        Parsed auth server metadata dictionary

    Raises:
        MetadataError: If fetch fails
    """
    from ..keys.jwks import DefaultHTTPClient
    from ..errors import MetadataError

    client = http_client or DefaultHTTPClient()

    try:
        return await client.fetch_json(url)
    except Exception as e:
        raise MetadataError(
            f"Failed to fetch auth server metadata from {url}: {e}",
            metadata_url=url
        )
