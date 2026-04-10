"""Resource metadata handling for AAuth.

Published at /.well-known/aauth-resource.json
"""

from typing import Dict, Any, Optional, List


def generate_resource_metadata(
    resource_id: str,
    jwks_uri: str,
    authorization_endpoint: str,
    client_name: Optional[str] = None,
    logo_uri: Optional[str] = None,
    logo_dark_uri: Optional[str] = None,
    scope_descriptions: Optional[Dict[str, str]] = None,
    signature_window: Optional[int] = None,
    additional_signature_components: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate resource metadata JSON per AAuth spec.

    Args:
        resource_id: Resource identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to resource's JSON Web Key Set - REQUIRED
        authorization_endpoint: URL where agents request authorization - REQUIRED
        client_name: Human-readable resource name (optional)
        logo_uri: URL to resource logo (optional)
        logo_dark_uri: URL to resource logo for dark backgrounds (optional)
        scope_descriptions: Object mapping scope names to Markdown descriptions (optional)
        signature_window: Signature validity window in seconds (optional, default 60)
        additional_signature_components: Additional HTTP components for signatures (optional)

    Returns:
        Resource metadata dictionary
    """
    metadata = {
        "resource": resource_id,
        "jwks_uri": jwks_uri,
        "authorization_endpoint": authorization_endpoint,
    }

    if client_name is not None:
        metadata["client_name"] = client_name
    if logo_uri is not None:
        metadata["logo_uri"] = logo_uri
    if logo_dark_uri is not None:
        metadata["logo_dark_uri"] = logo_dark_uri
    if scope_descriptions is not None:
        metadata["scope_descriptions"] = scope_descriptions
    if signature_window is not None:
        metadata["signature_window"] = signature_window
    if additional_signature_components is not None:
        metadata["additional_signature_components"] = additional_signature_components

    return metadata
