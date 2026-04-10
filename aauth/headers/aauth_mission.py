"""AAuth-Mission request header parsing and building.

Per AAuth protocol spec, the AAuth-Mission header is a Structured Fields
Dictionary (RFC 8941) sent by agents on initial requests to mission-aware
resources. It contains:
  - approver: Person Server's HTTPS URL (entity that approved the mission)
  - s256: Base64url-encoded SHA-256 hash of approved mission JSON
"""

import re
from typing import Dict, Optional


def build_aauth_mission(approver: str, s256: str) -> str:
    """Build AAuth-Mission request header value.

    Args:
        approver: Person Server's HTTPS URL (entity that approved the mission)
        s256: Base64url-encoded SHA-256 hash of approved mission JSON

    Returns:
        AAuth-Mission header value
    """
    return f'approver="{approver}"; s256="{s256}"'


def parse_aauth_mission(header_value: str) -> Dict[str, str]:
    """Parse AAuth-Mission request header value.

    Args:
        header_value: AAuth-Mission header value

    Returns:
        Dictionary with 'approver' and 's256' keys

    Raises:
        ValueError: If header format is invalid
    """
    result = {}

    approver_match = re.search(r'approver="([^"]+)"', header_value)
    if not approver_match:
        raise ValueError("AAuth-Mission header must include 'approver' parameter")
    result["approver"] = approver_match.group(1)

    s256_match = re.search(r's256="([^"]+)"', header_value)
    if not s256_match:
        raise ValueError("AAuth-Mission header must include 's256' parameter")
    result["s256"] = s256_match.group(1)

    return result


def mission_from_header(header_value: Optional[str]) -> Optional[Dict[str, str]]:
    """Extract mission object from AAuth-Mission header for embedding in tokens.

    Args:
        header_value: AAuth-Mission header value, or None if not present

    Returns:
        Mission object dict with 'approver' and 's256', or None
    """
    if not header_value:
        return None
    return parse_aauth_mission(header_value)
