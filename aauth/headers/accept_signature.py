"""Accept-Signature response header building and parsing.

Per RFC 9421 Section 5 and draft-hardt-httpbis-signature-key, the
Accept-Signature header tells clients which signature parameters are
acceptable. The `sigkey` parameter (from Signature-Key spec) indicates
what kind of key identification is required:
  - jkt: Pseudonymous key identified by JWK Thumbprint
  - uri: Key identified by a URI (e.g., jwks_uri with id)
  - x509: Key from an X.509 certificate chain
"""

import re
from typing import Dict, Any, List, Optional


# sigkey parameter values
SIGKEY_JKT = "jkt"
SIGKEY_URI = "uri"
SIGKEY_X509 = "x509"

# Default covered components for AAuth signatures
DEFAULT_COMPONENTS = ["@method", "@authority", "@path"]


def build_accept_signature(
    sigkey: str,
    label: str = "sig",
    components: Optional[List[str]] = None,
    algs: Optional[List[str]] = None,
) -> str:
    """Build Accept-Signature response header value.

    Args:
        sigkey: Required key type — "jkt", "uri", or "x509"
        label: Signature label (default "sig")
        components: Covered components list. Defaults to ["@method", "@authority", "@path"].
        algs: Optional list of acceptable algorithms (RFC 9421 identifiers)

    Returns:
        Accept-Signature header value, e.g.:
        sig=("@method" "@authority" "@path");sigkey=jkt
    """
    if components is None:
        components = DEFAULT_COMPONENTS

    components_str = " ".join(f'"{c}"' for c in components)
    result = f'{label}=({components_str});sigkey={sigkey}'

    if algs:
        algs_str = " ".join(f'"{a}"' for a in algs)
        result += f";algs=({algs_str})"

    return result


def parse_accept_signature(header_value: str) -> Dict[str, Any]:
    """Parse Accept-Signature response header value.

    Args:
        header_value: Accept-Signature header value

    Returns:
        Dictionary with keys:
          - label: Signature label (e.g., "sig")
          - components: List of covered component strings
          - sigkey: Key type ("jkt", "uri", or "x509")
          - algs: List of algorithm strings, or None

    Raises:
        ValueError: If header format is invalid
    """
    result: Dict[str, Any] = {}

    # Parse label and inner list: label=("comp1" "comp2" ...)
    label_match = re.match(r'(\w+)=\(([^)]*)\)', header_value)
    if not label_match:
        raise ValueError(f"Invalid Accept-Signature format: {header_value}")

    result["label"] = label_match.group(1)

    # Parse components from the inner list
    components_str = label_match.group(2)
    result["components"] = re.findall(r'"([^"]+)"', components_str)

    # Parse parameters after the inner list
    params_str = header_value[label_match.end():]

    # Parse sigkey parameter
    sigkey_match = re.search(r';sigkey=(\w+)', params_str)
    if not sigkey_match:
        raise ValueError("Accept-Signature must include 'sigkey' parameter")
    result["sigkey"] = sigkey_match.group(1)

    # Parse optional algs parameter
    algs_match = re.search(r';algs=\(([^)]*)\)', params_str)
    if algs_match:
        result["algs"] = re.findall(r'"([^"]+)"', algs_match.group(1))
    else:
        result["algs"] = None

    return result
