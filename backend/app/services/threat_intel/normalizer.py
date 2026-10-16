import ipaddress
import re
from urllib.parse import urlparse

from app.models.ioc import IndicatorType

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_HEX_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_HEX_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def normalize_indicator(indicator_type: str, raw_value: str) -> tuple[str, str]:
    """
    Validates and normalizes an indicator value according to its type.
    Returns: (normalized_type, normalized_value)
    Raises: ValueError with a descriptive explanation on invalid format.
    """
    clean_val = raw_value.strip()
    if not clean_val:
        raise ValueError("Indicator value cannot be empty")

    type_upper = indicator_type.upper().strip()

    if type_upper == IndicatorType.IPV4.value:
        try:
            ip = ipaddress.IPv4Address(clean_val)
            return IndicatorType.IPV4.value, str(ip)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address format: '{clean_val}'")

    elif type_upper == IndicatorType.IPV6.value:
        try:
            ip = ipaddress.IPv6Address(clean_val)
            return IndicatorType.IPV6.value, str(ip).lower()
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv6 address format: '{clean_val}'")

    elif type_upper == IndicatorType.DOMAIN.value:
        clean_domain = clean_val.lower().rstrip(".")
        # Strip protocol if user pasted http://domain.com
        if clean_domain.startswith(("http://", "https://")):
            parsed = urlparse(clean_domain)
            clean_domain = parsed.hostname or clean_domain
        if not _DOMAIN_REGEX.match(clean_domain):
            raise ValueError(f"Invalid domain name format: '{clean_val}'")
        return IndicatorType.DOMAIN.value, clean_domain

    elif type_upper == IndicatorType.URL.value:
        try:
            parsed = urlparse(clean_val)
            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError("URL must use http or https scheme")
            if not parsed.netloc:
                raise ValueError("URL must have a valid hostname/netloc")
            # SSRF safe normalization: remove user credentials from URL
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
            normalized = f"{parsed.scheme.lower()}://{hostname}{port_part}{parsed.path or '/'}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return IndicatorType.URL.value, normalized
        except Exception as exc:
            raise ValueError(f"Invalid URL format: {exc}") from exc

    elif type_upper == IndicatorType.SHA256.value:
        clean_hex = clean_val.lower()
        if not _HEX_SHA256.match(clean_hex):
            raise ValueError("SHA-256 hash must be exactly 64 hexadecimal characters")
        return IndicatorType.SHA256.value, clean_hex

    elif type_upper == IndicatorType.SHA1.value:
        clean_hex = clean_val.lower()
        if not _HEX_SHA1.match(clean_hex):
            raise ValueError("SHA-1 hash must be exactly 40 hexadecimal characters")
        return IndicatorType.SHA1.value, clean_hex

    elif type_upper == IndicatorType.MD5.value:
        clean_hex = clean_val.lower()
        if not _HEX_MD5.match(clean_hex):
            raise ValueError("MD5 hash must be exactly 32 hexadecimal characters")
        return IndicatorType.MD5.value, clean_hex

    else:
        raise ValueError(f"Unsupported indicator type: '{indicator_type}'")
