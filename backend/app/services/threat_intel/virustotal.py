import base64
from datetime import datetime, timezone
import logging
from typing import Any
import httpx

from app.core.config import get_settings
from app.models.ioc import IndicatorType, ThreatSeverity, ThreatVerdict
from app.services.threat_intel.base import ThreatIntelProvider

logger = logging.getLogger("sentinelops.threat_intel.virustotal")


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal API v3 Provider Adapter.
    Enriches file hashes, IPs, domains, and URLs.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def is_configured(self) -> bool:
        settings = get_settings()
        return bool(settings.virustotal_api_key and settings.virustotal_api_key.strip())

    def supports_type(self, indicator_type: str) -> bool:
        return indicator_type.upper() in (
            IndicatorType.SHA256.value,
            IndicatorType.SHA1.value,
            IndicatorType.MD5.value,
            IndicatorType.IPV4.value,
            IndicatorType.DOMAIN.value,
            IndicatorType.URL.value,
        )

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        settings = get_settings()
        api_key = settings.virustotal_api_key

        if not self.is_configured:
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "VirusTotal API key is not configured.",
                "raw": {},
                "error": "API key not configured",
                "is_mocked": False,
            }

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        # Determine endpoint path
        t = indicator_type.upper()
        if t in (IndicatorType.SHA256.value, IndicatorType.SHA1.value, IndicatorType.MD5.value):
            endpoint = f"{self.BASE_URL}/files/{value}"
        elif t == IndicatorType.IPV4.value:
            endpoint = f"{self.BASE_URL}/ip_addresses/{value}"
        elif t == IndicatorType.DOMAIN.value:
            endpoint = f"{self.BASE_URL}/domains/{value}"
        elif t == IndicatorType.URL.value:
            # VT uses base64url of URL without padding
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
        else:
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": f"Unsupported indicator type {indicator_type}",
                "raw": {},
                "error": "Unsupported type",
                "is_mocked": False,
            }

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(endpoint, headers=headers)

            if resp.status_code == 404:
                return {
                    "provider": self.name,
                    "lookup_at": now_iso,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 10,
                    "severity": ThreatSeverity.LOW.value,
                    "summary": "Indicator not observed in VirusTotal database.",
                    "raw": {"status_code": 404},
                    "error": None,
                    "is_mocked": False,
                }
            elif resp.status_code == 429:
                return {
                    "provider": self.name,
                    "lookup_at": now_iso,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 0,
                    "severity": ThreatSeverity.UNKNOWN.value,
                    "summary": "VirusTotal API rate limit exceeded.",
                    "raw": {"status_code": 429},
                    "error": "Rate limit exceeded (HTTP 429)",
                    "is_mocked": False,
                }
            elif resp.status_code != 200:
                return {
                    "provider": self.name,
                    "lookup_at": now_iso,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 0,
                    "severity": ThreatSeverity.UNKNOWN.value,
                    "summary": f"VirusTotal returned error HTTP {resp.status_code}.",
                    "raw": {"status_code": resp.status_code},
                    "error": f"HTTP {resp.status_code}",
                    "is_mocked": False,
                }

            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious >= 3:
                verdict = ThreatVerdict.MALICIOUS.value
                confidence = min(95, 60 + (malicious * 5))
                severity = ThreatSeverity.CRITICAL.value if malicious >= 10 else ThreatSeverity.HIGH.value
            elif malicious >= 1 or suspicious >= 2:
                verdict = ThreatVerdict.SUSPICIOUS.value
                confidence = 50 + (suspicious * 5)
                severity = ThreatSeverity.MEDIUM.value
            elif harmless >= 5 and malicious == 0:
                verdict = ThreatVerdict.BENIGN.value
                confidence = 85
                severity = ThreatSeverity.LOW.value
            else:
                verdict = ThreatVerdict.UNKNOWN.value
                confidence = 20
                severity = ThreatSeverity.UNKNOWN.value

            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": verdict,
                "confidence": confidence,
                "severity": severity,
                "summary": f"VT detection: {malicious} malicious, {suspicious} suspicious out of {total} engines.",
                "raw": {
                    "stats": stats,
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", [])[:10],
                },
                "error": None,
                "is_mocked": False,
            }

        except httpx.TimeoutException:
            logger.warning("VirusTotal lookup timed out for indicator %s", value)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "VirusTotal request timed out.",
                "raw": {},
                "error": "Request timed out",
                "is_mocked": False,
            }
        except Exception as exc:
            logger.error("VirusTotal lookup failed: %s", exc)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "VirusTotal lookup exception occurred.",
                "raw": {},
                "error": str(exc),
                "is_mocked": False,
            }
