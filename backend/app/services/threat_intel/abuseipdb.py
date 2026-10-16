from datetime import datetime, timezone
import logging
from typing import Any
import httpx

from app.core.config import get_settings
from app.models.ioc import IndicatorType, ThreatSeverity, ThreatVerdict
from app.services.threat_intel.base import ThreatIntelProvider

logger = logging.getLogger("sentinelops.threat_intel.abuseipdb")


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB API v2 Provider Adapter.
    Enriches IPv4 and IPv6 reputation and abuse reports.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    @property
    def is_configured(self) -> bool:
        settings = get_settings()
        return bool(settings.abuseipdb_api_key and settings.abuseipdb_api_key.strip())

    def supports_type(self, indicator_type: str) -> bool:
        return indicator_type.upper() in (IndicatorType.IPV4.value, IndicatorType.IPV6.value)

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        settings = get_settings()
        api_key = settings.abuseipdb_api_key

        if not self.is_configured:
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AbuseIPDB API key is not configured.",
                "raw": {},
                "error": "API key not configured",
                "is_mocked": False,
            }

        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": value,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(self.BASE_URL, headers=headers, params=params)

            if resp.status_code == 429:
                return {
                    "provider": self.name,
                    "lookup_at": now_iso,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 0,
                    "severity": ThreatSeverity.UNKNOWN.value,
                    "summary": "AbuseIPDB rate limit exceeded.",
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
                    "summary": f"AbuseIPDB returned HTTP {resp.status_code}.",
                    "raw": {"status_code": resp.status_code},
                    "error": f"HTTP {resp.status_code}",
                    "is_mocked": False,
                }

            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            is_whitelisted = data.get("isWhitelisted", False)

            if is_whitelisted or abuse_score == 0:
                verdict = ThreatVerdict.BENIGN.value
                confidence = 80
                severity = ThreatSeverity.LOW.value
            elif abuse_score >= 75:
                verdict = ThreatVerdict.MALICIOUS.value
                confidence = abuse_score
                severity = ThreatSeverity.CRITICAL.value if abuse_score >= 90 else ThreatSeverity.HIGH.value
            elif abuse_score >= 20:
                verdict = ThreatVerdict.SUSPICIOUS.value
                confidence = abuse_score
                severity = ThreatSeverity.MEDIUM.value
            else:
                verdict = ThreatVerdict.UNKNOWN.value
                confidence = 20
                severity = ThreatSeverity.LOW.value

            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": verdict,
                "confidence": confidence,
                "severity": severity,
                "summary": f"Abuse score: {abuse_score}% with {total_reports} reports (ISP: {isp}, Country: {country}).",
                "raw": {
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": total_reports,
                    "countryCode": country,
                    "usageType": data.get("usageType"),
                    "domain": data.get("domain"),
                },
                "error": None,
                "is_mocked": False,
            }

        except httpx.TimeoutException:
            logger.warning("AbuseIPDB lookup timed out for IP %s", value)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AbuseIPDB request timed out.",
                "raw": {},
                "error": "Request timed out",
                "is_mocked": False,
            }
        except Exception as exc:
            logger.error("AbuseIPDB lookup failed: %s", exc)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AbuseIPDB lookup exception occurred.",
                "raw": {},
                "error": str(exc),
                "is_mocked": False,
            }
