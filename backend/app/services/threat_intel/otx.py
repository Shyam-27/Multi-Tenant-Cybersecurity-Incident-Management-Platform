from datetime import datetime, timezone
import logging
from typing import Any
import httpx

from app.core.config import get_settings
from app.models.ioc import IndicatorType, ThreatSeverity, ThreatVerdict
from app.services.threat_intel.base import ThreatIntelProvider

logger = logging.getLogger("sentinelops.threat_intel.otx")


class AlienVaultOTXProvider(ThreatIntelProvider):
    """
    AlienVault OTX (Open Threat Exchange) Provider Adapter.
    Enriches IPv4, IPv6, Domain, URL, SHA256, and MD5 indicators.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    @property
    def name(self) -> str:
        return "AlienVaultOTX"

    @property
    def is_configured(self) -> bool:
        settings = get_settings()
        return bool(settings.alienvault_otx_api_key and settings.alienvault_otx_api_key.strip())

    def supports_type(self, indicator_type: str) -> bool:
        return indicator_type.upper() in (
            IndicatorType.IPV4.value,
            IndicatorType.IPV6.value,
            IndicatorType.DOMAIN.value,
            IndicatorType.URL.value,
            IndicatorType.SHA256.value,
            IndicatorType.SHA1.value,
            IndicatorType.MD5.value,
        )

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        settings = get_settings()
        api_key = settings.alienvault_otx_api_key

        if not self.is_configured:
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AlienVault OTX API key is not configured.",
                "raw": {},
                "error": "API key not configured",
                "is_mocked": False,
            }

        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
        }

        # Map to OTX indicator section
        t = indicator_type.upper()
        if t == IndicatorType.IPV4.value:
            section = "IPv4"
        elif t == IndicatorType.IPV6.value:
            section = "IPv6"
        elif t == IndicatorType.DOMAIN.value:
            section = "domain"
        elif t == IndicatorType.URL.value:
            section = "url"
        elif t in (IndicatorType.SHA256.value, IndicatorType.SHA1.value, IndicatorType.MD5.value):
            section = "file"
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

        endpoint = f"{self.BASE_URL}/{section}/{value}/general"

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(endpoint, headers=headers)

            if resp.status_code == 404:
                return {
                    "provider": self.name,
                    "lookup_at": now_iso,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 0,
                    "severity": ThreatSeverity.UNKNOWN.value,
                    "summary": "No threat pulses found in AlienVault OTX database.",
                    "raw": {"pulse_count": 0, "status_code": 404},
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
                    "summary": "AlienVault OTX rate limit exceeded.",
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
                    "summary": f"AlienVault OTX returned HTTP {resp.status_code}.",
                    "raw": {"status_code": resp.status_code},
                    "error": f"HTTP {resp.status_code}",
                    "is_mocked": False,
                }

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])[:5]
            pulse_names = [p.get("name") for p in pulses if p.get("name")]

            if pulse_count >= 5:
                verdict = ThreatVerdict.MALICIOUS.value
                confidence = min(90, 50 + (pulse_count * 5))
                severity = ThreatSeverity.HIGH.value if pulse_count < 10 else ThreatSeverity.CRITICAL.value
            elif pulse_count >= 1:
                verdict = ThreatVerdict.SUSPICIOUS.value
                confidence = 50 + (pulse_count * 10)
                severity = ThreatSeverity.MEDIUM.value
            else:
                verdict = ThreatVerdict.BENIGN.value
                confidence = 70
                severity = ThreatSeverity.LOW.value

            summary = (
                f"Referenced in {pulse_count} threat pulse(s)"
                + (f": {', '.join(pulse_names[:2])}" if pulse_names else ".")
            )

            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": verdict,
                "confidence": confidence,
                "severity": severity,
                "summary": summary,
                "raw": {
                    "pulse_count": pulse_count,
                    "pulses": pulse_names,
                    "reputation": data.get("reputation", 0),
                },
                "error": None,
                "is_mocked": False,
            }

        except httpx.TimeoutException:
            logger.warning("AlienVault OTX lookup timed out for indicator %s", value)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AlienVault OTX request timed out.",
                "raw": {},
                "error": "Request timed out",
                "is_mocked": False,
            }
        except Exception as exc:
            logger.error("AlienVault OTX lookup failed: %s", exc)
            return {
                "provider": self.name,
                "lookup_at": now_iso,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "confidence": 0,
                "severity": ThreatSeverity.UNKNOWN.value,
                "summary": "AlienVault OTX lookup exception occurred.",
                "raw": {},
                "error": str(exc),
                "is_mocked": False,
            }
