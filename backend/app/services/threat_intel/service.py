from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import ActorType, AuditOutcome
from app.models.ioc import IndicatorOfCompromise, ThreatSeverity, ThreatVerdict
from app.models.user import User
from app.services.audit_service import record_audit_event
from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
from app.services.threat_intel.base import ThreatIntelProvider
from app.services.threat_intel.otx import AlienVaultOTXProvider
from app.services.threat_intel.virustotal import VirusTotalProvider

logger = logging.getLogger("sentinelops.threat_intel")


class ThreatIntelService:
    """Orchestrates threat intelligence lookups across configured provider adapters."""

    def __init__(self) -> None:
        self.providers: list[ThreatIntelProvider] = [
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            AlienVaultOTXProvider(),
        ]

    def get_providers(self) -> list[ThreatIntelProvider]:
        return self.providers

    def enrich_indicator(
        self,
        db: Session,
        indicator: IndicatorOfCompromise,
        selected_providers: list[str] | None = None,
        force_refresh: bool = False,
        actor_user: User | None = None,
    ) -> IndicatorOfCompromise:
        """
        Enriches an IOC with external threat intelligence.
        Respects cache TTL unless force_refresh is True.
        """
        settings = get_settings()
        now = datetime.now(timezone.utc)
        cache_ttl = timedelta(minutes=settings.threat_intel_cache_ttl_minutes)

        # Check Cache freshness
        if not force_refresh and indicator.enriched_at:
            enriched_at = indicator.enriched_at
            if enriched_at.tzinfo is None:
                enriched_at = enriched_at.replace(tzinfo=timezone.utc)
            if (now - enriched_at) < cache_ttl:
                logger.info("Serving cached threat intel for indicator %s", indicator.value)
                return indicator

        # Select relevant providers
        normalized_type = indicator.indicator_type
        applicable_providers = [
            p for p in self.providers
            if p.supports_type(normalized_type)
            and (selected_providers is None or p.name.lower() in [sp.lower() for sp in selected_providers])
        ]

        if not applicable_providers:
            logger.info("No applicable providers for indicator type %s", normalized_type)
            return indicator

        provider_results: dict[str, Any] = dict(indicator.raw_enrichment_data.get("providers", {}))

        for prov in applicable_providers:
            try:
                res = prov.lookup(indicator.indicator_type, indicator.value)
                provider_results[prov.name] = res
            except Exception as exc:
                logger.error("Provider %s failed unexpectedly: %s", prov.name, exc)
                provider_results[prov.name] = {
                    "provider": prov.name,
                    "lookup_at": now.isoformat(),
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "confidence": 0,
                    "severity": ThreatSeverity.UNKNOWN.value,
                    "summary": f"Lookup failed: {exc}",
                    "raw": {},
                    "error": str(exc),
                    "is_mocked": False,
                }

        # Aggregate Verdict & Confidence
        verdicts = [res.get("verdict") for res in provider_results.values() if not res.get("error")]
        confidences = [res.get("confidence", 0) for res in provider_results.values() if not res.get("error")]
        severities = [res.get("severity") for res in provider_results.values() if not res.get("error")]

        if ThreatVerdict.MALICIOUS.value in verdicts:
            aggregated_verdict = ThreatVerdict.MALICIOUS.value
            aggregated_confidence = max(confidences) if confidences else 75
            if ThreatSeverity.CRITICAL.value in severities:
                aggregated_severity = ThreatSeverity.CRITICAL.value
            else:
                aggregated_severity = ThreatSeverity.HIGH.value
        elif ThreatVerdict.SUSPICIOUS.value in verdicts:
            aggregated_verdict = ThreatVerdict.SUSPICIOUS.value
            aggregated_confidence = max(confidences) if confidences else 50
            aggregated_severity = ThreatSeverity.MEDIUM.value
        elif verdicts and all(v == ThreatVerdict.BENIGN.value for v in verdicts):
            aggregated_verdict = ThreatVerdict.BENIGN.value
            aggregated_confidence = max(confidences) if confidences else 70
            aggregated_severity = ThreatSeverity.LOW.value
        else:
            aggregated_verdict = ThreatVerdict.UNKNOWN.value
            aggregated_confidence = max(confidences) if confidences else 0
            aggregated_severity = ThreatSeverity.UNKNOWN.value

        # Update indicator fields
        indicator.threat_verdict = aggregated_verdict
        indicator.confidence_score = aggregated_confidence
        indicator.severity = aggregated_severity
        indicator.enriched_at = now
        indicator.expires_at = now + cache_ttl
        indicator.last_seen_at = now
        indicator.raw_enrichment_data = {
            "providers": provider_results,
            "last_enriched_at": now.isoformat(),
            "cache_ttl_minutes": settings.threat_intel_cache_ttl_minutes,
        }

        # Audit Event
        record_audit_event(
            db=db,
            action="IOC_ENRICHED",
            resource_type="ioc",
            resource_id=str(indicator.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=actor_user,
            actor_type=ActorType.USER if actor_user else ActorType.SYSTEM,
            tenant_id=indicator.tenant_id,
            details={
                "indicator_type": indicator.indicator_type,
                "value": indicator.value,
                "verdict": aggregated_verdict,
                "confidence": aggregated_confidence,
                "providers_queried": [p.name for p in applicable_providers],
            },
        )

        db.commit()
        db.refresh(indicator)
        return indicator


_threat_intel_service = ThreatIntelService()


def get_threat_intel_service() -> ThreatIntelService:
    return _threat_intel_service
