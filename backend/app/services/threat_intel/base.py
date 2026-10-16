from abc import ABC, abstractmethod
from typing import Any

from app.models.ioc import ThreatSeverity, ThreatVerdict


class ThreatIntelProvider(ABC):
    """Abstract base provider for external threat intelligence lookups."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier."""
        pass

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the required credentials are present."""
        pass

    @abstractmethod
    def supports_type(self, indicator_type: str) -> bool:
        """Check if this provider supports looking up the specified indicator type."""
        pass

    @abstractmethod
    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        """
        Executes lookup for an indicator.
        Returns normalized dictionary with keys:
          - provider: str
          - lookup_at: ISO-8601 string
          - verdict: ThreatVerdict value
          - confidence: int (0-100)
          - severity: ThreatSeverity value
          - summary: str
          - raw: dict
          - error: str | None
          - is_mocked: bool
        """
        pass
