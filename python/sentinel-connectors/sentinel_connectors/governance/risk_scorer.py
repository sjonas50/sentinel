"""Risk scoring for shadow AI services."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel_connectors.governance.domains import RiskTier

if TYPE_CHECKING:
    from sentinel_connectors.governance.models import ShadowAiServiceRecord

# Weight configuration for composite risk score
RISK_TIER_WEIGHTS: dict[RiskTier, float] = {
    RiskTier.CRITICAL: 40.0,
    RiskTier.HIGH: 30.0,
    RiskTier.MEDIUM: 20.0,
    RiskTier.LOW: 10.0,
}

# Thresholds for volume-based scoring
HIGH_VOLUME_BYTES = 10 * 1024 * 1024  # 10 MB
HIGH_USER_COUNT = 10
HIGH_FLOW_COUNT = 100


def compute_risk_score(service: ShadowAiServiceRecord) -> float:
    """Compute composite risk score (0.0 - 100.0) for a shadow AI service.

    Scoring formula:
    - Base tier risk (40%): from the domain's inherent risk tier
    - Data volume risk (25%): based on bytes transferred
    - User breadth risk (20%): based on unique source hosts/IPs
    - Activity volume risk (15%): based on frequency of API calls
    - Sanctioned discount: ×0.5 if the service is approved
    """
    # Base tier score (0-40)
    base = RISK_TIER_WEIGHTS.get(service.risk_tier, 20.0)

    # Data volume score (0-25)
    total_bytes = service.total_bytes_sent + service.total_bytes_received
    volume_ratio = min(total_bytes / HIGH_VOLUME_BYTES, 1.0)
    volume_score = volume_ratio * 25.0

    # User breadth score (0-20)
    user_count = max(service.unique_source_ips, service.unique_source_hosts)
    breadth_ratio = min(user_count / HIGH_USER_COUNT, 1.0)
    breadth_score = breadth_ratio * 20.0

    # Activity volume score (0-15)
    activity = service.total_dns_queries + service.total_network_flows
    activity_ratio = min(activity / HIGH_FLOW_COUNT, 1.0)
    activity_score = activity_ratio * 15.0

    total = base + volume_score + breadth_score + activity_score

    # Sanctioned discount
    if service.sanctioned:
        total *= 0.5

    return round(min(total, 100.0), 1)
