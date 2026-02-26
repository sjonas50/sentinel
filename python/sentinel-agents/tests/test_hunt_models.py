"""Tests for hunt models, configs, and Sigma YAML serialization."""

from __future__ import annotations

import yaml
from sentinel_agents.hunt.models import (
    CredentialAbuseConfig,
    DataExfiltrationConfig,
    HuntConfig,
    HuntFinding,
    LateralMovementConfig,
    PlaybookResult,
    PlaybookType,
    SigmaDetection,
    SigmaRule,
)

# ── PlaybookType ─────────────────────────────────────────────────


def test_playbook_type_values() -> None:
    assert PlaybookType.CREDENTIAL_ABUSE == "credential_abuse"
    assert PlaybookType.LATERAL_MOVEMENT == "lateral_movement"
    assert PlaybookType.DATA_EXFILTRATION == "data_exfiltration"


# ── HuntConfig ───────────────────────────────────────────────────


def test_hunt_config_defaults() -> None:
    cfg = HuntConfig(playbook=PlaybookType.CREDENTIAL_ABUSE)
    assert cfg.time_window_hours == 24
    assert cfg.max_results_per_query == 1000
    assert cfg.generate_sigma_rules is True
    assert cfg.target_hosts == []


def test_credential_abuse_config_defaults() -> None:
    cfg = CredentialAbuseConfig()
    assert cfg.playbook == PlaybookType.CREDENTIAL_ABUSE
    assert cfg.failed_login_threshold == 10
    assert cfg.credential_stuffing_unique_users == 5
    assert cfg.service_account_monitoring is True


def test_lateral_movement_config_defaults() -> None:
    cfg = LateralMovementConfig()
    assert cfg.playbook == PlaybookType.LATERAL_MOVEMENT
    assert cfg.rdp_chain_max_hops == 3
    assert cfg.service_account_hop_threshold == 2
    assert "10." in cfg.internal_subnet_prefixes


def test_data_exfiltration_config_defaults() -> None:
    cfg = DataExfiltrationConfig()
    assert cfg.playbook == PlaybookType.DATA_EXFILTRATION
    assert cfg.large_transfer_bytes == 100_000_000
    assert cfg.dns_query_length_threshold == 50
    assert cfg.after_hours_start == 22
    assert cfg.after_hours_end == 6


def test_config_custom_values() -> None:
    cfg = CredentialAbuseConfig(
        time_window_hours=48,
        failed_login_threshold=20,
        index_pattern="custom-*",
        target_users=["admin"],
    )
    assert cfg.time_window_hours == 48
    assert cfg.failed_login_threshold == 20
    assert cfg.index_pattern == "custom-*"
    assert cfg.target_users == ["admin"]


# ── SigmaRule ────────────────────────────────────────────────────


def test_sigma_rule_to_yaml() -> None:
    rule = SigmaRule(
        title="Test Brute Force Detection",
        description="Detects brute force login attempts",
        tags=["attack.credential_access", "attack.t1110.001"],
        logsource={"category": "authentication", "product": "windows"},
        detection=SigmaDetection(
            selection={"event.outcome": "failure", "source.ip": ["10.0.0.1"]},
            condition="selection",
        ),
        level="high",
        falsepositives=["Password change"],
    )
    yaml_str = rule.to_yaml()
    parsed = yaml.safe_load(yaml_str)

    assert parsed["title"] == "Test Brute Force Detection"
    assert parsed["level"] == "high"
    assert "attack.credential_access" in parsed["tags"]
    assert parsed["detection"]["selection"]["event.outcome"] == "failure"
    assert parsed["logsource"]["category"] == "authentication"
    assert parsed["status"] == "experimental"


def test_sigma_rule_to_yaml_with_filter() -> None:
    rule = SigmaRule(
        title="Filtered Rule",
        description="Rule with filter",
        logsource={"category": "network_connection"},
        detection=SigmaDetection(
            selection={"destination.port": 3389},
            filter={"source.ip": "10.0.0.1"},
            condition="selection and not filter",
        ),
    )
    yaml_str = rule.to_yaml()
    parsed = yaml.safe_load(yaml_str)

    assert "filter" in parsed["detection"]
    assert parsed["detection"]["condition"] == "selection and not filter"


def test_sigma_rule_id_is_uuid() -> None:
    rule = SigmaRule(
        title="ID Test",
        description="Test UUID",
        logsource={},
        detection=SigmaDetection(selection={"field": "value"}),
    )
    yaml_str = rule.to_yaml()
    parsed = yaml.safe_load(yaml_str)
    assert len(parsed["id"]) == 36  # UUID format


# ── HuntFinding ──────────────────────────────────────────────────


def test_hunt_finding_creation() -> None:
    finding = HuntFinding(
        playbook=PlaybookType.CREDENTIAL_ABUSE,
        severity="high",
        title="Brute force from 10.0.0.1",
        description="50 failed logins detected",
        evidence={"source_ips": ["10.0.0.1"], "failed_count": 50},
        mitre_technique_ids=["T1110.001"],
        mitre_tactic="Credential Access",
        affected_users=["admin", "user1"],
    )
    assert finding.severity == "high"
    assert finding.mitre_technique_ids == ["T1110.001"]
    assert len(finding.affected_users) == 2
    assert finding.sigma_rule is None


def test_hunt_finding_with_sigma_rule() -> None:
    rule = SigmaRule(
        title="Test",
        description="Test",
        logsource={},
        detection=SigmaDetection(selection={"f": "v"}),
    )
    finding = HuntFinding(
        playbook=PlaybookType.LATERAL_MOVEMENT,
        severity="medium",
        title="Test finding",
        description="Test",
        sigma_rule=rule,
    )
    assert finding.sigma_rule is not None
    assert finding.sigma_rule.title == "Test"


# ── PlaybookResult ───────────────────────────────────────────────


def test_playbook_result_creation() -> None:
    result = PlaybookResult(
        playbook=PlaybookType.DATA_EXFILTRATION,
        config=DataExfiltrationConfig(),
        queries_executed=4,
        events_analyzed=5000,
        duration_seconds=12.5,
        summary="No exfiltration detected",
    )
    assert result.queries_executed == 4
    assert result.events_analyzed == 5000
    assert result.findings == []
    assert result.sigma_rules == []
