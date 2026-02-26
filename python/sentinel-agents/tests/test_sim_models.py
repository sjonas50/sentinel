"""Tests for simulation models."""

from __future__ import annotations

from uuid import UUID

from sentinel_agents.simulate.models import (
    ExfiltrationConfig,
    GraphProtocol,
    InitialAccessConfig,
    LateralMovementSimConfig,
    PrivilegeEscalationConfig,
    RemediationStep,
    SimConfig,
    SimulationFinding,
    SimulationResult,
    TacticType,
)

# ── TacticType ──────────────────────────────────────────────────


def test_tactic_type_values() -> None:
    assert TacticType.INITIAL_ACCESS == "initial_access"
    assert TacticType.LATERAL_MOVEMENT == "lateral_movement"
    assert TacticType.PRIVILEGE_ESCALATION == "privilege_escalation"
    assert TacticType.EXFILTRATION == "exfiltration"


def test_tactic_type_count() -> None:
    assert len(TacticType) == 4


# ── SimConfig ───────────────────────────────────────────────────


def test_sim_config_defaults() -> None:
    cfg = SimConfig(tactic=TacticType.INITIAL_ACCESS)
    assert cfg.max_paths == 50
    assert cfg.max_depth == 10
    assert cfg.min_exploitability == 0.3
    assert cfg.include_blast_radius is True
    assert cfg.techniques == []
    assert cfg.target_node_ids == []
    assert cfg.source_node_ids == []


def test_initial_access_config_defaults() -> None:
    cfg = InitialAccessConfig()
    assert cfg.tactic == TacticType.INITIAL_ACCESS
    assert cfg.check_exposed_services is True
    assert cfg.check_phishing_vectors is True
    assert cfg.check_valid_accounts is True
    assert 3389 in cfg.exposed_service_ports
    assert 22 in cfg.exposed_service_ports


def test_lateral_movement_sim_config_defaults() -> None:
    cfg = LateralMovementSimConfig()
    assert cfg.tactic == TacticType.LATERAL_MOVEMENT
    assert cfg.max_chain_length == 8
    assert cfg.check_credential_reuse is True
    assert cfg.check_trust_exploitation is True


def test_privilege_escalation_config_defaults() -> None:
    cfg = PrivilegeEscalationConfig()
    assert cfg.tactic == TacticType.PRIVILEGE_ESCALATION
    assert cfg.check_misconfigs is True
    assert "admin" in cfg.admin_role_patterns


def test_exfiltration_config_defaults() -> None:
    cfg = ExfiltrationConfig()
    assert cfg.tactic == TacticType.EXFILTRATION
    assert cfg.check_data_paths is True
    assert "pii" in cfg.sensitive_data_labels


def test_config_custom_values() -> None:
    cfg = SimConfig(
        tactic=TacticType.EXFILTRATION,
        techniques=["T1041", "T1048"],
        max_paths=10,
        min_exploitability=0.5,
    )
    assert cfg.techniques == ["T1041", "T1048"]
    assert cfg.max_paths == 10
    assert cfg.min_exploitability == 0.5


# ── RemediationStep ─────────────────────────────────────────────


def test_remediation_step() -> None:
    step = RemediationStep(
        title="Patch CVE",
        description="Apply patches",
        priority="critical",
        effort="medium",
    )
    assert step.title == "Patch CVE"
    assert step.automated is False


def test_remediation_step_automated() -> None:
    step = RemediationStep(
        title="Block IP",
        description="Block at firewall",
        priority="high",
        effort="low",
        automated=True,
    )
    assert step.automated is True


# ── SimulationFinding ───────────────────────────────────────────


def test_simulation_finding_creation() -> None:
    finding = SimulationFinding(
        tactic=TacticType.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        severity="critical",
        title="Exploitable service found",
        description="Test description",
    )
    assert isinstance(finding.id, UUID)
    assert finding.risk_score == 0.0
    assert finding.attack_paths == []
    assert finding.remediation == []


def test_simulation_finding_with_remediation() -> None:
    finding = SimulationFinding(
        tactic=TacticType.LATERAL_MOVEMENT,
        technique_id="T1021.001",
        technique_name="RDP",
        severity="high",
        title="RDP chain",
        description="Found RDP lateral chain",
        risk_score=7.5,
        remediation=[
            RemediationStep(
                title="Enable NLA",
                description="Enable NLA for RDP",
                priority="high",
                effort="low",
            ),
        ],
    )
    assert finding.risk_score == 7.5
    assert len(finding.remediation) == 1


# ── SimulationResult ────────────────────────────────────────────


def test_simulation_result_creation() -> None:
    result = SimulationResult(
        tactic=TacticType.EXFILTRATION,
        config=ExfiltrationConfig(),
        techniques_tested=5,
        techniques_with_findings=2,
        highest_risk_score=8.5,
        duration_seconds=12.3,
        summary="Test summary",
    )
    assert result.techniques_tested == 5
    assert result.highest_risk_score == 8.5
    assert result.findings == []


# ── GraphProtocol ───────────────────────────────────────────────


def test_graph_protocol_is_runtime_checkable() -> None:
    """Verify that a mock can satisfy GraphProtocol."""

    class _MinimalGraph:
        async def query_nodes(self, label, tenant_id, *, filters=None, limit=100):
            return []

        async def query_neighbors(
            self,
            node_id,
            tenant_id,
            *,
            edge_types=None,
            target_labels=None,
            limit=100,
        ):
            return []

        async def find_attack_paths(
            self,
            tenant_id,
            *,
            sources=None,
            targets=None,
            max_depth=10,
            max_paths=100,
            include_lateral=False,
            include_blast=False,
        ):
            return {}

        async def compute_blast_radius(
            self,
            tenant_id,
            compromised_node_id,
            *,
            max_hops=5,
            min_exploitability=0.3,
        ):
            return {}

        async def query_edges(
            self,
            tenant_id,
            *,
            edge_type=None,
            source_label=None,
            target_label=None,
            limit=200,
        ):
            return []

    assert isinstance(_MinimalGraph(), GraphProtocol)
