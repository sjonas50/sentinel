"""Tests for MITRE ATT&CK technique taxonomy."""

from __future__ import annotations

from sentinel_agents.simulate.mitre import (
    MITRE_TECHNIQUES,
    TECHNIQUES_BY_TACTIC,
    MitreTechnique,
    get_technique,
    get_techniques_for_tactic,
)
from sentinel_agents.simulate.models import TacticType


def test_total_technique_count() -> None:
    assert len(MITRE_TECHNIQUES) == 20


def test_five_techniques_per_tactic() -> None:
    for tactic in TacticType:
        techniques = TECHNIQUES_BY_TACTIC.get(tactic, [])
        assert len(techniques) == 5, (
            f"Expected 5 techniques for {tactic.value}, got {len(techniques)}"
        )


def test_all_technique_ids_unique() -> None:
    ids = list(MITRE_TECHNIQUES.keys())
    assert len(ids) == len(set(ids))


def test_get_technique_returns_known() -> None:
    t = get_technique("T1190")
    assert t is not None
    assert t.technique_name == "Exploit Public-Facing Application"
    assert t.tactic == TacticType.INITIAL_ACCESS


def test_get_technique_returns_none_for_unknown() -> None:
    assert get_technique("T9999") is None


def test_get_techniques_for_tactic_initial_access() -> None:
    techniques = get_techniques_for_tactic(TacticType.INITIAL_ACCESS)
    assert len(techniques) == 5
    ids = {t.technique_id for t in techniques}
    assert "T1190" in ids
    assert "T1133" in ids
    assert "T1566" in ids
    assert "T1078" in ids
    assert "T1199" in ids


def test_get_techniques_for_tactic_lateral_movement() -> None:
    techniques = get_techniques_for_tactic(TacticType.LATERAL_MOVEMENT)
    assert len(techniques) == 5
    ids = {t.technique_id for t in techniques}
    assert "T1021.001" in ids
    assert "T1021.004" in ids
    assert "T1550.002" in ids


def test_get_techniques_for_tactic_priv_esc() -> None:
    techniques = get_techniques_for_tactic(TacticType.PRIVILEGE_ESCALATION)
    assert len(techniques) == 5
    ids = {t.technique_id for t in techniques}
    assert "T1068" in ids
    assert "T1078.001" in ids
    assert "T1548" in ids


def test_get_techniques_for_tactic_exfiltration() -> None:
    techniques = get_techniques_for_tactic(TacticType.EXFILTRATION)
    assert len(techniques) == 5
    ids = {t.technique_id for t in techniques}
    assert "T1041" in ids
    assert "T1048" in ids
    assert "T1567" in ids


def test_all_techniques_have_mitre_url() -> None:
    for t in MITRE_TECHNIQUES.values():
        assert t.mitre_url.startswith("https://attack.mitre.org/")


def test_all_techniques_have_graph_query() -> None:
    for t in MITRE_TECHNIQUES.values():
        assert len(t.graph_query.node_labels) > 0
        assert len(t.graph_query.description) > 0


def test_technique_is_pydantic_model() -> None:
    t = get_technique("T1190")
    assert isinstance(t, MitreTechnique)
    data = t.model_dump()
    assert "technique_id" in data
    assert "graph_query" in data
