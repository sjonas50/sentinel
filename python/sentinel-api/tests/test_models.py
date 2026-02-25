"""Tests for core domain models — validates Pydantic serialization matches Rust."""

from uuid import uuid4

from sentinel_api.models.core import (
    CloudProvider,
    Criticality,
    Edge,
    EdgeType,
    Host,
    Vulnerability,
    VulnSeverity,
)
from sentinel_api.models.events import (
    EventSource,
    NodeDiscovered,
    SentinelEvent,
)


def test_host_serialization_roundtrip() -> None:
    tenant = uuid4()
    host = Host(
        tenant_id=tenant,
        ip="10.0.1.42",
        hostname="web-server-01",
        os="Ubuntu",
        os_version="22.04",
        cloud_provider=CloudProvider.AWS,
        cloud_instance_id="i-abc123",
        cloud_region="us-east-1",
        criticality=Criticality.HIGH,
        tags=["production", "web"],
    )

    data = host.model_dump()
    roundtripped = Host.model_validate(data)
    assert roundtripped.ip == "10.0.1.42"
    assert roundtripped.cloud_provider == CloudProvider.AWS
    assert roundtripped.criticality == Criticality.HIGH

    json_str = host.model_dump_json()
    assert "10.0.1.42" in json_str
    assert "aws" in json_str


def test_edge_type_values() -> None:
    assert EdgeType.CONNECTS_TO.value == "CONNECTS_TO"
    assert EdgeType.HAS_ACCESS.value == "HAS_ACCESS"
    assert EdgeType.HAS_CVE.value == "HAS_CVE"


def test_vulnerability_fields() -> None:
    vuln = Vulnerability(
        tenant_id=uuid4(),
        cve_id="CVE-2024-1234",
        cvss_score=8.1,
        epss_score=0.42,
        severity=VulnSeverity.HIGH,
        exploitable=True,
        in_cisa_kev=True,
    )

    json_str = vuln.model_dump_json()
    assert "CVE-2024-1234" in json_str
    assert "8.1" in json_str


def test_edge_with_properties() -> None:
    edge = Edge(
        tenant_id=uuid4(),
        source_id=uuid4(),
        target_id=uuid4(),
        edge_type=EdgeType.HAS_ACCESS,
        properties={"permissions": ["ssh", "sudo"]},
    )

    data = edge.model_dump()
    assert data["edge_type"] == "HAS_ACCESS"
    assert "ssh" in data["properties"]["permissions"]


def test_event_serialization() -> None:
    event = SentinelEvent(
        tenant_id=uuid4(),
        source=EventSource.DISCOVER,
        payload=NodeDiscovered(
            node_id=uuid4(),
            node_type="Host",
            label="web-server-01",
        ),
    )

    data = event.model_dump()
    assert data["source"] == "discover"
    assert data["payload"]["event_type"] == "NodeDiscovered"
    assert data["payload"]["label"] == "web-server-01"
