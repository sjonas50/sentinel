"""Tests for the configuration auditor service."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sentinel_api.services.config_auditor import (
    AuditResult,
    ConfigAuditor,
)


class _AsyncRecordIter:
    """Async iterator over mock Neo4j records."""

    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._records):
            raise StopAsyncIteration
        record = self._records[self._index]
        self._index += 1
        return record

    async def single(self):
        if self._records:
            return self._records[0]
        return None


def _make_neo4j_driver(
    resources_by_label: dict[str, list[dict]] | None = None,
    snapshot_hash: str | None = None,
) -> MagicMock:
    """Create a mock Neo4j driver that returns resources per label.

    resources_by_label: {"Policy": [{...}], "User": [{...}], ...}
    """
    if resources_by_label is None:
        resources_by_label = {}

    async def mock_run(cypher, **params):
        # Detect which query type this is
        if "ConfigSnapshot" in cypher and "RETURN s.config_hash" in cypher:
            if snapshot_hash:
                return _AsyncRecordIter(
                    [{"hash": snapshot_hash}]
                )
            return _AsyncRecordIter([])
        if "ConfigSnapshot" in cypher and "MERGE" in cypher:
            return _AsyncRecordIter([])
        if "Finding" in cypher and "MERGE" in cypher:
            return _AsyncRecordIter([])

        # Resource queries: detect label from cypher
        for label, resources in resources_by_label.items():
            if f"(n:{label}" in cypher:
                records = [{"n": r} for r in resources]
                return _AsyncRecordIter(records)

        return _AsyncRecordIter([])

    session = MagicMock()
    session.run = mock_run
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    driver = MagicMock()
    driver.session.return_value = session
    return driver


def test_audit_tenant_no_resources() -> None:
    """Empty graph returns zero findings."""
    driver = _make_neo4j_driver()
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))
    assert isinstance(result, AuditResult)
    assert result.resources_scanned == 0
    assert result.findings_created == 0


def test_audit_tenant_with_sg_violation() -> None:
    """Security group with open SSH produces a finding."""
    resources = {
        "Policy": [
            {
                "id": "sg-123",
                "name": "open-sg",
                "policy_type": "security_group",
                "rules_json": json.dumps(
                    [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ],
                        }
                    ]
                ),
            }
        ],
    }
    driver = _make_neo4j_driver(resources)
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.resources_scanned == 1
    assert result.findings_created >= 1
    assert result.high_count >= 1


def test_audit_tenant_mfa_violation() -> None:
    """IAM user without MFA produces a critical finding."""
    resources = {
        "User": [
            {
                "id": "user-1",
                "username": "alice",
                "source": "aws_iam",
                "mfa_enabled": False,
            }
        ],
    }
    driver = _make_neo4j_driver(resources)
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.resources_scanned == 1
    assert result.findings_created == 1
    assert result.critical_count == 1


def test_audit_tenant_compliant() -> None:
    """Compliant resources produce no findings."""
    resources = {
        "Policy": [
            {
                "id": "sg-ok",
                "name": "good-sg",
                "policy_type": "security_group",
                "rules_json": json.dumps(
                    [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [
                                {"CidrIp": "10.0.0.0/8"}
                            ],
                        }
                    ]
                ),
            }
        ],
        "User": [
            {
                "id": "user-2",
                "username": "bob",
                "source": "aws_iam",
                "mfa_enabled": True,
            }
        ],
    }
    driver = _make_neo4j_driver(resources)
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.resources_scanned == 2
    assert result.findings_created == 0


def test_audit_asset_single() -> None:
    """Auditing a single asset works."""
    resources = {
        "Policy": [
            {
                "id": "sg-target",
                "name": "target-sg",
                "policy_type": "security_group",
                "rules_json": json.dumps(
                    [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ],
                        }
                    ]
                ),
            }
        ],
    }
    driver = _make_neo4j_driver(resources)
    auditor = ConfigAuditor(driver)
    result = asyncio.run(
        auditor.audit_asset(uuid4(), "sg-target")
    )

    assert result.resources_scanned == 1
    assert result.findings_created >= 1
    assert result.critical_count >= 1


def test_audit_config_drift_detected() -> None:
    """Config drift is detected when hash differs."""
    resources = {
        "Policy": [
            {
                "id": "sg-drift",
                "name": "drift-sg",
                "policy_type": "security_group",
                "rules_json": "[]",
            }
        ],
    }
    # Use a different hash than what the resource would produce
    driver = _make_neo4j_driver(
        resources, snapshot_hash="old-hash-value"
    )
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.config_drifts == 1


def test_audit_no_drift_same_hash() -> None:
    """No drift when hash matches."""
    from sentinel_api.services.cis_rules import config_hash

    resource_data = {
        "id": "sg-nodrift",
        "name": "stable-sg",
        "policy_type": "security_group",
        "rules_json": "[]",
        "_label": "Policy",
    }
    expected_hash = config_hash(resource_data)

    resources = {"Policy": [dict(resource_data)]}
    driver = _make_neo4j_driver(
        resources, snapshot_hash=expected_hash
    )
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.config_drifts == 0


def test_audit_multiple_violations() -> None:
    """Multiple resources with violations are all detected."""
    resources = {
        "Policy": [
            {
                "id": "sg-1",
                "name": "sg-ssh",
                "policy_type": "security_group",
                "rules_json": json.dumps(
                    [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ],
                        }
                    ]
                ),
            },
            {
                "id": "pol-1",
                "name": "admin-policy",
                "policy_type": "iam_policy",
                "rules_json": json.dumps(
                    [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                ),
            },
        ],
        "User": [
            {
                "id": "user-nomfa",
                "username": "charlie",
                "source": "aws_iam",
                "mfa_enabled": False,
            }
        ],
    }
    driver = _make_neo4j_driver(resources)
    auditor = ConfigAuditor(driver)
    result = asyncio.run(auditor.audit_tenant(uuid4()))

    assert result.resources_scanned == 3
    assert result.findings_created == 3
    assert result.high_count >= 1
    assert result.critical_count >= 1


def test_audit_result_model() -> None:
    """AuditResult is a valid Pydantic model."""
    r = AuditResult(
        resources_scanned=10,
        rules_evaluated=7,
        findings_created=3,
        critical_count=1,
        high_count=2,
    )
    data = r.model_dump()
    assert data["resources_scanned"] == 10
    assert data["critical_count"] == 1
    assert data["errors"] == []
