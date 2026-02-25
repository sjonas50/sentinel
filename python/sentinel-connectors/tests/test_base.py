"""Tests for the base connector and SyncResult."""

from uuid import uuid4

import pytest
from sentinel_api.engram.session import EngramSession
from sentinel_connectors.base import BaseConnector, SyncResult


class DummyConnector(BaseConnector):
    """Minimal connector for testing the base class."""

    @property
    def name(self) -> str:
        return "dummy"

    async def health_check(self) -> bool:
        return True

    async def discover(self, session: EngramSession) -> SyncResult:
        session.add_action("test", "dummy discovery", success=True)
        return SyncResult(connector_name=self.name)


def test_sync_result_total_assets() -> None:
    r = SyncResult(connector_name="test")
    assert r.total_assets == 0


def test_sync_result_total_assets_includes_new_fields() -> None:
    from sentinel_api.models.core import Application, AppType, Group, Service

    tid = uuid4()
    r = SyncResult(connector_name="test")
    r.applications.append(Application(tenant_id=tid, name="bucket", app_type=AppType.DATABASE))
    r.groups.append(Group(tenant_id=tid, name="admins"))
    r.services.append(Service(tenant_id=tid, name="db", port=5432))
    assert r.total_assets == 3


@pytest.mark.asyncio
async def test_base_connector_sync() -> None:
    tid = uuid4()
    connector = DummyConnector(tenant_id=tid)
    result = await connector.sync()
    assert result.connector_name == "dummy"
    assert result.total_assets == 0
    assert len(result.errors) == 0


@pytest.mark.asyncio
async def test_base_connector_name() -> None:
    connector = DummyConnector(tenant_id=uuid4())
    assert connector.name == "dummy"


@pytest.mark.asyncio
async def test_base_connector_health_check() -> None:
    connector = DummyConnector(tenant_id=uuid4())
    assert await connector.health_check() is True
