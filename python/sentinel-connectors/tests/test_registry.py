"""Tests for the connector registry."""

from uuid import uuid4

import pytest
from sentinel_api.engram.session import EngramSession
from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.registry import (
    clear_registry,
    get_connector,
    list_connectors,
    register,
)


class FakeConnector(BaseConnector):
    NAME = "fake"

    @property
    def name(self) -> str:
        return "fake"

    async def health_check(self) -> bool:
        return True

    async def discover(self, session: EngramSession) -> SyncResult:
        return SyncResult(connector_name=self.name)


@pytest.fixture(autouse=True)
def _clean_registry() -> None:
    clear_registry()


def test_register_and_list() -> None:
    register(FakeConnector)
    assert "fake" in list_connectors()


def test_get_connector() -> None:
    register(FakeConnector)
    conn = get_connector("fake", tenant_id=uuid4())
    assert conn.name == "fake"


def test_get_unknown_connector_raises() -> None:
    with pytest.raises(KeyError, match="Unknown connector 'nonexistent'"):
        get_connector("nonexistent", tenant_id=uuid4())


def test_clear_registry() -> None:
    register(FakeConnector)
    assert len(list_connectors()) == 1
    clear_registry()
    assert len(list_connectors()) == 0
