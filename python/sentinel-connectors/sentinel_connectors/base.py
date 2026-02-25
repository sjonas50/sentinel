"""Abstract base connector with lifecycle hooks and Engram integration."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sentinel_api.engram.session import EngramSession

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.models.core import (
        Application,
        Edge,
        EdgeProperties,
        EdgeType,
        Group,
        Host,
        Policy,
        Role,
        Service,
        Subnet,
        User,
        Vpc,
    )

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Summary of a connector sync operation."""

    connector_name: str
    hosts: list[Host] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    vpcs: list[Vpc] = field(default_factory=list)
    applications: list[Application] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_assets(self) -> int:
        return (
            len(self.hosts)
            + len(self.users)
            + len(self.roles)
            + len(self.policies)
            + len(self.subnets)
            + len(self.vpcs)
            + len(self.applications)
            + len(self.groups)
            + len(self.services)
        )


class BaseConnector(ABC):
    """Abstract interface that all connectors must implement.

    Each connector discovers assets from an external source and returns
    them as structured sentinel-core types. An Engram session is
    automatically created for each sync operation to capture reasoning.
    """

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        self.tenant_id = tenant_id
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique connector identifier, e.g. 'aws', 'azure'."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify credentials and connectivity to the external source."""

    @abstractmethod
    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover assets from the external source.

        The Engram session should be used to log decisions and actions
        taken during discovery. Returns a SyncResult with all found assets.
        """

    def _make_edge(
        self,
        source_id: UUID,
        target_id: UUID,
        edge_type: EdgeType,
        properties: EdgeProperties | None = None,
    ) -> Edge:
        """Create an Edge with the connector's tenant_id."""
        from sentinel_api.models.core import Edge, EdgeProperties

        return Edge(
            tenant_id=self.tenant_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties or EdgeProperties(),
        )

    async def sync(self) -> SyncResult:
        """Run a full sync: create Engram session, discover, finalize.

        This is the main entry point for connector operations.
        """
        session = EngramSession(
            tenant_id=self.tenant_id,
            agent_id=f"connector/{self.name}",
            intent=f"Sync assets from {self.name}",
        )
        session.set_context({"connector": self.name, "config_keys": list(self.config.keys())})

        try:
            result = await self.discover(session)
            session.add_action(
                action_type="sync_complete",
                description=f"Discovered {result.total_assets} assets",
                details={
                    "hosts": len(result.hosts),
                    "users": len(result.users),
                    "roles": len(result.roles),
                    "policies": len(result.policies),
                    "subnets": len(result.subnets),
                    "vpcs": len(result.vpcs),
                    "applications": len(result.applications),
                    "groups": len(result.groups),
                    "services": len(result.services),
                    "edges": len(result.edges),
                    "errors": len(result.errors),
                },
                success=len(result.errors) == 0,
            )
        except Exception as exc:
            session.add_action(
                action_type="sync_failed",
                description=str(exc),
                success=False,
            )
            raise
        finally:
            session.finalize()
            logger.info(
                "Connector %s sync complete: engram=%s",
                self.name,
                session.id,
            )

        return result
