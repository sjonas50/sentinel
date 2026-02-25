"""Entra ID identity connector — users, groups, roles, conditional access.

Discovers identity assets from Microsoft Entra ID (formerly Azure AD) via
the Microsoft Graph API. Provides deeper identity coverage than the Azure
cloud connector: MFA status per user, conditional access policies, and
comprehensive role/group membership edges.

Requires ``msgraph-sdk`` and ``azure-identity``. Install with
``pip install sentinel-connectors[azure]``.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from sentinel_api.models.core import (
    EdgeType,
    Group,
    IdentitySource,
    Policy,
    PolicyType,
    Role,
    User,
    UserType,
)

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.credentials import AzureCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class EntraIdConnector(BaseConnector):
    """Discover Entra ID identity assets: users, groups, roles, conditional access."""

    NAME = "entra_id"

    def __init__(
        self, tenant_id: UUID, config: dict[str, Any] | None = None
    ) -> None:
        super().__init__(tenant_id, config)
        self._creds = AzureCredentials.from_env()
        self._limiter = RateLimiter(calls_per_second=5.0)

        # Cloud-ID → Sentinel UUID mappings for edge creation
        self._user_cloud_to_uuid: dict[str, UUID] = {}
        self._group_cloud_to_uuid: dict[str, UUID] = {}
        self._role_cloud_to_uuid: dict[str, UUID] = {}

        # Relationship tracking
        self._group_members: dict[str, list[str]] = {}  # group_id → [user_id]
        self._role_members: dict[str, list[str]] = {}  # role_id → [user_id]

    @property
    def name(self) -> str:
        return "entra_id"

    async def health_check(self) -> bool:
        """Verify Azure credentials are configured."""
        return bool(self._creds.client_id and self._creds.client_secret)

    def _get_credential(self) -> Any:
        """Create an Azure ClientSecretCredential."""
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=self._creds.tenant_id,
            client_id=self._creds.client_id,
            client_secret=self._creds.client_secret,
        )

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover Entra ID identity assets."""
        result = SyncResult(connector_name=self.name)

        session.add_decision(
            "full_identity_discovery",
            "Discovering Entra ID users, groups, roles, and conditional access",
            1.0,
        )

        await self._discover_users(result, session)
        await self._discover_groups(result, session)
        await self._discover_roles(result, session)
        await self._discover_conditional_access(result, session)
        await self._create_edges(result, session)

        return result

    # ── Discovery methods ─────────────────────────────────────────

    async def _discover_users(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Discover Entra ID users with MFA status."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            users_resp = await graph.users.get()
            count = 0
            for u in users_resp.value or []:
                await self._limiter.acquire()
                mfa_enabled = None
                # Check authentication methods to determine MFA status
                if u.id:
                    try:
                        auth_resp = (
                            await graph.users.by_user_id(u.id)
                            .authentication.methods.get()
                        )
                        methods = auth_resp.value or []
                        # More than 1 method means MFA (password + something)
                        mfa_enabled = len(methods) > 1
                    except Exception:
                        pass  # Non-critical: MFA check can fail

                user = User(
                    tenant_id=self.tenant_id,
                    username=(
                        u.user_principal_name or u.display_name or ""
                    ),
                    display_name=u.display_name,
                    email=u.mail,
                    user_type=UserType.HUMAN,
                    source=IdentitySource.ENTRA_ID,
                    enabled=u.account_enabled or False,
                    mfa_enabled=mfa_enabled,
                )
                result.users.append(user)
                if u.id:
                    self._user_cloud_to_uuid[u.id] = user.id
                count += 1
            session.add_action(
                "discover_users",
                f"Found {count} Entra ID users",
                success=True,
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed — install with sentinel-connectors[azure]"
            result.errors.append(msg)
            session.add_action("discover_users", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID users: {exc}")
            session.add_action("discover_users", str(exc), success=False)

    async def _discover_groups(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Discover Entra ID groups and their members."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            groups_resp = await graph.groups.get()
            count = 0
            for g in groups_resp.value or []:
                await self._limiter.acquire()
                group = Group(
                    tenant_id=self.tenant_id,
                    name=g.display_name or "",
                    description=g.description,
                    source=IdentitySource.ENTRA_ID,
                )
                result.groups.append(group)
                if g.id:
                    self._group_cloud_to_uuid[g.id] = group.id
                    # Fetch group members for MEMBER_OF edges
                    try:
                        members_resp = (
                            await graph.groups.by_group_id(g.id)
                            .members.get()
                        )
                        member_ids = [
                            m.id
                            for m in (members_resp.value or [])
                            if m.id
                        ]
                        if member_ids:
                            self._group_members[g.id] = member_ids
                    except Exception:
                        pass  # Non-critical
                count += 1
            session.add_action(
                "discover_groups",
                f"Found {count} Entra ID groups",
                success=True,
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_groups", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID groups: {exc}")
            session.add_action("discover_groups", str(exc), success=False)

    async def _discover_roles(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Discover Entra ID directory roles and their members."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            roles_resp = await graph.directory_roles.get()
            count = 0
            for r in roles_resp.value or []:
                await self._limiter.acquire()
                role = Role(
                    tenant_id=self.tenant_id,
                    name=r.display_name or "",
                    description=r.description,
                    source=IdentitySource.ENTRA_ID,
                    permissions=[],
                )
                result.roles.append(role)
                if r.id:
                    self._role_cloud_to_uuid[r.id] = role.id
                    # Fetch role members for HAS_ACCESS edges
                    try:
                        members_resp = (
                            await graph.directory_roles
                            .by_directory_role_id(r.id)
                            .members.get()
                        )
                        member_ids = [
                            m.id
                            for m in (members_resp.value or [])
                            if m.id
                        ]
                        if member_ids:
                            self._role_members[r.id] = member_ids
                    except Exception:
                        pass  # Non-critical
                count += 1
            session.add_action(
                "discover_roles",
                f"Found {count} Entra ID directory roles",
                success=True,
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_roles", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID roles: {exc}")
            session.add_action("discover_roles", str(exc), success=False)

    async def _discover_conditional_access(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Discover Entra ID conditional access policies."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            policies_resp = (
                await graph.identity.conditional_access.policies.get()
            )
            count = 0
            for p in policies_resp.value or []:
                await self._limiter.acquire()
                rules = {}
                if p.conditions:
                    rules["conditions"] = str(p.conditions)
                if p.grant_controls:
                    rules["grant_controls"] = str(p.grant_controls)

                policy = Policy(
                    tenant_id=self.tenant_id,
                    name=p.display_name or "",
                    policy_type=PolicyType.CONDITIONAL_ACCESS,
                    source="entra_id",
                    rules_json=json.dumps(rules) if rules else None,
                )
                result.policies.append(policy)
                count += 1
            session.add_action(
                "discover_conditional_access",
                f"Found {count} conditional access policies",
                success=True,
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action(
                "discover_conditional_access", msg, success=False
            )
        except Exception as exc:
            result.errors.append(f"Conditional access: {exc}")
            session.add_action(
                "discover_conditional_access", str(exc), success=False
            )

    # ── Edge creation ─────────────────────────────────────────────

    async def _create_edges(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Build graph edges from identity relationships."""
        try:
            # User → Group (MEMBER_OF)
            for group_id, member_ids in self._group_members.items():
                group_uuid = self._group_cloud_to_uuid.get(group_id)
                if not group_uuid:
                    continue
                for member_id in member_ids:
                    user_uuid = self._user_cloud_to_uuid.get(member_id)
                    if user_uuid:
                        result.edges.append(
                            self._make_edge(
                                user_uuid,
                                group_uuid,
                                EdgeType.MEMBER_OF,
                            )
                        )

            # User → Role (HAS_ACCESS)
            for role_id, member_ids in self._role_members.items():
                role_uuid = self._role_cloud_to_uuid.get(role_id)
                if not role_uuid:
                    continue
                for member_id in member_ids:
                    user_uuid = self._user_cloud_to_uuid.get(member_id)
                    if user_uuid:
                        result.edges.append(
                            self._make_edge(
                                user_uuid,
                                role_uuid,
                                EdgeType.HAS_ACCESS,
                            )
                        )

            session.add_action(
                "create_edges",
                f"Created {len(result.edges)} identity edges",
                success=True,
            )
        except Exception as exc:
            result.errors.append(f"Edges: {exc}")
            session.add_action("create_edges", str(exc), success=False)
