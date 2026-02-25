"""Okta identity connector — users, groups, apps, policies.

Discovers identity assets from Okta via its REST API using httpx.
No additional SDK is needed — Okta's API is JSON-based with token auth.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx
from sentinel_api.models.core import (
    Application,
    AppType,
    EdgeType,
    Group,
    IdentitySource,
    Policy,
    PolicyType,
    User,
    UserType,
)

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.credentials import OktaCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class OktaConnector(BaseConnector):
    """Discover Okta identity assets: users, groups, apps, policies."""

    NAME = "okta"

    def __init__(
        self, tenant_id: UUID, config: dict[str, Any] | None = None
    ) -> None:
        super().__init__(tenant_id, config)
        self._creds = OktaCredentials.from_env()
        self._limiter = RateLimiter(calls_per_second=5.0)

        # Cloud-ID → Sentinel UUID mappings for edge creation
        self._user_cloud_to_uuid: dict[str, UUID] = {}
        self._group_cloud_to_uuid: dict[str, UUID] = {}
        self._app_cloud_to_uuid: dict[str, UUID] = {}

        # Relationship tracking
        self._group_members: dict[str, list[str]] = {}  # group_id → [user_id]
        self._app_users: dict[str, list[str]] = {}  # app_id → [user_id]

    @property
    def name(self) -> str:
        return "okta"

    async def health_check(self) -> bool:
        """Verify Okta credentials are configured."""
        return bool(self._creds.domain and self._creds.api_token)

    def _base_url(self) -> str:
        """Build the Okta API base URL from the configured domain."""
        domain = self._creds.domain.rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return domain

    def _headers(self) -> dict[str, str]:
        """Build auth headers for the Okta API."""
        return {
            "Authorization": f"SSWS {self._creds.api_token}",
            "Accept": "application/json",
        }

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover Okta identity assets."""
        result = SyncResult(connector_name=self.name)

        session.add_decision(
            "full_identity_discovery",
            "Discovering Okta users, groups, apps, and policies",
            1.0,
        )

        async with httpx.AsyncClient(
            base_url=self._base_url(),
            headers=self._headers(),
            timeout=30.0,
        ) as client:
            await self._discover_users(result, session, client)
            await self._discover_groups(result, session, client)
            await self._discover_apps(result, session, client)
            await self._discover_policies(result, session, client)
            await self._create_edges(result, session)

        return result

    # ── Discovery methods ─────────────────────────────────────────

    async def _discover_users(
        self,
        result: SyncResult,
        session: EngramSession,
        client: httpx.AsyncClient,
    ) -> None:
        """Discover Okta users with MFA status from enrolled factors."""
        try:
            await self._limiter.acquire()
            resp = await client.get("/api/v1/users")
            resp.raise_for_status()
            users_data = resp.json()

            count = 0
            for u in users_data:
                await self._limiter.acquire()
                uid = u.get("id", "")
                profile = u.get("profile", {})
                status = u.get("status", "")

                # Check enrolled MFA factors
                mfa_enabled = None
                if uid:
                    try:
                        factors_resp = await client.get(
                            f"/api/v1/users/{uid}/factors"
                        )
                        if factors_resp.status_code == 200:
                            factors = factors_resp.json()
                            mfa_enabled = len(factors) > 0
                    except Exception:
                        pass  # Non-critical

                user = User(
                    tenant_id=self.tenant_id,
                    username=profile.get("login", ""),
                    display_name=(
                        f"{profile.get('firstName', '')}"
                        f" {profile.get('lastName', '')}"
                    ).strip() or None,
                    email=profile.get("email"),
                    user_type=UserType.HUMAN,
                    source=IdentitySource.OKTA,
                    enabled=status == "ACTIVE",
                    mfa_enabled=mfa_enabled,
                )
                result.users.append(user)
                if uid:
                    self._user_cloud_to_uuid[uid] = user.id
                count += 1

            session.add_action(
                "discover_users",
                f"Found {count} Okta users",
                success=True,
            )
        except Exception as exc:
            result.errors.append(f"Okta users: {exc}")
            session.add_action("discover_users", str(exc), success=False)

    async def _discover_groups(
        self,
        result: SyncResult,
        session: EngramSession,
        client: httpx.AsyncClient,
    ) -> None:
        """Discover Okta groups and their members."""
        try:
            await self._limiter.acquire()
            resp = await client.get("/api/v1/groups")
            resp.raise_for_status()
            groups_data = resp.json()

            count = 0
            for g in groups_data:
                await self._limiter.acquire()
                gid = g.get("id", "")
                profile = g.get("profile", {})

                group = Group(
                    tenant_id=self.tenant_id,
                    name=profile.get("name", ""),
                    description=profile.get("description"),
                    source=IdentitySource.OKTA,
                )
                result.groups.append(group)
                if gid:
                    self._group_cloud_to_uuid[gid] = group.id
                    # Fetch group members
                    try:
                        members_resp = await client.get(
                            f"/api/v1/groups/{gid}/users"
                        )
                        if members_resp.status_code == 200:
                            members = members_resp.json()
                            member_ids = [
                                m["id"] for m in members if "id" in m
                            ]
                            if member_ids:
                                self._group_members[gid] = member_ids
                    except Exception:
                        pass  # Non-critical
                count += 1

            session.add_action(
                "discover_groups",
                f"Found {count} Okta groups",
                success=True,
            )
        except Exception as exc:
            result.errors.append(f"Okta groups: {exc}")
            session.add_action("discover_groups", str(exc), success=False)

    async def _discover_apps(
        self,
        result: SyncResult,
        session: EngramSession,
        client: httpx.AsyncClient,
    ) -> None:
        """Discover Okta applications and their user assignments."""
        try:
            await self._limiter.acquire()
            resp = await client.get("/api/v1/apps")
            resp.raise_for_status()
            apps_data = resp.json()

            count = 0
            for a in apps_data:
                await self._limiter.acquire()
                aid = a.get("id", "")

                app = Application(
                    tenant_id=self.tenant_id,
                    name=a.get("label", a.get("name", "")),
                    app_type=AppType.WEB_APP,
                )
                result.applications.append(app)
                if aid:
                    self._app_cloud_to_uuid[aid] = app.id
                    # Fetch app user assignments for HAS_ACCESS edges
                    try:
                        users_resp = await client.get(
                            f"/api/v1/apps/{aid}/users"
                        )
                        if users_resp.status_code == 200:
                            app_users = users_resp.json()
                            user_ids = [
                                au["id"]
                                for au in app_users
                                if "id" in au
                            ]
                            if user_ids:
                                self._app_users[aid] = user_ids
                    except Exception:
                        pass  # Non-critical
                count += 1

            session.add_action(
                "discover_apps",
                f"Found {count} Okta applications",
                success=True,
            )
        except Exception as exc:
            result.errors.append(f"Okta apps: {exc}")
            session.add_action("discover_apps", str(exc), success=False)

    async def _discover_policies(
        self,
        result: SyncResult,
        session: EngramSession,
        client: httpx.AsyncClient,
    ) -> None:
        """Discover Okta access policies."""
        try:
            await self._limiter.acquire()
            resp = await client.get(
                "/api/v1/policies", params={"type": "ACCESS_POLICY"}
            )
            resp.raise_for_status()
            policies_data = resp.json()

            count = 0
            for p in policies_data:
                await self._limiter.acquire()
                conditions = p.get("conditions")
                rules_json = json.dumps(conditions) if conditions else None

                policy = Policy(
                    tenant_id=self.tenant_id,
                    name=p.get("name", ""),
                    policy_type=PolicyType.CONDITIONAL_ACCESS,
                    source="okta",
                    rules_json=rules_json,
                )
                result.policies.append(policy)
                count += 1

            session.add_action(
                "discover_policies",
                f"Found {count} Okta access policies",
                success=True,
            )
        except Exception as exc:
            result.errors.append(f"Okta policies: {exc}")
            session.add_action(
                "discover_policies", str(exc), success=False
            )

    # ── Edge creation ─────────────────────────────────────────────

    async def _create_edges(
        self, result: SyncResult, session: EngramSession
    ) -> None:
        """Build graph edges from Okta identity relationships."""
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

            # User → App (HAS_ACCESS)
            for app_id, user_ids in self._app_users.items():
                app_uuid = self._app_cloud_to_uuid.get(app_id)
                if not app_uuid:
                    continue
                for user_id in user_ids:
                    user_uuid = self._user_cloud_to_uuid.get(user_id)
                    if user_uuid:
                        result.edges.append(
                            self._make_edge(
                                user_uuid,
                                app_uuid,
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
