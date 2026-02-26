"""Entra ID identity connector tests using mocked Graph API clients."""

from __future__ import annotations

import asyncio
import os
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel_api.models.core import EdgeType
from sentinel_connectors.identity.entra import EntraIdConnector

BASE = "sentinel_connectors.identity.entra.EntraIdConnector"
ALL_METHODS = [
    "_discover_users",
    "_discover_groups",
    "_discover_roles",
    "_discover_conditional_access",
    "_create_edges",
]


def _set_azure_env() -> None:
    """Set fake Azure credentials for Entra ID connector."""
    os.environ["AZURE_TENANT_ID"] = "test-tenant"
    os.environ["AZURE_CLIENT_ID"] = "test-client"
    os.environ["AZURE_CLIENT_SECRET"] = "test-secret"
    os.environ["AZURE_SUBSCRIPTION_ID"] = "test-sub"


def _make_mock_user(
    upn: str = "alice@contoso.com",
    uid: str = "user-1",
    enabled: bool = True,
) -> MagicMock:
    u = MagicMock()
    u.id = uid
    u.user_principal_name = upn
    u.display_name = upn.split("@")[0]
    u.mail = upn
    u.account_enabled = enabled
    return u


def _make_mock_group(name: str = "admins", gid: str = "group-1") -> MagicMock:
    g = MagicMock()
    g.id = gid
    g.display_name = name
    g.description = f"{name} group"
    return g


def _make_mock_role(name: str = "Global Admin", rid: str = "role-1") -> MagicMock:
    r = MagicMock()
    r.id = rid
    r.display_name = name
    r.description = f"{name} role"
    return r


def _make_mock_ca_policy(name: str = "Require MFA", pid: str = "policy-1") -> MagicMock:
    p = MagicMock()
    p.id = pid
    p.display_name = name
    p.conditions = MagicMock()
    p.grant_controls = MagicMock()
    return p


def _patch_others(*keep: str) -> ExitStack:
    """Patch all discovery methods except those in *keep*. Returns an ExitStack."""
    stack = ExitStack()
    for m in ALL_METHODS:
        if m not in keep:
            stack.enter_context(patch(f"{BASE}.{m}"))
    return stack


# ── Discovery tests ───────────────────────────────────────────


@patch(f"{BASE}._get_credential")
def test_entra_discover_users(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    user = _make_mock_user()

    with _patch_others("_discover_users"), patch("msgraph.GraphServiceClient") as mock_graph:
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        # Mock auth methods for MFA check (2 methods = MFA enabled)
        auth_resp = MagicMock()
        auth_resp.value = [MagicMock(), MagicMock()]
        (
            mock_graph.return_value.users.by_user_id.return_value.authentication.methods.get
        ) = AsyncMock(return_value=auth_resp)

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.users) == 1
        assert result.users[0].username == "alice@contoso.com"
        assert result.users[0].source == "entra_id"
        assert result.users[0].mfa_enabled is True


@patch(f"{BASE}._get_credential")
def test_entra_user_no_mfa(mock_cred: MagicMock) -> None:
    """User with only 1 auth method (password) → mfa_enabled=False."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    user = _make_mock_user()

    with _patch_others("_discover_users"), patch("msgraph.GraphServiceClient") as mock_graph:
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        auth_resp = MagicMock()
        auth_resp.value = [MagicMock()]  # Only password
        (
            mock_graph.return_value.users.by_user_id.return_value.authentication.methods.get
        ) = AsyncMock(return_value=auth_resp)

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.users[0].mfa_enabled is False


@patch(f"{BASE}._get_credential")
def test_entra_user_disabled(mock_cred: MagicMock) -> None:
    """Disabled user has enabled=False."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    user = _make_mock_user(enabled=False)

    with _patch_others("_discover_users"), patch("msgraph.GraphServiceClient") as mock_graph:
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        auth_resp = MagicMock()
        auth_resp.value = []
        (
            mock_graph.return_value.users.by_user_id.return_value.authentication.methods.get
        ) = AsyncMock(return_value=auth_resp)

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.users[0].enabled is False


@patch(f"{BASE}._get_credential")
def test_entra_discover_groups(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    group = _make_mock_group()

    with _patch_others("_discover_groups"), patch("msgraph.GraphServiceClient") as mock_graph:
        groups_resp = MagicMock()
        groups_resp.value = [group]
        mock_graph.return_value.groups.get = AsyncMock(return_value=groups_resp)
        members_resp = MagicMock()
        members_resp.value = []
        (mock_graph.return_value.groups.by_group_id.return_value.members.get) = AsyncMock(
            return_value=members_resp
        )

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.groups) == 1
        assert result.groups[0].name == "admins"
        assert result.groups[0].source == "entra_id"


@patch(f"{BASE}._get_credential")
def test_entra_discover_roles(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    role = _make_mock_role()

    with _patch_others("_discover_roles"), patch("msgraph.GraphServiceClient") as mock_graph:
        roles_resp = MagicMock()
        roles_resp.value = [role]
        mock_graph.return_value.directory_roles.get = AsyncMock(return_value=roles_resp)
        members_resp = MagicMock()
        members_resp.value = []
        (
            mock_graph.return_value.directory_roles.by_directory_role_id.return_value.members.get
        ) = AsyncMock(return_value=members_resp)

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.roles) == 1
        assert result.roles[0].name == "Global Admin"
        assert result.roles[0].source == "entra_id"


@patch(f"{BASE}._get_credential")
def test_entra_discover_conditional_access(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    policy = _make_mock_ca_policy()

    with (
        _patch_others("_discover_conditional_access"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        policies_resp = MagicMock()
        policies_resp.value = [policy]
        (mock_graph.return_value.identity.conditional_access.policies.get) = AsyncMock(
            return_value=policies_resp
        )

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.policies) == 1
        assert result.policies[0].name == "Require MFA"
        assert result.policies[0].policy_type == "conditional_access"
        assert result.policies[0].source == "entra_id"


# ── Edge tests ────────────────────────────────────────────────


@patch(f"{BASE}._get_credential")
def test_entra_edges_member_of(mock_cred: MagicMock) -> None:
    """Verify MEMBER_OF edges from users to groups."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()

    user = _make_mock_user(uid="user-1")
    group = _make_mock_group(gid="group-1")

    with (
        _patch_others("_discover_users", "_discover_groups", "_create_edges"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        # Users
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        auth_resp = MagicMock()
        auth_resp.value = []
        (
            mock_graph.return_value.users.by_user_id.return_value.authentication.methods.get
        ) = AsyncMock(return_value=auth_resp)

        # Groups with membership
        groups_resp = MagicMock()
        groups_resp.value = [group]
        mock_graph.return_value.groups.get = AsyncMock(return_value=groups_resp)
        member = MagicMock()
        member.id = "user-1"
        members_resp = MagicMock()
        members_resp.value = [member]
        (mock_graph.return_value.groups.by_group_id.return_value.members.get) = AsyncMock(
            return_value=members_resp
        )

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        member_edges = [e for e in result.edges if e.edge_type == EdgeType.MEMBER_OF]
        assert len(member_edges) == 1


@patch(f"{BASE}._get_credential")
def test_entra_edges_has_access(mock_cred: MagicMock) -> None:
    """Verify HAS_ACCESS edges from users to roles."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()

    user = _make_mock_user(uid="user-1")
    role = _make_mock_role(rid="role-1")

    with (
        _patch_others("_discover_users", "_discover_roles", "_create_edges"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        # Users
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        auth_resp = MagicMock()
        auth_resp.value = []
        (
            mock_graph.return_value.users.by_user_id.return_value.authentication.methods.get
        ) = AsyncMock(return_value=auth_resp)

        # Roles with membership
        roles_resp = MagicMock()
        roles_resp.value = [role]
        mock_graph.return_value.directory_roles.get = AsyncMock(return_value=roles_resp)
        member = MagicMock()
        member.id = "user-1"
        members_resp = MagicMock()
        members_resp.value = [member]
        (
            mock_graph.return_value.directory_roles.by_directory_role_id.return_value.members.get
        ) = AsyncMock(return_value=members_resp)

        connector = EntraIdConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        access_edges = [e for e in result.edges if e.edge_type == EdgeType.HAS_ACCESS]
        assert len(access_edges) == 1


def test_entra_health_check_no_creds() -> None:
    """Health check returns False when no credentials are set."""
    for key in (
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID",
    ):
        os.environ.pop(key, None)
    connector = EntraIdConnector(tenant_id=uuid4())
    result = asyncio.run(connector.health_check())
    assert result is False


def test_entra_health_check_with_creds() -> None:
    """Health check returns True when credentials are configured."""
    _set_azure_env()
    connector = EntraIdConnector(tenant_id=uuid4())
    result = asyncio.run(connector.health_check())
    assert result is True
