"""Okta identity connector tests using mocked httpx responses."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch
from uuid import uuid4

from sentinel_api.models.core import EdgeType
from sentinel_connectors.identity.okta import OktaConnector


def _set_okta_env() -> None:
    """Set fake Okta credentials."""
    os.environ["OKTA_DOMAIN"] = "dev-12345.okta.com"
    os.environ["OKTA_API_TOKEN"] = "test-token-xyz"


def _make_user(
    uid: str = "user-1",
    login: str = "alice@example.com",
    first: str = "Alice",
    last: str = "Smith",
    status: str = "ACTIVE",
) -> dict:
    return {
        "id": uid,
        "status": status,
        "profile": {
            "login": login,
            "firstName": first,
            "lastName": last,
            "email": login,
        },
    }


def _make_group(
    gid: str = "group-1",
    name: str = "Engineering",
    desc: str = "Engineering team",
) -> dict:
    return {
        "id": gid,
        "profile": {"name": name, "description": desc},
    }


def _make_app(
    aid: str = "app-1",
    label: str = "Slack",
) -> dict:
    return {"id": aid, "label": label, "name": "slack"}


def _make_policy(
    pid: str = "policy-1",
    name: str = "Default Access Policy",
) -> dict:
    return {
        "id": pid,
        "name": name,
        "conditions": {"people": {"everyone": True}},
    }


def _mock_response(json_data, status_code: int = 200) -> MagicMock:
    """Create a mock httpx Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


class MockAsyncClient:
    """Mock httpx.AsyncClient that routes GET requests to canned responses."""

    def __init__(self, routes: dict[str, list | dict] | None = None):
        self._routes = routes or {}

    async def get(self, url: str, **kwargs) -> MagicMock:
        # Exact match first, then longest prefix match
        if url in self._routes:
            return _mock_response(self._routes[url])
        best_key = ""
        for key in self._routes:
            if url.startswith(key) and len(key) > len(best_key):
                best_key = key
        if best_key:
            return _mock_response(self._routes[best_key])
        return _mock_response([])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ── Discovery tests ───────────────────────────────────────────


def test_okta_discover_users() -> None:
    _set_okta_env()
    user = _make_user()
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [{"id": "f1", "factorType": "push"}],
        "/api/v1/groups": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.users) == 1
        assert result.users[0].username == "alice@example.com"
        assert result.users[0].source == "okta"
        assert result.users[0].mfa_enabled is True
        assert result.users[0].enabled is True


def test_okta_user_no_mfa() -> None:
    """User with no enrolled factors → mfa_enabled=False."""
    _set_okta_env()
    user = _make_user()
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.users[0].mfa_enabled is False


def test_okta_user_inactive() -> None:
    """Inactive user has enabled=False."""
    _set_okta_env()
    user = _make_user(status="SUSPENDED")
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.users[0].enabled is False


def test_okta_user_display_name() -> None:
    """Display name is composed from first + last name."""
    _set_okta_env()
    user = _make_user(first="Bob", last="Jones")
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.users[0].display_name == "Bob Jones"


def test_okta_discover_groups() -> None:
    _set_okta_env()
    group = _make_group()
    routes = {
        "/api/v1/users": [],
        "/api/v1/groups": [group],
        "/api/v1/groups/group-1/users": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.groups) == 1
        assert result.groups[0].name == "Engineering"
        assert result.groups[0].source == "okta"


def test_okta_discover_apps() -> None:
    _set_okta_env()
    app = _make_app()
    routes = {
        "/api/v1/users": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [app],
        "/api/v1/apps/app-1/users": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.applications) == 1
        assert result.applications[0].name == "Slack"
        assert result.applications[0].app_type == "web_app"


def test_okta_discover_policies() -> None:
    _set_okta_env()
    policy = _make_policy()
    routes = {
        "/api/v1/users": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [],
        "/api/v1/policies": [policy],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.policies) == 1
        assert result.policies[0].name == "Default Access Policy"
        assert result.policies[0].policy_type == "conditional_access"
        assert result.policies[0].source == "okta"
        assert result.policies[0].rules_json is not None


# ── Edge tests ────────────────────────────────────────────────


def test_okta_edges_member_of() -> None:
    """Verify MEMBER_OF edges from users to groups."""
    _set_okta_env()
    user = _make_user(uid="user-1")
    group = _make_group(gid="group-1")
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [],
        "/api/v1/groups": [group],
        "/api/v1/groups/group-1/users": [{"id": "user-1"}],
        "/api/v1/apps": [],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        member_edges = [
            e for e in result.edges if e.edge_type == EdgeType.MEMBER_OF
        ]
        assert len(member_edges) == 1


def test_okta_edges_has_access() -> None:
    """Verify HAS_ACCESS edges from users to apps."""
    _set_okta_env()
    user = _make_user(uid="user-1")
    app = _make_app(aid="app-1")
    routes = {
        "/api/v1/users": [user],
        "/api/v1/users/user-1/factors": [],
        "/api/v1/groups": [],
        "/api/v1/apps": [app],
        "/api/v1/apps/app-1/users": [{"id": "user-1"}],
        "/api/v1/policies": [],
    }
    mock_client = MockAsyncClient(routes)

    with patch("httpx.AsyncClient", return_value=mock_client):
        connector = OktaConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        access_edges = [
            e for e in result.edges if e.edge_type == EdgeType.HAS_ACCESS
        ]
        assert len(access_edges) == 1


def test_okta_health_check_no_creds() -> None:
    """Health check returns False when no credentials are set."""
    os.environ.pop("OKTA_DOMAIN", None)
    os.environ.pop("OKTA_API_TOKEN", None)
    connector = OktaConnector(tenant_id=uuid4())
    result = asyncio.run(connector.health_check())
    assert result is False


def test_okta_health_check_with_creds() -> None:
    """Health check returns True when credentials are configured."""
    _set_okta_env()
    connector = OktaConnector(tenant_id=uuid4())
    result = asyncio.run(connector.health_check())
    assert result is True
