"""Azure connector tests using mocked Azure SDK clients."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel_api.models.core import EdgeType
from sentinel_connectors.cloud.azure import AzureConnector


def _set_azure_env() -> None:
    """Set fake Azure credentials."""
    os.environ["AZURE_TENANT_ID"] = "test-tenant"
    os.environ["AZURE_CLIENT_ID"] = "test-client"
    os.environ["AZURE_CLIENT_SECRET"] = "test-secret"
    os.environ["AZURE_SUBSCRIPTION_ID"] = "test-sub"


def _make_mock_vm(name: str = "test-vm", location: str = "eastus") -> MagicMock:
    vm = MagicMock()
    vm.name = name
    vm.vm_id = f"vm-{name}"
    vm.location = location
    vm.tags = {"env": "test"}
    vm.storage_profile = MagicMock()
    vm.storage_profile.os_disk.os_type = "Linux"
    vm.network_profile = MagicMock()
    vm.network_profile.network_interfaces = []
    return vm


def _make_mock_vnet(name: str = "test-vnet", location: str = "eastus") -> MagicMock:
    vnet = MagicMock()
    base = "/subscriptions/sub/resourceGroups/rg/providers"
    vnet.id = f"{base}/Microsoft.Network/virtualNetworks/{name}"
    vnet.name = name
    vnet.location = location
    vnet.address_space = MagicMock()
    vnet.address_space.address_prefixes = ["10.0.0.0/16"]

    # Include subnets
    subnet = MagicMock()
    subnet.id = f"{vnet.id}/subnets/default"
    subnet.name = "default"
    subnet.address_prefix = "10.0.1.0/24"
    vnet.subnets = [subnet]
    return vnet


def _make_mock_nsg(name: str = "test-nsg") -> MagicMock:
    nsg = MagicMock()
    base = "/subscriptions/sub/resourceGroups/rg/providers"
    nsg.id = f"{base}/Microsoft.Network/networkSecurityGroups/{name}"
    nsg.name = name
    nsg.security_rules = [MagicMock(), MagicMock()]
    return nsg


def _make_mock_graph_user(upn: str = "alice@contoso.com", uid: str = "user-1") -> MagicMock:
    u = MagicMock()
    u.id = uid
    u.user_principal_name = upn
    u.display_name = upn.split("@")[0]
    u.mail = upn
    u.account_enabled = True
    return u


def _make_mock_graph_group(name: str = "admins", gid: str = "group-1") -> MagicMock:
    g = MagicMock()
    g.id = gid
    g.display_name = name
    g.description = f"{name} group"
    return g


def _make_mock_graph_role(name: str = "Global Admin", rid: str = "role-1") -> MagicMock:
    r = MagicMock()
    r.id = rid
    r.display_name = name
    r.description = f"{name} role"
    return r


def _make_mock_key_vault(name: str = "test-vault") -> MagicMock:
    vault = MagicMock()
    vault.name = name
    return vault


def _make_mock_aks_cluster(name: str = "test-aks", location: str = "eastus") -> MagicMock:
    cluster = MagicMock()
    base = "/subscriptions/sub/resourceGroups/rg/providers"
    cluster.id = f"{base}/Microsoft.ContainerService/managedClusters/{name}"
    cluster.name = name
    cluster.location = location
    cluster.agent_pool_profiles = []
    return cluster


# ── Discovery tests ───────────────────────────────────────────


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_vms(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    vm = _make_mock_vm()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("azure.mgmt.compute.ComputeManagementClient") as mock_compute,
    ):
        mock_compute.return_value.virtual_machines.list_all.return_value = [vm]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.hosts) == 1
        assert result.hosts[0].hostname == "test-vm"
        assert result.hosts[0].cloud_provider == "azure"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_vnets_and_subnets(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    vnet = _make_mock_vnet()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("azure.mgmt.network.NetworkManagementClient") as mock_net,
    ):
        mock_net.return_value.virtual_networks.list_all.return_value = [vnet]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.vpcs) == 1
        assert result.vpcs[0].name == "test-vnet"
        assert len(result.subnets) == 1
        assert result.subnets[0].cidr == "10.0.1.0/24"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_nsgs(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    nsg = _make_mock_nsg()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("azure.mgmt.network.NetworkManagementClient") as mock_net,
    ):
        mock_net.return_value.network_security_groups.list_all.return_value = [nsg]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.policies) == 1
        assert result.policies[0].name == "test-nsg"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_users(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    user = _make_mock_graph_user()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.users) == 1
        assert result.users[0].username == "alice@contoso.com"
        assert result.users[0].source == "entra_id"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_groups(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    group = _make_mock_graph_group()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        groups_resp = MagicMock()
        groups_resp.value = [group]
        members_resp = MagicMock()
        members_resp.value = []
        mock_graph.return_value.groups.get = AsyncMock(return_value=groups_resp)
        mock_graph.return_value.groups.by_group_id.return_value.members.get = AsyncMock(
            return_value=members_resp
        )
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.groups) == 1
        assert result.groups[0].name == "admins"
        assert result.groups[0].source == "entra_id"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_roles(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    role = _make_mock_graph_role()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        roles_resp = MagicMock()
        roles_resp.value = [role]
        mock_graph.return_value.directory_roles.get = AsyncMock(return_value=roles_resp)
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.roles) == 1
        assert result.roles[0].name == "Global Admin"
        assert result.roles[0].source == "azure_rbac"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_key_vaults(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    vault = _make_mock_key_vault()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("azure.mgmt.keyvault.KeyVaultManagementClient") as mock_kv,
    ):
        mock_kv.return_value.vaults.list.return_value = [vault]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.applications) == 1
        assert result.applications[0].name == "test-vault"
        assert result.applications[0].app_type == "database"


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_discover_aks(mock_cred: MagicMock) -> None:
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    cluster = _make_mock_aks_cluster()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._create_edges"),
        patch("azure.mgmt.containerservice.ContainerServiceClient") as mock_aks,
    ):
        mock_aks.return_value.managed_clusters.list.return_value = [cluster]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        aks_hosts = [h for h in result.hosts if "kubernetes" in h.tags]
        assert len(aks_hosts) == 1
        assert aks_hosts[0].hostname == "test-aks"
        assert aks_hosts[0].criticality == "high"


# ── Edge tests ────────────────────────────────────────────────


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_edges_member_of(mock_cred: MagicMock) -> None:
    """Verify MEMBER_OF edges from users to groups."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()

    user = _make_mock_graph_user(uid="user-1")
    group = _make_mock_graph_group(gid="group-1")

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vnets"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("msgraph.GraphServiceClient") as mock_graph,
    ):
        # Users
        users_resp = MagicMock()
        users_resp.value = [user]
        mock_graph.return_value.users.get = AsyncMock(return_value=users_resp)

        # Groups + membership
        groups_resp = MagicMock()
        groups_resp.value = [group]
        mock_graph.return_value.groups.get = AsyncMock(return_value=groups_resp)

        member = MagicMock()
        member.id = "user-1"
        members_resp = MagicMock()
        members_resp.value = [member]
        mock_graph.return_value.groups.by_group_id.return_value.members.get = AsyncMock(
            return_value=members_resp
        )

        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        member_edges = [e for e in result.edges if e.edge_type == EdgeType.MEMBER_OF]
        assert len(member_edges) == 1


@patch("sentinel_connectors.cloud.azure.AzureConnector._get_credential")
def test_azure_edges_subnet_to_vnet(mock_cred: MagicMock) -> None:
    """Verify BELONGS_TO_VPC edges from subnets to VNets."""
    _set_azure_env()
    mock_cred.return_value = MagicMock()
    vnet = _make_mock_vnet()

    with (
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_vms"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_nsgs"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_users"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_groups"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_roles"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_key_vaults"),
        patch("sentinel_connectors.cloud.azure.AzureConnector._discover_aks_clusters"),
        patch("azure.mgmt.network.NetworkManagementClient") as mock_net,
    ):
        mock_net.return_value.virtual_networks.list_all.return_value = [vnet]
        connector = AzureConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        vpc_edges = [e for e in result.edges if e.edge_type == EdgeType.BELONGS_TO_VPC]
        assert len(vpc_edges) == 1


def test_azure_health_check_no_creds() -> None:
    """Health check returns False when no credentials are set."""
    keys = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID")
    for key in keys:
        os.environ.pop(key, None)
    connector = AzureConnector(tenant_id=uuid4())
    result = asyncio.run(connector.health_check())
    assert result is False
