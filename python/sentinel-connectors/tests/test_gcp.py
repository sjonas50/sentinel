"""GCP connector tests using mocked GCP SDK clients."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch
from uuid import uuid4

from sentinel_api.models.core import EdgeType
from sentinel_connectors.cloud.gcp import GcpConnector


def _set_gcp_env() -> None:
    """Set fake GCP credentials."""
    os.environ["GCP_PROJECT_ID"] = "test-project"
    os.environ["GCP_REGION"] = "us-central1"
    os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)


def _make_mock_network(name: str = "default") -> MagicMock:
    net = MagicMock()
    net.name = name
    net.self_link = (
        f"https://compute.googleapis.com/compute/v1/projects/test-project/global/networks/{name}"
    )
    return net


def _make_mock_subnet(
    name: str = "default-sub",
    cidr: str = "10.0.0.0/24",
    network: str = "default",
    region: str = "us-central1",
) -> MagicMock:
    sub = MagicMock()
    sub.name = name
    sub.ip_cidr_range = cidr
    sub.network = (
        f"https://compute.googleapis.com/compute/v1/projects/test-project/global/networks/{network}"
    )
    sub.self_link = f"https://compute.googleapis.com/compute/v1/projects/test-project/regions/{region}/subnetworks/{name}"
    return sub


def _make_mock_instance(
    name: str = "web-1",
    zone: str = "us-central1-a",
    subnet_link: str | None = None,
) -> MagicMock:
    inst = MagicMock()
    inst.name = name
    inst.id = 12345
    inst.labels = {"env": "test"}
    inst.tags = MagicMock()
    inst.tags.items = ["http-server"]

    nic = MagicMock()
    nic.network_i_p = "10.0.0.5"
    nic.subnetwork = subnet_link or ""
    inst.network_interfaces = [nic]
    return inst


def _make_mock_firewall(
    name: str = "allow-http",
    network: str = "default",
    target_tags: list[str] | None = None,
) -> MagicMock:
    rule = MagicMock()
    rule.name = name
    rule.network = (
        f"https://compute.googleapis.com/compute/v1/projects/test-project/global/networks/{network}"
    )
    rule.target_tags = target_tags or ["http-server"]
    allowed = MagicMock()
    allowed.I_p_protocol = "tcp"
    allowed.ports = ["80", "443"]
    rule.allowed = [allowed]
    return rule


def _make_mock_iam_binding(role: str, members: list[str]) -> MagicMock:
    binding = MagicMock()
    binding.role = role
    binding.members = members
    return binding


def _make_mock_gke_cluster(
    name: str = "test-gke",
    network: str = "default",
    subnet: str = "default-sub",
) -> MagicMock:
    cluster = MagicMock()
    cluster.name = name
    cluster.endpoint = "35.100.200.1"
    cluster.self_link = f"https://container.googleapis.com/v1/projects/test-project/locations/us-central1/clusters/{name}"
    cluster.location = "us-central1"
    cluster.network = network
    cluster.subnetwork = subnet
    return cluster


# ── Discovery tests ───────────────────────────────────────────


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_vpcs(*mocks: MagicMock) -> None:
    _set_gcp_env()
    net = _make_mock_network()

    with patch("google.cloud.compute_v1.NetworksClient") as mock_client:
        mock_client.return_value.list.return_value = [net]
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.vpcs) == 1
        assert result.vpcs[0].name == "default"
        assert result.vpcs[0].cloud_provider == "gcp"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_subnets(*mocks: MagicMock) -> None:
    _set_gcp_env()
    sub = _make_mock_subnet()

    with patch("google.cloud.compute_v1.SubnetworksClient") as mock_client:
        region_resp = MagicMock()
        region_resp.subnetworks = [sub]
        mock_client.return_value.aggregated_list.return_value = [
            ("regions/us-central1", region_resp)
        ]
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.subnets) == 1
        assert result.subnets[0].cidr == "10.0.0.0/24"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_instances(*mocks: MagicMock) -> None:
    _set_gcp_env()
    inst = _make_mock_instance()

    with patch("google.cloud.compute_v1.InstancesClient") as mock_client:
        zone_resp = MagicMock()
        zone_resp.instances = [inst]
        mock_client.return_value.aggregated_list.return_value = [("zones/us-central1-a", zone_resp)]
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.hosts) == 1
        assert result.hosts[0].hostname == "web-1"
        assert result.hosts[0].ip == "10.0.0.5"
        assert result.hosts[0].cloud_provider == "gcp"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_firewall_rules(*mocks: MagicMock) -> None:
    _set_gcp_env()
    fw = _make_mock_firewall()

    with patch("google.cloud.compute_v1.FirewallsClient") as mock_client:
        mock_client.return_value.list.return_value = [fw]
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.policies) == 1
        assert result.policies[0].name == "allow-http"
        assert result.policies[0].policy_type == "firewall_rule"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_iam(*mocks: MagicMock) -> None:
    _set_gcp_env()
    binding = _make_mock_iam_binding(
        "roles/editor",
        ["user:alice@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"],
    )
    policy = MagicMock()
    policy.bindings = [binding]

    with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
        mock_client.return_value.get_iam_policy.return_value = policy
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.users) == 2
        assert len(result.roles) == 1
        emails = {u.username for u in result.users}
        assert "alice@example.com" in emails
        assert "sa@project.iam.gserviceaccount.com" in emails
        # Check service account type
        sa = next(u for u in result.users if "sa@" in u.username)
        assert sa.user_type == "service_account"
        assert sa.source == "gcp_iam"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_gke_clusters(*mocks: MagicMock) -> None:
    _set_gcp_env()
    cluster = _make_mock_gke_cluster()

    with patch("google.cloud.container_v1.ClusterManagerClient") as mock_client:
        resp = MagicMock()
        resp.clusters = [cluster]
        mock_client.return_value.list_clusters.return_value = resp
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        gke_hosts = [h for h in result.hosts if "kubernetes" in h.tags]
        assert len(gke_hosts) == 1
        assert gke_hosts[0].hostname == "test-gke"
        assert gke_hosts[0].criticality == "high"


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_cloud_sql(*mocks: MagicMock) -> None:
    _set_gcp_env()

    with (
        patch("google.auth.default", return_value=(MagicMock(), "test-project")),
        patch("googleapiclient.discovery.build") as mock_build,
    ):
        mock_service = MagicMock()
        mock_service.instances.return_value.list.return_value.execute.return_value = {
            "items": [{"name": "test-pg", "databaseVersion": "POSTGRES_15", "state": "RUNNABLE"}]
        }
        mock_build.return_value = mock_service
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert len(result.services) == 1
        assert result.services[0].name == "test-pg"
        assert result.services[0].port == 5432  # PostgreSQL


@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters")
@patch("sentinel_connectors.cloud.gcp.GcpConnector._create_edges")
def test_gcp_discover_cloud_sql_mysql(*mocks: MagicMock) -> None:
    _set_gcp_env()

    with (
        patch("google.auth.default", return_value=(MagicMock(), "test-project")),
        patch("googleapiclient.discovery.build") as mock_build,
    ):
        mock_service = MagicMock()
        mock_service.instances.return_value.list.return_value.execute.return_value = {
            "items": [{"name": "test-mysql", "databaseVersion": "MYSQL_8_0", "state": "RUNNABLE"}]
        }
        mock_build.return_value = mock_service
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        assert result.services[0].port == 3306  # MySQL


# ── Edge tests ────────────────────────────────────────────────


def test_gcp_edges_instance_to_subnet() -> None:
    """Verify BELONGS_TO_SUBNET edges from instances to subnets."""
    _set_gcp_env()
    net = _make_mock_network()
    sub = _make_mock_subnet()
    inst = _make_mock_instance(subnet_link=sub.self_link)

    with (
        patch("google.cloud.compute_v1.NetworksClient") as mock_net,
        patch("google.cloud.compute_v1.SubnetworksClient") as mock_sub,
        patch("google.cloud.compute_v1.InstancesClient") as mock_inst,
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql"),
    ):
        mock_net.return_value.list.return_value = [net]
        region_resp = MagicMock()
        region_resp.subnetworks = [sub]
        mock_sub.return_value.aggregated_list.return_value = [("regions/us-central1", region_resp)]
        zone_resp = MagicMock()
        zone_resp.instances = [inst]
        mock_inst.return_value.aggregated_list.return_value = [("zones/us-central1-a", zone_resp)]

        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        subnet_edges = [e for e in result.edges if e.edge_type == EdgeType.BELONGS_TO_SUBNET]
        assert len(subnet_edges) == 1


def test_gcp_edges_subnet_to_vpc() -> None:
    """Verify BELONGS_TO_VPC edges from subnets to VPCs."""
    _set_gcp_env()
    net = _make_mock_network()
    sub = _make_mock_subnet()

    with (
        patch("google.cloud.compute_v1.NetworksClient") as mock_net,
        patch("google.cloud.compute_v1.SubnetworksClient") as mock_sub,
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql"),
    ):
        mock_net.return_value.list.return_value = [net]
        region_resp = MagicMock()
        region_resp.subnetworks = [sub]
        mock_sub.return_value.aggregated_list.return_value = [("regions/us-central1", region_resp)]

        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        vpc_edges = [e for e in result.edges if e.edge_type == EdgeType.BELONGS_TO_VPC]
        assert len(vpc_edges) == 1


def test_gcp_edges_firewall_exposes() -> None:
    """Verify EXPOSES edges from firewall rules to instances via tag matching."""
    _set_gcp_env()
    fw = _make_mock_firewall(target_tags=["http-server"])
    inst = _make_mock_instance()  # has tag "http-server"

    with (
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets"),
        patch("google.cloud.compute_v1.InstancesClient") as mock_inst,
        patch("google.cloud.compute_v1.FirewallsClient") as mock_fw,
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_iam"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql"),
    ):
        zone_resp = MagicMock()
        zone_resp.instances = [inst]
        mock_inst.return_value.aggregated_list.return_value = [("zones/us-central1-a", zone_resp)]
        mock_fw.return_value.list.return_value = [fw]

        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        expose_edges = [e for e in result.edges if e.edge_type == EdgeType.EXPOSES]
        assert len(expose_edges) == 1


def test_gcp_edges_iam_has_access() -> None:
    """Verify HAS_ACCESS edges from IAM bindings."""
    _set_gcp_env()
    binding = _make_mock_iam_binding("roles/editor", ["user:alice@example.com"])
    policy = MagicMock()
    policy.bindings = [binding]

    with (
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_vpcs"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_subnets"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_instances"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_firewall_rules"),
        patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_rm,
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_gke_clusters"),
        patch("sentinel_connectors.cloud.gcp.GcpConnector._discover_cloud_sql"),
    ):
        mock_rm.return_value.get_iam_policy.return_value = policy
        connector = GcpConnector(tenant_id=uuid4())
        result = asyncio.run(connector.sync())
        access_edges = [e for e in result.edges if e.edge_type == EdgeType.HAS_ACCESS]
        assert len(access_edges) == 1


def test_gcp_connector_name() -> None:
    _set_gcp_env()
    connector = GcpConnector(tenant_id=uuid4())
    assert connector.name == "gcp"
