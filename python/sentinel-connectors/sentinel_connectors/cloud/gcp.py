"""GCP connector — discovers Compute Engine, VPC, IAM, GKE, Cloud SQL.

Requires google-cloud-compute, google-cloud-resource-manager, google-cloud-container,
google-cloud-sqladmin, and google-auth. These are optional dependencies:
install with ``pip install sentinel-connectors[gcp]``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_api.models.core import (
    CloudProvider,
    Criticality,
    EdgeType,
    Host,
    IdentitySource,
    Policy,
    PolicyType,
    Protocol,
    Role,
    Service,
    ServiceState,
    Subnet,
    User,
    UserType,
    Vpc,
)

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.credentials import GcpCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class GcpConnector(BaseConnector):
    """Discover GCP assets: Compute, VPCs, Subnets, Firewalls, IAM, GKE, Cloud SQL."""

    NAME = "gcp"

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        super().__init__(tenant_id, config)
        self._creds = GcpCredentials.from_env()
        self._project = (
            config.get("project_id", self._creds.project_id) if config else self._creds.project_id
        )
        self._region = config.get("region", self._creds.region) if config else self._creds.region
        self._limiter = RateLimiter(calls_per_second=5.0)

        # Cloud-ID → Sentinel UUID mappings for edge creation
        self._vpc_name_to_uuid: dict[str, UUID] = {}
        self._subnet_link_to_uuid: dict[str, UUID] = {}
        self._host_cloud_to_uuid: dict[str, UUID] = {}
        self._user_email_to_uuid: dict[str, UUID] = {}
        self._role_name_to_uuid: dict[str, UUID] = {}
        self._policy_name_to_uuid: dict[str, UUID] = {}

        # Relationship tracking
        self._instance_subnet: dict[str, str] = {}  # instance_name → subnet self_link
        self._subnet_network: dict[str, str] = {}  # subnet self_link → network name
        self._firewall_network: dict[str, str] = {}  # firewall_name → network name
        self._firewall_target_tags: dict[str, list[str]] = {}  # firewall_name → [tags]
        self._instance_tags: dict[str, list[str]] = {}  # instance_name → [tags]
        self._iam_bindings: list[tuple[str, str]] = []  # (member_email, role_name)
        self._gke_network: dict[str, str] = {}  # cluster_name → network name
        self._gke_subnet: dict[str, str] = {}  # cluster_name → subnet self_link

    @property
    def name(self) -> str:
        return "gcp"

    async def health_check(self) -> bool:
        """Verify GCP credentials by attempting a basic API call."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.ZonesClient()
            request = compute_v1.ListZonesRequest(project=self._project)
            list(client.list(request=request))
            return True
        except Exception:
            logger.warning("GCP health check failed")
            return False

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover all GCP assets."""
        result = SyncResult(connector_name=self.name)

        session.add_decision("full_discovery", "Discovering all supported GCP resource types", 1.0)

        await self._discover_vpcs(result, session)
        await self._discover_subnets(result, session)
        await self._discover_instances(result, session)
        await self._discover_firewall_rules(result, session)
        await self._discover_iam(result, session)
        await self._discover_gke_clusters(result, session)
        await self._discover_cloud_sql(result, session)
        await self._create_edges(result, session)

        return result

    # ── Discovery methods ─────────────────────────────────────────

    async def _discover_vpcs(self, result: SyncResult, session: EngramSession) -> None:
        """Discover GCP VPC networks."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.NetworksClient()
            request = compute_v1.ListNetworksRequest(project=self._project)
            await self._limiter.acquire()
            count = 0
            for network in client.list(request=request):
                vpc = Vpc(
                    tenant_id=self.tenant_id,
                    vpc_id=network.self_link or network.name,
                    name=network.name,
                    cidr=None,  # GCP VPCs don't have a single CIDR
                    cloud_provider=CloudProvider.GCP,
                    region=self._region,
                )
                result.vpcs.append(vpc)
                self._vpc_name_to_uuid[network.name] = vpc.id
                count += 1
            session.add_action("discover_vpcs", f"Found {count} VPC networks", success=True)
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_vpcs", msg, success=False)
        except Exception as exc:
            result.errors.append(f"VPCs: {exc}")
            session.add_action("discover_vpcs", str(exc), success=False)

    async def _discover_subnets(self, result: SyncResult, session: EngramSession) -> None:
        """Discover GCP subnetworks across all regions."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.SubnetworksClient()
            request = compute_v1.AggregatedListSubnetworksRequest(project=self._project)
            await self._limiter.acquire()
            count = 0
            for _region, response in client.aggregated_list(request=request):
                for sub in response.subnetworks or []:
                    subnet = Subnet(
                        tenant_id=self.tenant_id,
                        cidr=sub.ip_cidr_range or "",
                        name=sub.name,
                        cloud_provider=CloudProvider.GCP,
                        vpc_id=sub.network,
                        is_public=False,
                    )
                    result.subnets.append(subnet)
                    if sub.self_link:
                        self._subnet_link_to_uuid[sub.self_link] = subnet.id
                    # Track network name for edges
                    if sub.network:
                        network_name = sub.network.rsplit("/", 1)[-1]
                        self._subnet_network[sub.self_link or sub.name] = network_name
                    count += 1
            session.add_action("discover_subnets", f"Found {count} subnets", success=True)
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_subnets", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Subnets: {exc}")
            session.add_action("discover_subnets", str(exc), success=False)

    async def _discover_instances(self, result: SyncResult, session: EngramSession) -> None:
        """Discover GCP Compute Engine instances across all zones."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.InstancesClient()
            request = compute_v1.AggregatedListInstancesRequest(project=self._project)
            await self._limiter.acquire()
            count = 0
            for zone, response in client.aggregated_list(request=request):
                for inst in response.instances or []:
                    ip = ""
                    subnet_link = ""
                    if inst.network_interfaces:
                        nic = inst.network_interfaces[0]
                        ip = nic.network_i_p or ""
                        subnet_link = nic.subnetwork or ""

                    zone_name = zone.rsplit("/", 1)[-1] if "/" in zone else zone
                    labels = dict(inst.labels) if inst.labels else {}
                    host = Host(
                        tenant_id=self.tenant_id,
                        ip=ip,
                        hostname=inst.name or "",
                        os="linux",
                        cloud_provider=CloudProvider.GCP,
                        cloud_instance_id=str(inst.id) if inst.id else "",
                        cloud_region=zone_name,
                        criticality=Criticality.MEDIUM,
                        tags=list(labels.keys()),
                    )
                    result.hosts.append(host)
                    self._host_cloud_to_uuid[inst.name or ""] = host.id

                    if subnet_link:
                        self._instance_subnet[inst.name or ""] = subnet_link
                    # Track instance tags for firewall matching
                    if inst.tags and inst.tags.items:
                        self._instance_tags[inst.name or ""] = list(inst.tags.items)
                    count += 1
            session.add_action("discover_instances", f"Found {count} instances", success=True)
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_instances", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Compute: {exc}")
            session.add_action("discover_instances", str(exc), success=False)

    async def _discover_firewall_rules(self, result: SyncResult, session: EngramSession) -> None:
        """Discover GCP firewall rules."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.FirewallsClient()
            request = compute_v1.ListFirewallsRequest(project=self._project)
            await self._limiter.acquire()
            count = 0
            for rule in client.list(request=request):
                allowed = [
                    {"protocol": a.I_p_protocol, "ports": list(a.ports or [])}
                    for a in (rule.allowed or [])
                ]
                policy = Policy(
                    tenant_id=self.tenant_id,
                    name=rule.name or "",
                    policy_type=PolicyType.FIREWALL_RULE,
                    source="gcp",
                    rules_json=str(allowed),
                )
                result.policies.append(policy)
                self._policy_name_to_uuid[rule.name or ""] = policy.id

                # Track network and target tags for edges
                if rule.network:
                    network_name = rule.network.rsplit("/", 1)[-1]
                    self._firewall_network[rule.name or ""] = network_name
                if rule.target_tags:
                    self._firewall_target_tags[rule.name or ""] = list(rule.target_tags)
                count += 1
            session.add_action(
                "discover_firewall_rules", f"Found {count} firewall rules", success=True
            )
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_firewall_rules", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Firewalls: {exc}")
            session.add_action("discover_firewall_rules", str(exc), success=False)

    async def _discover_iam(self, result: SyncResult, session: EngramSession) -> None:
        """Discover GCP IAM policy bindings (users, service accounts, roles)."""
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient()
            await self._limiter.acquire()
            policy = client.get_iam_policy(resource=f"projects/{self._project}")

            seen_users: set[str] = set()
            seen_roles: set[str] = set()

            for binding in policy.bindings:
                role_id = binding.role
                if role_id not in seen_roles:
                    role = Role(
                        tenant_id=self.tenant_id,
                        name=role_id,
                        source=IdentitySource.GCP_IAM,
                        permissions=[],
                    )
                    result.roles.append(role)
                    self._role_name_to_uuid[role_id] = role.id
                    seen_roles.add(role_id)

                for member in binding.members:
                    if member in seen_users:
                        self._iam_bindings.append((member, role_id))
                        continue

                    if member.startswith("user:"):
                        email = member.split(":", 1)[1]
                        user = User(
                            tenant_id=self.tenant_id,
                            username=email,
                            email=email,
                            user_type=UserType.HUMAN,
                            source=IdentitySource.GCP_IAM,
                        )
                        result.users.append(user)
                        self._user_email_to_uuid[member] = user.id
                    elif member.startswith("serviceAccount:"):
                        email = member.split(":", 1)[1]
                        user = User(
                            tenant_id=self.tenant_id,
                            username=email,
                            email=email,
                            user_type=UserType.SERVICE_ACCOUNT,
                            source=IdentitySource.GCP_IAM,
                        )
                        result.users.append(user)
                        self._user_email_to_uuid[member] = user.id

                    seen_users.add(member)
                    self._iam_bindings.append((member, role_id))

            session.add_action(
                "discover_iam",
                f"Found {len(result.users)} users/SAs and {len(result.roles)} roles",
                success=True,
            )
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_iam", msg, success=False)
        except Exception as exc:
            result.errors.append(f"IAM: {exc}")
            session.add_action("discover_iam", str(exc), success=False)

    async def _discover_gke_clusters(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Google Kubernetes Engine clusters."""
        try:
            from google.cloud import container_v1

            client = container_v1.ClusterManagerClient()
            await self._limiter.acquire()
            resp = client.list_clusters(parent=f"projects/{self._project}/locations/-")
            count = 0
            for cluster in resp.clusters:
                host = Host(
                    tenant_id=self.tenant_id,
                    ip=cluster.endpoint or "",
                    hostname=cluster.name or "",
                    cloud_provider=CloudProvider.GCP,
                    cloud_instance_id=cluster.self_link or "",
                    cloud_region=cluster.location or self._region,
                    criticality=Criticality.HIGH,
                    tags=["gke", "kubernetes"],
                )
                result.hosts.append(host)
                self._host_cloud_to_uuid[f"gke:{cluster.name}"] = host.id

                if cluster.network:
                    self._gke_network[cluster.name] = cluster.network
                if cluster.subnetwork:
                    self._gke_subnet[cluster.name] = cluster.subnetwork
                count += 1
            session.add_action("discover_gke", f"Found {count} GKE clusters", success=True)
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_gke", msg, success=False)
        except Exception as exc:
            result.errors.append(f"GKE: {exc}")
            session.add_action("discover_gke", str(exc), success=False)

    async def _discover_cloud_sql(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Cloud SQL instances via the SQL Admin API."""
        try:
            import google.auth
            from googleapiclient.discovery import build as build_service

            credentials, _ = google.auth.default()
            service = build_service("sqladmin", "v1beta4", credentials=credentials)
            await self._limiter.acquire()
            resp = service.instances().list(project=self._project).execute()
            count = 0
            for inst in resp.get("items", []):
                db_version = inst.get("databaseVersion", "")
                port = 3306 if "MYSQL" in db_version.upper() else 5432
                state = (
                    ServiceState.RUNNING
                    if inst.get("state") == "RUNNABLE"
                    else ServiceState.STOPPED
                )
                svc = Service(
                    tenant_id=self.tenant_id,
                    name=inst.get("name", ""),
                    port=port,
                    protocol=Protocol.TCP,
                    state=state,
                    version=db_version,
                )
                result.services.append(svc)
                count += 1
            session.add_action(
                "discover_cloud_sql",
                f"Found {count} Cloud SQL instances",
                success=True,
            )
        except ImportError:
            msg = "GCP SDK not installed — install with sentinel-connectors[gcp]"
            result.errors.append(msg)
            session.add_action("discover_cloud_sql", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Cloud SQL: {exc}")
            session.add_action("discover_cloud_sql", str(exc), success=False)

    # ── Edge creation ─────────────────────────────────────────────

    async def _create_edges(self, result: SyncResult, session: EngramSession) -> None:
        """Build graph edges from cloud-ID relationships tracked during discovery."""
        try:
            # Instance → Subnet (BELONGS_TO_SUBNET)
            for inst_name, subnet_link in self._instance_subnet.items():
                host_uuid = self._host_cloud_to_uuid.get(inst_name)
                subnet_uuid = self._subnet_link_to_uuid.get(subnet_link)
                if host_uuid and subnet_uuid:
                    result.edges.append(
                        self._make_edge(host_uuid, subnet_uuid, EdgeType.BELONGS_TO_SUBNET)
                    )

            # Subnet → VPC (BELONGS_TO_VPC)
            for subnet_link, network_name in self._subnet_network.items():
                subnet_uuid = self._subnet_link_to_uuid.get(subnet_link)
                vpc_uuid = self._vpc_name_to_uuid.get(network_name)
                if subnet_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(subnet_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            # Firewall → Instance (EXPOSES) via tag matching
            for fw_name, target_tags in self._firewall_target_tags.items():
                policy_uuid = self._policy_name_to_uuid.get(fw_name)
                if not policy_uuid:
                    continue
                target_set = set(target_tags)
                for inst_name, inst_tags in self._instance_tags.items():
                    if target_set & set(inst_tags):
                        host_uuid = self._host_cloud_to_uuid.get(inst_name)
                        if host_uuid:
                            result.edges.append(
                                self._make_edge(policy_uuid, host_uuid, EdgeType.EXPOSES)
                            )

            # User → Role (HAS_ACCESS) from IAM bindings
            for member, role_name in self._iam_bindings:
                user_uuid = self._user_email_to_uuid.get(member)
                role_uuid = self._role_name_to_uuid.get(role_name)
                if user_uuid and role_uuid:
                    result.edges.append(self._make_edge(user_uuid, role_uuid, EdgeType.HAS_ACCESS))

            # GKE → VPC (BELONGS_TO_VPC)
            for cluster_name, network_name in self._gke_network.items():
                host_uuid = self._host_cloud_to_uuid.get(f"gke:{cluster_name}")
                vpc_uuid = self._vpc_name_to_uuid.get(network_name)
                if host_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(host_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            session.add_action("create_edges", f"Created {len(result.edges)} edges", success=True)
        except Exception as exc:
            result.errors.append(f"Edges: {exc}")
            session.add_action("create_edges", str(exc), success=False)
