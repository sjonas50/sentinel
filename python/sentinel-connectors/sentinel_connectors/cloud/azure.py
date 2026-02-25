"""Azure connector — discovers VMs, VNets, NSGs, Entra ID, Key Vault, AKS.

Requires azure-identity, azure-mgmt-compute, azure-mgmt-network, azure-mgmt-keyvault,
azure-mgmt-containerservice, and msgraph-sdk. These are optional dependencies:
install with ``pip install sentinel-connectors[azure]``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_api.models.core import (
    Application,
    AppType,
    CloudProvider,
    Criticality,
    EdgeType,
    Group,
    Host,
    IdentitySource,
    Policy,
    PolicyType,
    Role,
    Subnet,
    User,
    UserType,
    Vpc,
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
class AzureConnector(BaseConnector):
    """Discover Azure assets: VMs, VNets, Subnets, NSGs, Entra ID, Key Vault, AKS."""

    NAME = "azure"

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        super().__init__(tenant_id, config)
        self._creds = AzureCredentials.from_env()
        self._limiter = RateLimiter(calls_per_second=5.0)

        # Cloud-ID → Sentinel UUID mappings for edge creation
        self._vpc_cloud_to_uuid: dict[str, UUID] = {}
        self._subnet_cloud_to_uuid: dict[str, UUID] = {}
        self._host_cloud_to_uuid: dict[str, UUID] = {}
        self._policy_cloud_to_uuid: dict[str, UUID] = {}
        self._user_cloud_to_uuid: dict[str, UUID] = {}
        self._group_cloud_to_uuid: dict[str, UUID] = {}
        self._role_cloud_to_uuid: dict[str, UUID] = {}

        # Relationship tracking
        self._vm_subnet: dict[str, str] = {}  # vm_id → subnet resource_id
        self._vm_nsgs: dict[str, list[str]] = {}  # vm_id → [nsg resource_id]
        self._subnet_vnet: dict[str, str] = {}  # subnet resource_id → vnet resource_id
        self._group_members: dict[str, list[str]] = {}  # group_id → [user_id]
        self._aks_vnet: dict[str, str] = {}  # cluster_id → vnet resource_id

    @property
    def name(self) -> str:
        return "azure"

    async def health_check(self) -> bool:
        """Verify Azure credentials are configured."""
        return bool(self._creds.client_id and self._creds.client_secret)

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover Azure assets."""
        result = SyncResult(connector_name=self.name)

        session.add_decision(
            "full_discovery", "Discovering all supported Azure resource types", 1.0
        )

        await self._discover_vnets(result, session)
        await self._discover_vms(result, session)
        await self._discover_nsgs(result, session)
        await self._discover_users(result, session)
        await self._discover_groups(result, session)
        await self._discover_roles(result, session)
        await self._discover_key_vaults(result, session)
        await self._discover_aks_clusters(result, session)
        await self._create_edges(result, session)

        return result

    def _get_credential(self) -> Any:
        """Create an Azure ClientSecretCredential."""
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=self._creds.tenant_id,
            client_id=self._creds.client_id,
            client_secret=self._creds.client_secret,
        )

    # ── Discovery methods ─────────────────────────────────────────

    async def _discover_vms(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure VMs via azure-mgmt-compute."""
        try:
            from azure.mgmt.compute import ComputeManagementClient

            credential = self._get_credential()
            compute = ComputeManagementClient(credential, self._creds.subscription_id)

            count = 0
            for vm in compute.virtual_machines.list_all():
                host = Host(
                    tenant_id=self.tenant_id,
                    ip="",
                    hostname=vm.name or "",
                    os=vm.storage_profile.os_disk.os_type if vm.storage_profile else None,
                    cloud_provider=CloudProvider.AZURE,
                    cloud_instance_id=vm.vm_id or "",
                    cloud_region=vm.location or "",
                    criticality=Criticality.MEDIUM,
                    tags=list((vm.tags or {}).keys()),
                )
                result.hosts.append(host)
                vm_id = vm.vm_id or vm.name or ""
                self._host_cloud_to_uuid[vm_id] = host.id

                # Track NIC → subnet for edges
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic_ref in vm.network_profile.network_interfaces:
                        if nic_ref.id:
                            self._vm_subnet[vm_id] = nic_ref.id
                count += 1
            session.add_action("discover_vms", f"Found {count} VMs", success=True)
        except ImportError:
            msg = "Azure SDK not installed — install with sentinel-connectors[azure]"
            result.errors.append(msg)
            session.add_action("discover_vms", msg, success=False)
        except Exception as exc:
            result.errors.append(f"VMs: {exc}")
            session.add_action("discover_vms", str(exc), success=False)

    async def _discover_vnets(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure VNets and their subnets."""
        try:
            from azure.mgmt.network import NetworkManagementClient

            credential = self._get_credential()
            network = NetworkManagementClient(credential, self._creds.subscription_id)

            vnet_count = 0
            subnet_count = 0
            for vnet in network.virtual_networks.list_all():
                space = vnet.address_space
                cidrs = space.address_prefixes if space else []
                vpc = Vpc(
                    tenant_id=self.tenant_id,
                    vpc_id=vnet.id or "",
                    name=vnet.name,
                    cidr=cidrs[0] if cidrs else None,
                    cloud_provider=CloudProvider.AZURE,
                    region=vnet.location or "",
                )
                result.vpcs.append(vpc)
                self._vpc_cloud_to_uuid[vnet.id or ""] = vpc.id
                vnet_count += 1

                # Discover subnets within this VNet
                for s in vnet.subnets or []:
                    subnet = Subnet(
                        tenant_id=self.tenant_id,
                        cidr=s.address_prefix or "",
                        name=s.name,
                        cloud_provider=CloudProvider.AZURE,
                        vpc_id=vnet.id,
                        is_public=False,
                    )
                    result.subnets.append(subnet)
                    if s.id:
                        self._subnet_cloud_to_uuid[s.id] = subnet.id
                        self._subnet_vnet[s.id] = vnet.id or ""
                    subnet_count += 1

            session.add_action(
                "discover_vnets",
                f"Found {vnet_count} VNets and {subnet_count} subnets",
                success=True,
            )
        except ImportError:
            msg = "Azure SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_vnets", msg, success=False)
        except Exception as exc:
            result.errors.append(f"VNets: {exc}")
            session.add_action("discover_vnets", str(exc), success=False)

    async def _discover_nsgs(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure Network Security Groups."""
        try:
            from azure.mgmt.network import NetworkManagementClient

            credential = self._get_credential()
            network = NetworkManagementClient(credential, self._creds.subscription_id)
            count = 0
            for nsg in network.network_security_groups.list_all():
                policy = Policy(
                    tenant_id=self.tenant_id,
                    name=nsg.name or "",
                    policy_type=PolicyType.SECURITY_GROUP,
                    source="azure",
                    rules_json=str(len(nsg.security_rules or [])) + " rules",
                )
                result.policies.append(policy)
                if nsg.id:
                    self._policy_cloud_to_uuid[nsg.id] = policy.id
                count += 1
            session.add_action("discover_nsgs", f"Found {count} NSGs", success=True)
        except ImportError:
            msg = "Azure SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_nsgs", msg, success=False)
        except Exception as exc:
            result.errors.append(f"NSGs: {exc}")
            session.add_action("discover_nsgs", str(exc), success=False)

    async def _discover_users(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Entra ID users via Microsoft Graph."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            users_resp = await graph.users.get()
            for u in users_resp.value or []:
                user = User(
                    tenant_id=self.tenant_id,
                    username=u.user_principal_name or u.display_name or "",
                    display_name=u.display_name,
                    email=u.mail,
                    user_type=UserType.HUMAN,
                    source=IdentitySource.ENTRA_ID,
                    enabled=u.account_enabled or False,
                )
                result.users.append(user)
                if u.id:
                    self._user_cloud_to_uuid[u.id] = user.id
            session.add_action(
                "discover_users", f"Found {len(result.users)} Entra ID users", success=True
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_users", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID: {exc}")
            session.add_action("discover_users", str(exc), success=False)

    async def _discover_groups(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Entra ID groups via Microsoft Graph."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            groups_resp = await graph.groups.get()
            count = 0
            for g in groups_resp.value or []:
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
                        members_resp = await graph.groups.by_group_id(g.id).members.get()
                        member_ids = [
                            m.id for m in (members_resp.value or []) if m.id
                        ]
                        if member_ids:
                            self._group_members[g.id] = member_ids
                    except Exception:
                        pass  # Non-critical: group membership lookup can fail
                count += 1
            session.add_action(
                "discover_groups", f"Found {count} Entra ID groups", success=True
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_groups", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID groups: {exc}")
            session.add_action("discover_groups", str(exc), success=False)

    async def _discover_roles(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Entra ID directory roles via Microsoft Graph."""
        try:
            from msgraph import GraphServiceClient

            credential = self._get_credential()
            graph = GraphServiceClient(credential)
            roles_resp = await graph.directory_roles.get()
            count = 0
            for r in roles_resp.value or []:
                role = Role(
                    tenant_id=self.tenant_id,
                    name=r.display_name or "",
                    description=r.description,
                    source=IdentitySource.AZURE_RBAC,
                    permissions=[],
                )
                result.roles.append(role)
                if r.id:
                    self._role_cloud_to_uuid[r.id] = role.id
                count += 1
            session.add_action(
                "discover_roles", f"Found {count} Entra ID roles", success=True
            )
        except ImportError:
            msg = "Azure/Graph SDK not installed"
            result.errors.append(msg)
            session.add_action("discover_roles", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Entra ID roles: {exc}")
            session.add_action("discover_roles", str(exc), success=False)

    async def _discover_key_vaults(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure Key Vaults."""
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient

            credential = self._get_credential()
            kv_client = KeyVaultManagementClient(credential, self._creds.subscription_id)
            count = 0
            for vault in kv_client.vaults.list():
                app = Application(
                    tenant_id=self.tenant_id,
                    name=vault.name or "",
                    app_type=AppType.DATABASE,
                )
                result.applications.append(app)
                count += 1
            session.add_action(
                "discover_key_vaults", f"Found {count} Key Vaults", success=True
            )
        except ImportError:
            msg = "azure-mgmt-keyvault not installed — install with sentinel-connectors[azure]"
            result.errors.append(msg)
            session.add_action("discover_key_vaults", msg, success=False)
        except Exception as exc:
            result.errors.append(f"Key Vaults: {exc}")
            session.add_action("discover_key_vaults", str(exc), success=False)

    async def _discover_aks_clusters(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure Kubernetes Service (AKS) clusters."""
        try:
            from azure.mgmt.containerservice import ContainerServiceClient

            credential = self._get_credential()
            aks_client = ContainerServiceClient(credential, self._creds.subscription_id)
            count = 0
            for cluster in aks_client.managed_clusters.list():
                host = Host(
                    tenant_id=self.tenant_id,
                    ip="",
                    hostname=cluster.name or "",
                    cloud_provider=CloudProvider.AZURE,
                    cloud_instance_id=cluster.id or "",
                    cloud_region=cluster.location or "",
                    criticality=Criticality.HIGH,
                    tags=["aks", "kubernetes"],
                )
                result.hosts.append(host)
                cluster_id = cluster.id or cluster.name or ""
                self._host_cloud_to_uuid[cluster_id] = host.id

                # Track VNet for edges
                if cluster.agent_pool_profiles:
                    for pool in cluster.agent_pool_profiles:
                        if pool.vnet_subnet_id:
                            # vnet_subnet_id is a full resource ID for the subnet
                            # Extract VNet ID (everything before /subnets/)
                            parts = pool.vnet_subnet_id.split("/subnets/")
                            if len(parts) == 2:
                                self._aks_vnet[cluster_id] = parts[0]
                            break
                count += 1
            session.add_action(
                "discover_aks", f"Found {count} AKS clusters", success=True
            )
        except ImportError:
            msg = (
                "azure-mgmt-containerservice not installed"
                " — install with sentinel-connectors[azure]"
            )
            result.errors.append(msg)
            session.add_action("discover_aks", msg, success=False)
        except Exception as exc:
            result.errors.append(f"AKS: {exc}")
            session.add_action("discover_aks", str(exc), success=False)

    # ── Edge creation ─────────────────────────────────────────────

    async def _create_edges(self, result: SyncResult, session: EngramSession) -> None:
        """Build graph edges from cloud-ID relationships tracked during discovery."""
        try:
            # Subnet → VNet (BELONGS_TO_VPC)
            for subnet_id, vnet_id in self._subnet_vnet.items():
                subnet_uuid = self._subnet_cloud_to_uuid.get(subnet_id)
                vpc_uuid = self._vpc_cloud_to_uuid.get(vnet_id)
                if subnet_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(subnet_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            # AKS → VNet (BELONGS_TO_VPC)
            for cluster_id, vnet_id in self._aks_vnet.items():
                host_uuid = self._host_cloud_to_uuid.get(cluster_id)
                vpc_uuid = self._vpc_cloud_to_uuid.get(vnet_id)
                if host_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(host_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            # User → Group (MEMBER_OF)
            for group_id, member_ids in self._group_members.items():
                group_uuid = self._group_cloud_to_uuid.get(group_id)
                if not group_uuid:
                    continue
                for member_id in member_ids:
                    user_uuid = self._user_cloud_to_uuid.get(member_id)
                    if user_uuid:
                        result.edges.append(
                            self._make_edge(user_uuid, group_uuid, EdgeType.MEMBER_OF)
                        )

            session.add_action(
                "create_edges", f"Created {len(result.edges)} edges", success=True
            )
        except Exception as exc:
            result.errors.append(f"Edges: {exc}")
            session.add_action("create_edges", str(exc), success=False)
