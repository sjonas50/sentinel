"""Azure connector — discovers VMs, NSGs, Entra ID users/groups, subscriptions.

Requires azure-identity, azure-mgmt-compute, azure-mgmt-network, and msgraph-sdk.
These are optional dependencies: install with `pip install sentinel-connectors[azure]`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_api.models.core import (
    CloudProvider,
    Criticality,
    Host,
    IdentitySource,
    Policy,
    PolicyType,
    User,
    UserType,
    Vpc,
)

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.credentials import AzureCredentials
from sentinel_connectors.registry import register

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class AzureConnector(BaseConnector):
    """Discover Azure assets: VMs, NSGs, VNets, Entra ID users/groups.

    This is a framework implementation. The actual Azure SDK calls are
    stubbed — full implementation requires the azure optional dependencies.
    """

    NAME = "azure"

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        super().__init__(tenant_id, config)
        self._creds = AzureCredentials.from_env()

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

        await self._discover_vms(result, session)
        await self._discover_vnets(result, session)
        await self._discover_nsgs(result, session)
        await self._discover_users(result, session)

        return result

    async def _discover_vms(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure VMs via azure-mgmt-compute."""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.compute import ComputeManagementClient

            credential = ClientSecretCredential(
                tenant_id=self._creds.tenant_id,
                client_id=self._creds.client_id,
                client_secret=self._creds.client_secret,
            )
            compute = ComputeManagementClient(credential, self._creds.subscription_id)

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
            session.add_action("discover_vms", f"Found {len(result.hosts)} VMs", success=True)
        except ImportError:
            msg = "Azure SDK not installed — install with sentinel-connectors[azure]"
            result.errors.append(msg)
            session.add_action("discover_vms", msg, success=False)
        except Exception as exc:
            result.errors.append(f"VMs: {exc}")
            session.add_action("discover_vms", str(exc), success=False)

    async def _discover_vnets(self, result: SyncResult, session: EngramSession) -> None:
        """Discover Azure VNets via azure-mgmt-network."""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.network import NetworkManagementClient

            credential = ClientSecretCredential(
                tenant_id=self._creds.tenant_id,
                client_id=self._creds.client_id,
                client_secret=self._creds.client_secret,
            )
            network = NetworkManagementClient(credential, self._creds.subscription_id)

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
            session.add_action("discover_vnets", f"Found {len(result.vpcs)} VNets", success=True)
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
            from azure.identity import ClientSecretCredential
            from azure.mgmt.network import NetworkManagementClient

            credential = ClientSecretCredential(
                tenant_id=self._creds.tenant_id,
                client_id=self._creds.client_id,
                client_secret=self._creds.client_secret,
            )
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
            from azure.identity import ClientSecretCredential
            from msgraph import GraphServiceClient

            credential = ClientSecretCredential(
                tenant_id=self._creds.tenant_id,
                client_id=self._creds.client_id,
                client_secret=self._creds.client_secret,
            )
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
