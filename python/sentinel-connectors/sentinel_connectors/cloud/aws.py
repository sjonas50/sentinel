"""AWS connector — discovers EC2, VPC, IAM, S3, and security groups."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import boto3
from sentinel_api.models.core import (
    CloudProvider,
    Criticality,
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
from sentinel_connectors.credentials import AwsCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter, with_retry

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class AwsConnector(BaseConnector):
    """Discover AWS assets: EC2 instances, VPCs, subnets, IAM users/roles, security groups."""

    NAME = "aws"

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        super().__init__(tenant_id, config)
        creds = AwsCredentials.from_env()
        self._region = config.get("region", creds.region) if config else creds.region
        self._session = boto3.Session(
            aws_access_key_id=creds.access_key_id or None,
            aws_secret_access_key=creds.secret_access_key or None,
            aws_session_token=creds.session_token,
            region_name=self._region,
        )
        self._limiter = RateLimiter(calls_per_second=5.0)

    @property
    def name(self) -> str:
        return "aws"

    async def health_check(self) -> bool:
        """Verify AWS credentials via STS GetCallerIdentity."""
        try:
            sts = self._session.client("sts")
            await with_retry(self._call_sync, sts.get_caller_identity, max_attempts=2)
            return True
        except Exception:
            logger.warning("AWS health check failed")
            return False

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover all AWS assets."""
        result = SyncResult(connector_name=self.name)

        session.add_decision("full_discovery", "Discovering all supported AWS resource types", 1.0)

        await self._discover_vpcs(result, session)
        await self._discover_subnets(result, session)
        await self._discover_instances(result, session)
        await self._discover_security_groups(result, session)
        await self._discover_iam_users(result, session)
        await self._discover_iam_roles(result, session)

        return result

    async def _call_sync(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Call a synchronous boto3 function with rate limiting."""
        await self._limiter.acquire()
        return fn(*args, **kwargs)

    async def _discover_instances(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ec2 = self._session.client("ec2")
            resp = await with_retry(self._call_sync, ec2.describe_instances)
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    host = Host(
                        tenant_id=self.tenant_id,
                        ip=inst.get("PrivateIpAddress", ""),
                        hostname=tags.get("Name", inst.get("InstanceId", "")),
                        os=inst.get("Platform", "linux"),
                        cloud_provider=CloudProvider.AWS,
                        cloud_instance_id=inst["InstanceId"],
                        cloud_region=self._region,
                        criticality=Criticality.MEDIUM,
                        tags=list(tags.keys()),
                    )
                    result.hosts.append(host)
            session.add_action("discover_ec2", f"Found {len(result.hosts)} instances", success=True)
        except Exception as exc:
            result.errors.append(f"EC2: {exc}")
            session.add_action("discover_ec2", str(exc), success=False)

    async def _discover_vpcs(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ec2 = self._session.client("ec2")
            resp = await with_retry(self._call_sync, ec2.describe_vpcs)
            for v in resp.get("Vpcs", []):
                tags = {t["Key"]: t["Value"] for t in v.get("Tags", [])}
                vpc = Vpc(
                    tenant_id=self.tenant_id,
                    vpc_id=v["VpcId"],
                    name=tags.get("Name"),
                    cidr=v.get("CidrBlock"),
                    cloud_provider=CloudProvider.AWS,
                    region=self._region,
                )
                result.vpcs.append(vpc)
            session.add_action("discover_vpcs", f"Found {len(result.vpcs)} VPCs", success=True)
        except Exception as exc:
            result.errors.append(f"VPC: {exc}")
            session.add_action("discover_vpcs", str(exc), success=False)

    async def _discover_subnets(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ec2 = self._session.client("ec2")
            resp = await with_retry(self._call_sync, ec2.describe_subnets)
            for s in resp.get("Subnets", []):
                tags = {t["Key"]: t["Value"] for t in s.get("Tags", [])}
                subnet = Subnet(
                    tenant_id=self.tenant_id,
                    cidr=s["CidrBlock"],
                    name=tags.get("Name"),
                    cloud_provider=CloudProvider.AWS,
                    vpc_id=s.get("VpcId"),
                    is_public=s.get("MapPublicIpOnLaunch", False),
                )
                result.subnets.append(subnet)
            session.add_action(
                "discover_subnets", f"Found {len(result.subnets)} subnets", success=True
            )
        except Exception as exc:
            result.errors.append(f"Subnets: {exc}")
            session.add_action("discover_subnets", str(exc), success=False)

    async def _discover_security_groups(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ec2 = self._session.client("ec2")
            resp = await with_retry(self._call_sync, ec2.describe_security_groups)
            count = 0
            for sg in resp.get("SecurityGroups", []):
                policy = Policy(
                    tenant_id=self.tenant_id,
                    name=sg.get("GroupName", sg["GroupId"]),
                    policy_type=PolicyType.SECURITY_GROUP,
                    source="aws",
                    rules_json=str(sg.get("IpPermissions", [])),
                )
                result.policies.append(policy)
                count += 1
            session.add_action(
                "discover_security_groups", f"Found {count} security groups", success=True
            )
        except Exception as exc:
            result.errors.append(f"SecurityGroups: {exc}")
            session.add_action("discover_security_groups", str(exc), success=False)

    async def _discover_iam_users(self, result: SyncResult, session: EngramSession) -> None:
        try:
            iam = self._session.client("iam")
            resp = await with_retry(self._call_sync, iam.list_users)
            for u in resp.get("Users", []):
                user = User(
                    tenant_id=self.tenant_id,
                    username=u["UserName"],
                    display_name=u.get("Path", ""),
                    user_type=UserType.HUMAN,
                    source=IdentitySource.AWS_IAM,
                )
                result.users.append(user)
            session.add_action(
                "discover_iam_users", f"Found {len(result.users)} IAM users", success=True
            )
        except Exception as exc:
            result.errors.append(f"IAM Users: {exc}")
            session.add_action("discover_iam_users", str(exc), success=False)

    async def _discover_iam_roles(self, result: SyncResult, session: EngramSession) -> None:
        try:
            iam = self._session.client("iam")
            resp = await with_retry(self._call_sync, iam.list_roles)
            for r in resp.get("Roles", []):
                role = Role(
                    tenant_id=self.tenant_id,
                    name=r["RoleName"],
                    description=r.get("Description"),
                    source=IdentitySource.AWS_IAM,
                    permissions=[],
                )
                result.roles.append(role)
            session.add_action(
                "discover_iam_roles", f"Found {len(result.roles)} IAM roles", success=True
            )
        except Exception as exc:
            result.errors.append(f"IAM Roles: {exc}")
            session.add_action("discover_iam_roles", str(exc), success=False)
