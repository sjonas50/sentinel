"""AWS connector — discovers EC2, VPC, IAM, S3, RDS, Lambda, ECS, EKS, and security groups."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import boto3
from sentinel_api.models.core import (
    Application,
    AppType,
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
from sentinel_connectors.credentials import AwsCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter, with_retry

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class AwsConnector(BaseConnector):
    """Discover AWS assets: EC2, VPCs, subnets, IAM, S3, RDS, Lambda, ECS, EKS, security groups."""

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

        # Cloud-ID → Sentinel UUID mappings for edge creation
        self._vpc_cloud_to_uuid: dict[str, UUID] = {}
        self._subnet_cloud_to_uuid: dict[str, UUID] = {}
        self._host_cloud_to_uuid: dict[str, UUID] = {}
        self._policy_cloud_to_uuid: dict[str, UUID] = {}
        self._user_name_to_uuid: dict[str, UUID] = {}
        self._role_name_to_uuid: dict[str, UUID] = {}

        # Relationship tracking
        self._instance_subnet: dict[str, str] = {}  # instance_id → subnet_id
        self._instance_sgs: dict[str, list[str]] = {}  # instance_id → [sg_id]
        self._subnet_vpc: dict[str, str] = {}  # subnet_id → vpc_id
        self._rds_subnet_vpc: dict[str, str] = {}  # rds_id → vpc_id
        self._rds_sgs: dict[str, list[str]] = {}  # rds_id → [sg_id]
        self._lambda_roles: dict[str, str] = {}  # function_name → role_name
        self._eks_vpc: dict[str, str] = {}  # cluster_name → vpc_id
        self._eks_subnets: dict[str, list[str]] = {}  # cluster_name → [subnet_id]

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
        await self._discover_s3_buckets(result, session)
        await self._discover_rds_instances(result, session)
        await self._discover_lambda_functions(result, session)
        await self._discover_ecs_services(result, session)
        await self._discover_eks_clusters(result, session)
        await self._create_edges(result, session)

        return result

    async def _call_sync(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Call a synchronous boto3 function with rate limiting."""
        await self._limiter.acquire()
        return fn(*args, **kwargs)

    # ── Discovery methods ─────────────────────────────────────────

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
                self._vpc_cloud_to_uuid[v["VpcId"]] = vpc.id
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
                self._subnet_cloud_to_uuid[s["SubnetId"]] = subnet.id
                if vpc_id := s.get("VpcId"):
                    self._subnet_vpc[s["SubnetId"]] = vpc_id
            session.add_action(
                "discover_subnets", f"Found {len(result.subnets)} subnets", success=True
            )
        except Exception as exc:
            result.errors.append(f"Subnets: {exc}")
            session.add_action("discover_subnets", str(exc), success=False)

    async def _discover_instances(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ec2 = self._session.client("ec2")
            resp = await with_retry(self._call_sync, ec2.describe_instances)
            count = 0
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    instance_id = inst["InstanceId"]
                    host = Host(
                        tenant_id=self.tenant_id,
                        ip=inst.get("PrivateIpAddress", ""),
                        hostname=tags.get("Name", instance_id),
                        os=inst.get("Platform", "linux"),
                        cloud_provider=CloudProvider.AWS,
                        cloud_instance_id=instance_id,
                        cloud_region=self._region,
                        criticality=Criticality.MEDIUM,
                        tags=list(tags.keys()),
                    )
                    result.hosts.append(host)
                    self._host_cloud_to_uuid[instance_id] = host.id
                    if subnet_id := inst.get("SubnetId"):
                        self._instance_subnet[instance_id] = subnet_id
                    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    if sg_ids:
                        self._instance_sgs[instance_id] = sg_ids
                    count += 1
            session.add_action("discover_ec2", f"Found {count} instances", success=True)
        except Exception as exc:
            result.errors.append(f"EC2: {exc}")
            session.add_action("discover_ec2", str(exc), success=False)

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
                self._policy_cloud_to_uuid[sg["GroupId"]] = policy.id
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
                self._user_name_to_uuid[u["UserName"]] = user.id
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
                self._role_name_to_uuid[r["RoleName"]] = role.id
            session.add_action(
                "discover_iam_roles", f"Found {len(result.roles)} IAM roles", success=True
            )
        except Exception as exc:
            result.errors.append(f"IAM Roles: {exc}")
            session.add_action("discover_iam_roles", str(exc), success=False)

    async def _discover_s3_buckets(self, result: SyncResult, session: EngramSession) -> None:
        try:
            s3 = self._session.client("s3")
            resp = await with_retry(self._call_sync, s3.list_buckets)
            count = 0
            for b in resp.get("Buckets", []):
                app = Application(
                    tenant_id=self.tenant_id,
                    name=b["Name"],
                    app_type=AppType.DATABASE,
                )
                result.applications.append(app)
                count += 1
            session.add_action("discover_s3", f"Found {count} S3 buckets", success=True)
        except Exception as exc:
            result.errors.append(f"S3: {exc}")
            session.add_action("discover_s3", str(exc), success=False)

    async def _discover_rds_instances(self, result: SyncResult, session: EngramSession) -> None:
        try:
            rds = self._session.client("rds")
            resp = await with_retry(self._call_sync, rds.describe_db_instances)
            count = 0
            for db in resp.get("DBInstances", []):
                endpoint = db.get("Endpoint", {})
                port = endpoint.get("Port", 5432)
                svc = Service(
                    tenant_id=self.tenant_id,
                    name=db["DBInstanceIdentifier"],
                    port=port,
                    protocol=Protocol.TCP,
                    state=(
                        ServiceState.RUNNING
                        if db.get("DBInstanceStatus") == "available"
                        else ServiceState.STOPPED
                    ),
                )
                result.services.append(svc)
                # Track VPC and security groups for edges
                subnet_group = db.get("DBSubnetGroup", {})
                if vpc_id := subnet_group.get("VpcId"):
                    self._rds_subnet_vpc[db["DBInstanceIdentifier"]] = vpc_id
                sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
                if sg_ids:
                    self._rds_sgs[db["DBInstanceIdentifier"]] = sg_ids
                count += 1
            session.add_action("discover_rds", f"Found {count} RDS instances", success=True)
        except Exception as exc:
            result.errors.append(f"RDS: {exc}")
            session.add_action("discover_rds", str(exc), success=False)

    async def _discover_lambda_functions(self, result: SyncResult, session: EngramSession) -> None:
        try:
            lamb = self._session.client("lambda")
            resp = await with_retry(self._call_sync, lamb.list_functions)
            count = 0
            for fn in resp.get("Functions", []):
                app = Application(
                    tenant_id=self.tenant_id,
                    name=fn["FunctionName"],
                    app_type=AppType.LAMBDA,
                    version=fn.get("Runtime"),
                )
                result.applications.append(app)
                # Track role for IAM edges
                role_arn = fn.get("Role", "")
                if role_arn:
                    role_name = role_arn.rsplit("/", 1)[-1]
                    self._lambda_roles[fn["FunctionName"]] = role_name
                count += 1
            session.add_action("discover_lambda", f"Found {count} Lambda functions", success=True)
        except Exception as exc:
            result.errors.append(f"Lambda: {exc}")
            session.add_action("discover_lambda", str(exc), success=False)

    async def _discover_ecs_services(self, result: SyncResult, session: EngramSession) -> None:
        try:
            ecs = self._session.client("ecs")
            clusters_resp = await with_retry(self._call_sync, ecs.list_clusters)
            count = 0
            for cluster_arn in clusters_resp.get("clusterArns", []):
                cluster_name = cluster_arn.rsplit("/", 1)[-1]
                services_resp = await with_retry(
                    self._call_sync, ecs.list_services, cluster=cluster_arn
                )
                for svc_arn in services_resp.get("serviceArns", []):
                    svc_name = svc_arn.rsplit("/", 1)[-1]
                    app = Application(
                        tenant_id=self.tenant_id,
                        name=svc_name,
                        app_type=AppType.CONTAINER_IMAGE,
                        version=cluster_name,
                    )
                    result.applications.append(app)
                    count += 1
            session.add_action("discover_ecs", f"Found {count} ECS services", success=True)
        except Exception as exc:
            result.errors.append(f"ECS: {exc}")
            session.add_action("discover_ecs", str(exc), success=False)

    async def _discover_eks_clusters(self, result: SyncResult, session: EngramSession) -> None:
        try:
            eks = self._session.client("eks")
            clusters_resp = await with_retry(self._call_sync, eks.list_clusters)
            count = 0
            for cluster_name in clusters_resp.get("clusters", []):
                detail = await with_retry(self._call_sync, eks.describe_cluster, name=cluster_name)
                cluster = detail.get("cluster", {})
                vpc_config = cluster.get("resourcesVpcConfig", {})
                host = Host(
                    tenant_id=self.tenant_id,
                    ip=cluster.get("endpoint", ""),
                    hostname=cluster_name,
                    cloud_provider=CloudProvider.AWS,
                    cloud_instance_id=cluster.get("arn", ""),
                    cloud_region=self._region,
                    criticality=Criticality.HIGH,
                    tags=["eks", "kubernetes"],
                )
                result.hosts.append(host)
                self._host_cloud_to_uuid[f"eks:{cluster_name}"] = host.id
                if vpc_id := vpc_config.get("vpcId"):
                    self._eks_vpc[cluster_name] = vpc_id
                if subnet_ids := vpc_config.get("subnetIds"):
                    self._eks_subnets[cluster_name] = subnet_ids
                count += 1
            session.add_action("discover_eks", f"Found {count} EKS clusters", success=True)
        except Exception as exc:
            result.errors.append(f"EKS: {exc}")
            session.add_action("discover_eks", str(exc), success=False)

    # ── Edge creation ─────────────────────────────────────────────

    async def _create_edges(self, result: SyncResult, session: EngramSession) -> None:
        """Build graph edges from the cloud-ID relationships tracked during discovery."""
        try:
            # Instance → Subnet (BELONGS_TO_SUBNET)
            for instance_id, subnet_id in self._instance_subnet.items():
                host_uuid = self._host_cloud_to_uuid.get(instance_id)
                subnet_uuid = self._subnet_cloud_to_uuid.get(subnet_id)
                if host_uuid and subnet_uuid:
                    result.edges.append(
                        self._make_edge(host_uuid, subnet_uuid, EdgeType.BELONGS_TO_SUBNET)
                    )

            # Subnet → VPC (BELONGS_TO_VPC)
            for subnet_id, vpc_id in self._subnet_vpc.items():
                subnet_uuid = self._subnet_cloud_to_uuid.get(subnet_id)
                vpc_uuid = self._vpc_cloud_to_uuid.get(vpc_id)
                if subnet_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(subnet_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            # SecurityGroup → Instance (EXPOSES)
            for instance_id, sg_ids in self._instance_sgs.items():
                host_uuid = self._host_cloud_to_uuid.get(instance_id)
                if not host_uuid:
                    continue
                for sg_id in sg_ids:
                    policy_uuid = self._policy_cloud_to_uuid.get(sg_id)
                    if policy_uuid:
                        result.edges.append(
                            self._make_edge(policy_uuid, host_uuid, EdgeType.EXPOSES)
                        )

            # EKS → VPC (BELONGS_TO_VPC)
            for cluster_name, vpc_id in self._eks_vpc.items():
                host_uuid = self._host_cloud_to_uuid.get(f"eks:{cluster_name}")
                vpc_uuid = self._vpc_cloud_to_uuid.get(vpc_id)
                if host_uuid and vpc_uuid:
                    result.edges.append(
                        self._make_edge(host_uuid, vpc_uuid, EdgeType.BELONGS_TO_VPC)
                    )

            # EKS → Subnets (BELONGS_TO_SUBNET)
            for cluster_name, subnet_ids in self._eks_subnets.items():
                host_uuid = self._host_cloud_to_uuid.get(f"eks:{cluster_name}")
                if not host_uuid:
                    continue
                for subnet_id in subnet_ids:
                    subnet_uuid = self._subnet_cloud_to_uuid.get(subnet_id)
                    if subnet_uuid:
                        result.edges.append(
                            self._make_edge(host_uuid, subnet_uuid, EdgeType.BELONGS_TO_SUBNET)
                        )

            session.add_action("create_edges", f"Created {len(result.edges)} edges", success=True)
        except Exception as exc:
            result.errors.append(f"Edges: {exc}")
            session.add_action("create_edges", str(exc), success=False)
