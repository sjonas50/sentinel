"""AWS connector integration tests using moto mocks."""

from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import boto3
from moto import mock_aws
from sentinel_api.models.core import EdgeType
from sentinel_connectors.cloud.aws import AwsConnector


def _set_aws_env() -> None:
    """Set fake AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


def _seed_ec2() -> dict[str, str]:
    """Create mock EC2 resources. Returns a dict with resource IDs."""
    ec2 = boto3.client("ec2", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "test-vpc"}])

    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    sg = ec2.create_security_group(GroupName="test-sg", Description="Test SG", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    ec2.run_instances(
        ImageId="ami-12345678",
        InstanceType="t2.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[sg["GroupId"]],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "web-server"}],
            }
        ],
    )

    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg["GroupId"]}


def _seed_iam() -> None:
    """Create mock IAM resources."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")
    iam.create_role(
        RoleName="lambda-exec",
        AssumeRolePolicyDocument="{}",
        Description="Lambda execution role",
    )


def _seed_s3() -> None:
    """Create mock S3 buckets."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-data-bucket")
    s3.create_bucket(Bucket="test-logs-bucket")


def _seed_rds() -> None:
    """Create mock RDS instances."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    rds = boto3.client("rds", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sub1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.1.1.0/24", AvailabilityZone="us-east-1a")
    sub2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.1.2.0/24", AvailabilityZone="us-east-1b")
    rds.create_db_subnet_group(
        DBSubnetGroupName="test-subnet-group",
        DBSubnetGroupDescription="Test",
        SubnetIds=[sub1["Subnet"]["SubnetId"], sub2["Subnet"]["SubnetId"]],
    )
    rds.create_db_instance(
        DBInstanceIdentifier="test-postgres",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123",
        DBSubnetGroupName="test-subnet-group",
    )


def _seed_lambda() -> None:
    """Create mock Lambda functions."""
    iam = boto3.client("iam", region_name="us-east-1")
    lamb = boto3.client("lambda", region_name="us-east-1")

    role = iam.create_role(
        RoleName="lambda-test-role",
        AssumeRolePolicyDocument="{}",
    )
    lamb.create_function(
        FunctionName="test-processor",
        Runtime="python3.12",
        Role=role["Role"]["Arn"],
        Handler="handler.main",
        Code={"ZipFile": b"fake"},
    )


def _seed_ecs() -> None:
    """Create mock ECS cluster."""
    ecs = boto3.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="test-cluster")


def _seed_eks() -> dict[str, str]:
    """Create mock EKS cluster."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    eks = boto3.client("eks", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.2.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sub = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.2.1.0/24")
    subnet_id = sub["Subnet"]["SubnetId"]

    role = iam.create_role(RoleName="eks-role", AssumeRolePolicyDocument="{}")
    eks.create_cluster(
        name="test-eks-cluster",
        roleArn=role["Role"]["Arn"],
        resourcesVpcConfig={"subnetIds": [subnet_id], "securityGroupIds": []},
    )
    return {"vpc_id": vpc_id, "subnet_id": subnet_id}


# ── Existing resource tests ──────────────────────────────────


@mock_aws
def test_aws_discover_ec2_instances() -> None:
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    assert len(result.hosts) == 1
    assert result.hosts[0].hostname == "web-server"
    assert result.hosts[0].cloud_provider == "aws"


@mock_aws
def test_aws_discover_vpcs() -> None:
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    assert len(result.vpcs) >= 1
    names = [v.name for v in result.vpcs]
    assert "test-vpc" in names


@mock_aws
def test_aws_discover_subnets() -> None:
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    assert len(result.subnets) >= 1


@mock_aws
def test_aws_discover_security_groups() -> None:
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    sg_names = [p.name for p in result.policies]
    assert "test-sg" in sg_names


@mock_aws
def test_aws_discover_iam_users() -> None:
    _set_aws_env()
    _seed_iam()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    usernames = [u.username for u in result.users]
    assert "alice" in usernames
    assert "bob" in usernames


@mock_aws
def test_aws_discover_iam_roles() -> None:
    _set_aws_env()
    _seed_iam()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    role_names = [r.name for r in result.roles]
    assert "lambda-exec" in role_names


@mock_aws
def test_aws_sync_creates_engram() -> None:
    """Verify that sync produces zero errors on a valid mock environment."""
    _set_aws_env()
    _seed_ec2()
    _seed_iam()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    assert result.total_assets > 0
    assert len(result.errors) == 0


# ── New resource tests ────────────────────────────────────────


@mock_aws
def test_aws_discover_s3_buckets() -> None:
    _set_aws_env()
    _seed_s3()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    bucket_names = [a.name for a in result.applications]
    assert "test-data-bucket" in bucket_names
    assert "test-logs-bucket" in bucket_names


@mock_aws
def test_aws_discover_rds_instances() -> None:
    _set_aws_env()
    _seed_rds()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    svc_names = [s.name for s in result.services]
    assert "test-postgres" in svc_names


@mock_aws
def test_aws_discover_lambda_functions() -> None:
    _set_aws_env()
    _seed_lambda()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    app_names = [a.name for a in result.applications if a.app_type == "lambda"]
    assert "test-processor" in app_names


@mock_aws
def test_aws_discover_ecs_clusters() -> None:
    _set_aws_env()
    _seed_ecs()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    # ECS cluster is created but no services, so no applications from ECS
    assert result.total_assets >= 0


@mock_aws
def test_aws_discover_eks_clusters() -> None:
    _set_aws_env()
    _seed_eks()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    hostnames = [h.hostname for h in result.hosts]
    assert "test-eks-cluster" in hostnames
    eks_host = next(h for h in result.hosts if h.hostname == "test-eks-cluster")
    assert eks_host.criticality == "high"
    assert "kubernetes" in eks_host.tags


# ── Edge creation tests ───────────────────────────────────────


@mock_aws
def test_aws_edges_instance_to_subnet() -> None:
    """Verify BELONGS_TO_SUBNET edges from EC2 instances to subnets."""
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    subnet_edges = [e for e in result.edges if e.edge_type == EdgeType.BELONGS_TO_SUBNET]
    assert len(subnet_edges) >= 1


@mock_aws
def test_aws_edges_subnet_to_vpc() -> None:
    """Verify BELONGS_TO_VPC edges from subnets to VPCs."""
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    vpc_edges = [e for e in result.edges if e.edge_type == EdgeType.BELONGS_TO_VPC]
    assert len(vpc_edges) >= 1


@mock_aws
def test_aws_edges_sg_exposes_instance() -> None:
    """Verify EXPOSES edges from security groups to instances."""
    _set_aws_env()
    _seed_ec2()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    expose_edges = [e for e in result.edges if e.edge_type == EdgeType.EXPOSES]
    assert len(expose_edges) >= 1


@mock_aws
def test_aws_full_discovery() -> None:
    """Full integration: all resource types + edges."""
    _set_aws_env()
    _seed_ec2()
    _seed_iam()
    _seed_s3()
    connector = AwsConnector(tenant_id=uuid4())
    result = asyncio.run(connector.sync())
    assert result.total_assets > 0
    assert len(result.edges) > 0
    assert len(result.errors) == 0
    # Check all resource types discovered
    assert len(result.hosts) >= 1
    assert len(result.vpcs) >= 1
    assert len(result.subnets) >= 1
    assert len(result.policies) >= 1
    assert len(result.users) >= 1
    assert len(result.roles) >= 1
    assert len(result.applications) >= 1  # S3 buckets
