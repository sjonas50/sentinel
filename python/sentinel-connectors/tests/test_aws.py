"""AWS connector integration tests using moto mocks."""

from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import boto3
from moto import mock_aws
from sentinel_connectors.cloud.aws import AwsConnector


def _set_aws_env() -> None:
    """Set fake AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


def _seed_ec2() -> None:
    """Create mock EC2 resources."""
    ec2 = boto3.client("ec2", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "test-vpc"}])

    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    sg = ec2.create_security_group(
        GroupName="test-sg", Description="Test SG", VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    ec2.run_instances(
        ImageId="ami-12345678",
        InstanceType="t2.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "web-server"}],
        }],
    )


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
