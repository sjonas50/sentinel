"""Tests for CIS Benchmark rules engine."""

import json

from sentinel_api.services.cis_rules import (
    CisAwsEncryptionAtRest,
    CisAwsIamMfaEnabled,
    CisAwsIamWildcardPolicy,
    CisAwsS3PublicAccess,
    CisAwsSgOpenRdp,
    CisAwsSgOpenSsh,
    CisAwsSgUnrestrictedIngress,
    CloudTarget,
    config_hash,
    get_rule,
    get_rules,
)

# ── Registry tests ─────────────────────────────────────────────


def test_all_rules_registered() -> None:
    rules = get_rules()
    assert len(rules) == 7


def test_filter_by_cloud_aws() -> None:
    rules = get_rules(cloud=CloudTarget.AWS)
    assert len(rules) == 7
    for rule in rules:
        assert rule.metadata.cloud == CloudTarget.AWS


def test_filter_by_resource_type_policy() -> None:
    rules = get_rules(resource_type="Policy")
    rule_ids = {r.metadata.rule_id for r in rules}
    assert "cis-aws-2.0-5.2" in rule_ids
    assert "cis-aws-2.0-5.3" in rule_ids
    assert "cis-aws-2.0-5.4" in rule_ids
    assert "cis-aws-2.0-1.16" in rule_ids


def test_filter_by_resource_type_user() -> None:
    rules = get_rules(resource_type="User")
    assert len(rules) == 1
    assert rules[0].metadata.rule_id == "cis-aws-2.0-1.4"


def test_get_rule_by_id() -> None:
    rule = get_rule("cis-aws-2.0-5.2")
    assert rule is not None
    assert rule.metadata.title.startswith("Security group")


def test_get_rule_missing() -> None:
    assert get_rule("nonexistent") is None


# ── S3 Public Access ───────────────────────────────────────────


def test_s3_public_access_missing_block() -> None:
    rule = CisAwsS3PublicAccess()
    resource = {"id": "app-1", "name": "my-bucket"}
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "my-bucket" in findings[0].description


def test_s3_public_access_with_block() -> None:
    rule = CisAwsS3PublicAccess()
    resource = {
        "id": "app-1",
        "name": "my-bucket",
        "public_access_block": True,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


def test_s3_public_access_empty_name() -> None:
    rule = CisAwsS3PublicAccess()
    resource = {"id": "app-1", "name": ""}
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── SG Open SSH ────────────────────────────────────────────────


def test_sg_open_ssh_violation() -> None:
    rule = CisAwsSgOpenSsh()
    resource = {
        "id": "sg-123",
        "name": "open-sg",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule_id == "cis-aws-2.0-5.2"


def test_sg_open_ssh_restricted_cidr() -> None:
    rule = CisAwsSgOpenSsh()
    resource = {
        "id": "sg-456",
        "name": "restricted-sg",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


def test_sg_open_ssh_wrong_policy_type() -> None:
    rule = CisAwsSgOpenSsh()
    resource = {
        "id": "sg-789",
        "name": "iam",
        "policy_type": "iam_policy",
        "rules_json": "[]",
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── SG Open RDP ────────────────────────────────────────────────


def test_sg_open_rdp_violation() -> None:
    rule = CisAwsSgOpenRdp()
    resource = {
        "id": "sg-rdp",
        "name": "rdp-sg",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_sg_open_rdp_compliant() -> None:
    rule = CisAwsSgOpenRdp()
    resource = {
        "id": "sg-rdp2",
        "name": "good-sg",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── SG Unrestricted Ingress ────────────────────────────────────


def test_sg_unrestricted_all_traffic() -> None:
    rule = CisAwsSgUnrestrictedIngress()
    resource = {
        "id": "sg-all",
        "name": "open-all",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_sg_restricted_all_traffic() -> None:
    rule = CisAwsSgUnrestrictedIngress()
    resource = {
        "id": "sg-all2",
        "name": "internal",
        "policy_type": "security_group",
        "rules_json": json.dumps(
            [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── IAM Wildcard Policy ────────────────────────────────────────


def test_iam_wildcard_action_violation() -> None:
    rule = CisAwsIamWildcardPolicy()
    resource = {
        "id": "pol-1",
        "name": "admin-policy",
        "policy_type": "iam_policy",
        "rules_json": json.dumps(
            [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_iam_specific_action_compliant() -> None:
    rule = CisAwsIamWildcardPolicy()
    resource = {
        "id": "pol-2",
        "name": "s3-read",
        "policy_type": "iam_policy",
        "rules_json": json.dumps(
            [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


def test_iam_wildcard_deny_ignored() -> None:
    rule = CisAwsIamWildcardPolicy()
    resource = {
        "id": "pol-3",
        "name": "deny-all",
        "policy_type": "iam_policy",
        "rules_json": json.dumps(
            [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── IAM MFA ────────────────────────────────────────────────────


def test_iam_mfa_disabled() -> None:
    rule = CisAwsIamMfaEnabled()
    resource = {
        "id": "user-1",
        "username": "alice",
        "source": "aws_iam",
        "mfa_enabled": False,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_iam_mfa_none() -> None:
    rule = CisAwsIamMfaEnabled()
    resource = {
        "id": "user-2",
        "username": "bob",
        "source": "aws_iam",
        "mfa_enabled": None,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1


def test_iam_mfa_enabled() -> None:
    rule = CisAwsIamMfaEnabled()
    resource = {
        "id": "user-3",
        "username": "charlie",
        "source": "aws_iam",
        "mfa_enabled": True,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


def test_iam_mfa_non_aws_user_ignored() -> None:
    rule = CisAwsIamMfaEnabled()
    resource = {
        "id": "user-4",
        "username": "dan",
        "source": "okta",
        "mfa_enabled": False,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── RDS Encryption ─────────────────────────────────────────────


def test_rds_no_encryption() -> None:
    rule = CisAwsEncryptionAtRest()
    resource = {
        "id": "rds-1",
        "name": "my-db",
        "storage_encrypted": False,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_rds_encrypted() -> None:
    rule = CisAwsEncryptionAtRest()
    resource = {
        "id": "rds-2",
        "name": "my-db-enc",
        "storage_encrypted": True,
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 0


def test_rds_encryption_unknown() -> None:
    """No storage_encrypted field should not produce a finding."""
    rule = CisAwsEncryptionAtRest()
    resource = {"id": "rds-3", "name": "my-db-unknown"}
    findings = rule.evaluate(resource)
    assert len(findings) == 0


# ── config_hash ────────────────────────────────────────────────


def test_config_hash_deterministic() -> None:
    data = {"key": "value", "number": 42}
    h1 = config_hash(data)
    h2 = config_hash(data)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_config_hash_order_independent() -> None:
    h1 = config_hash({"a": 1, "b": 2})
    h2 = config_hash({"b": 2, "a": 1})
    assert h1 == h2


def test_config_hash_different_data() -> None:
    h1 = config_hash({"key": "value1"})
    h2 = config_hash({"key": "value2"})
    assert h1 != h2


# ── Parse rules_json ───────────────────────────────────────────


def test_sg_with_python_repr_format() -> None:
    """The AWS connector uses str() which produces Python repr."""
    rule = CisAwsSgOpenSsh()
    resource = {
        "id": "sg-repr",
        "name": "repr-sg",
        "policy_type": "security_group",
        "rules_json": str(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        ),
    }
    findings = rule.evaluate(resource)
    assert len(findings) == 1
