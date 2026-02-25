"""Tests for credential management."""

from __future__ import annotations

import os

from sentinel_connectors.credentials import AwsCredentials, AzureCredentials


def test_aws_credentials_from_env() -> None:
    orig = {k: os.environ.pop(k, None) for k in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_SESSION_TOKEN",
    )}
    try:
        os.environ["AWS_ACCESS_KEY_ID"] = "AKIATEST"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret123"
        os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
        creds = AwsCredentials.from_env()
        assert creds.access_key_id == "AKIATEST"
        assert creds.secret_access_key == "secret123"
        assert creds.region == "eu-west-1"
        assert creds.session_token is None
    finally:
        for k, v in orig.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)


def test_aws_credentials_defaults() -> None:
    orig = {k: os.environ.pop(k, None) for k in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION",
    )}
    try:
        creds = AwsCredentials.from_env()
        assert creds.access_key_id == ""
        assert creds.region == "us-east-1"
    finally:
        for k, v in orig.items():
            if v is not None:
                os.environ[k] = v


def test_azure_credentials_from_env() -> None:
    orig = {k: os.environ.pop(k, None) for k in (
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID",
    )}
    try:
        os.environ["AZURE_TENANT_ID"] = "tid-123"
        os.environ["AZURE_CLIENT_ID"] = "cid-456"
        os.environ["AZURE_CLIENT_SECRET"] = "secret"
        os.environ["AZURE_SUBSCRIPTION_ID"] = "sub-789"
        creds = AzureCredentials.from_env()
        assert creds.tenant_id == "tid-123"
        assert creds.client_id == "cid-456"
        assert creds.subscription_id == "sub-789"
    finally:
        for k, v in orig.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
