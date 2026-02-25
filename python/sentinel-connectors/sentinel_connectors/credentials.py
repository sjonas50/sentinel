"""Credential management — reads secrets from environment variables.

Never hardcodes credentials. In production, this would integrate with
a secrets manager (Vault, AWS Secrets Manager, etc.).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AwsCredentials:
    """AWS access key credentials."""

    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"
    session_token: str | None = None

    @classmethod
    def from_env(cls) -> AwsCredentials:
        """Load AWS credentials from environment variables."""
        return cls(
            access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", ""),
            secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            session_token=os.environ.get("AWS_SESSION_TOKEN"),
        )


@dataclass(frozen=True)
class AzureCredentials:
    """Azure service principal credentials."""

    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str

    @classmethod
    def from_env(cls) -> AzureCredentials:
        """Load Azure credentials from environment variables."""
        return cls(
            tenant_id=os.environ.get("AZURE_TENANT_ID", ""),
            client_id=os.environ.get("AZURE_CLIENT_ID", ""),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET", ""),
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        )
