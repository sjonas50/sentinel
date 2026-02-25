"""Core domain types for the Sentinel knowledge graph.

These Pydantic models mirror the Rust types in sentinel-core/src/types.rs.
Keep them in sync when modifying either side.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

# ── Enums ──────────────────────────────────────────────────────────


class CloudProvider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREM = "onprem"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    DNS = "dns"


class ServiceState(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class UserType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    SYSTEM = "system"


class IdentitySource(StrEnum):
    ENTRA_ID = "entra_id"
    OKTA = "okta"
    AWS_IAM = "aws_iam"
    AZURE_RBAC = "azure_rbac"
    GCP_IAM = "gcp_iam"
    LOCAL = "local"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class PolicyType(StrEnum):
    IAM_POLICY = "iam_policy"
    FIREWALL_RULE = "firewall_rule"
    SECURITY_GROUP = "security_group"
    CONDITIONAL_ACCESS = "conditional_access"
    NETWORK_ACL = "network_acl"


class AppType(StrEnum):
    WEB_APP = "web_app"
    CONTAINER_IMAGE = "container_image"
    LAMBDA = "lambda"
    DAEMON = "daemon"
    DATABASE = "database"


class EdgeType(StrEnum):
    CONNECTS_TO = "CONNECTS_TO"
    HAS_ACCESS = "HAS_ACCESS"
    MEMBER_OF = "MEMBER_OF"
    RUNS_ON = "RUNS_ON"
    TRUSTS = "TRUSTS"
    ROUTES_TO = "ROUTES_TO"
    EXPOSES = "EXPOSES"
    DEPENDS_ON = "DEPENDS_ON"
    CAN_REACH = "CAN_REACH"
    HAS_CVE = "HAS_CVE"
    HAS_PORT = "HAS_PORT"
    HAS_CERTIFICATE = "HAS_CERTIFICATE"
    HAS_FINDING = "HAS_FINDING"
    BELONGS_TO_SUBNET = "BELONGS_TO_SUBNET"
    BELONGS_TO_VPC = "BELONGS_TO_VPC"


# ── Node Types ─────────────────────────────────────────────────────


class Host(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    ip: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    mac_address: str | None = None
    cloud_provider: CloudProvider | None = None
    cloud_instance_id: str | None = None
    cloud_region: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Service(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    version: str | None = None
    port: int
    protocol: Protocol = Protocol.TCP
    state: ServiceState = ServiceState.UNKNOWN
    banner: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Port(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    number: int
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    username: str
    display_name: str | None = None
    email: str | None = None
    user_type: UserType = UserType.HUMAN
    source: IdentitySource = IdentitySource.LOCAL
    enabled: bool = True
    mfa_enabled: bool | None = None
    last_login: datetime | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Group(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    description: str | None = None
    source: IdentitySource = IdentitySource.LOCAL
    member_count: int | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Role(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    description: str | None = None
    source: IdentitySource = IdentitySource.LOCAL
    permissions: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Policy(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    policy_type: PolicyType
    source: str
    rules_json: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Subnet(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    cidr: str
    name: str | None = None
    cloud_provider: CloudProvider | None = None
    vpc_id: str | None = None
    is_public: bool = False
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Vpc(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    vpc_id: str
    name: str | None = None
    cidr: str | None = None
    cloud_provider: CloudProvider
    region: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Vulnerability(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    cve_id: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    severity: VulnSeverity = VulnSeverity.NONE
    description: str | None = None
    exploitable: bool = False
    in_cisa_kev: bool = False
    published_date: datetime | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Certificate(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Application(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    version: str | None = None
    app_type: AppType
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class McpServer(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    endpoint: str
    tools: list[str] = Field(default_factory=list)
    authenticated: bool = False
    tls_enabled: bool = False
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    resource_id: str
    resource_type: str
    remediation: str | None = None
    details_json: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    found_at: datetime = Field(default_factory=datetime.utcnow)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


# ── Discriminated union for all node types ─────────────────────────

Node = Annotated[
    Host
    | Service
    | Port
    | User
    | Group
    | Role
    | Policy
    | Subnet
    | Vpc
    | Vulnerability
    | Certificate
    | Application
    | McpServer
    | Finding,
    Field(discriminator=None),
]


# ── Edge Types ─────────────────────────────────────────────────────


class EdgeProperties(BaseModel):
    protocol: Protocol | None = None
    port: int | None = None
    encrypted: bool | None = None
    permissions: list[str] = Field(default_factory=list)
    exploitability_score: float | None = None
    extra: dict[str, object] = Field(default_factory=dict)


class Edge(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    source_id: UUID
    target_id: UUID
    edge_type: EdgeType
    properties: EdgeProperties = Field(default_factory=EdgeProperties)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


# ── Attack Path Types ──────────────────────────────────────────────


class AttackStep(BaseModel):
    node_id: UUID
    edge_id: UUID
    technique: str | None = None
    description: str
    exploitability: float


class AttackPath(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    steps: list[AttackStep]
    risk_score: float
    source_node: UUID
    target_node: UUID
    computed_at: datetime = Field(default_factory=datetime.utcnow)
