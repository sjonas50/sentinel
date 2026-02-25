"""Core domain types for the Sentinel knowledge graph.

These Pydantic models mirror the Rust types in sentinel-core/src/types.rs.
Keep them in sync when modifying either side.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREM = "onprem"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    DNS = "dns"


class ServiceState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class UserType(str, Enum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    SYSTEM = "system"


class IdentitySource(str, Enum):
    ENTRA_ID = "entra_id"
    OKTA = "okta"
    AWS_IAM = "aws_iam"
    AZURE_RBAC = "azure_rbac"
    GCP_IAM = "gcp_iam"
    LOCAL = "local"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class PolicyType(str, Enum):
    IAM_POLICY = "iam_policy"
    FIREWALL_RULE = "firewall_rule"
    SECURITY_GROUP = "security_group"
    CONDITIONAL_ACCESS = "conditional_access"
    NETWORK_ACL = "network_acl"


class AppType(str, Enum):
    WEB_APP = "web_app"
    CONTAINER_IMAGE = "container_image"
    LAMBDA = "lambda"
    DAEMON = "daemon"
    DATABASE = "database"


class EdgeType(str, Enum):
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
    BELONGS_TO_SUBNET = "BELONGS_TO_SUBNET"
    BELONGS_TO_VPC = "BELONGS_TO_VPC"


# ── Node Types ─────────────────────────────────────────────────────


class Host(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    mac_address: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    cloud_instance_id: Optional[str] = None
    cloud_region: Optional[str] = None
    criticality: Criticality = Criticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Service(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    version: Optional[str] = None
    port: int
    protocol: Protocol = Protocol.TCP
    state: ServiceState = ServiceState.UNKNOWN
    banner: Optional[str] = None
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
    display_name: Optional[str] = None
    email: Optional[str] = None
    user_type: UserType = UserType.HUMAN
    source: IdentitySource = IdentitySource.LOCAL
    enabled: bool = True
    mfa_enabled: Optional[bool] = None
    last_login: Optional[datetime] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Group(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    description: Optional[str] = None
    source: IdentitySource = IdentitySource.LOCAL
    member_count: Optional[int] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Role(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    description: Optional[str] = None
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
    rules_json: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Subnet(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    cidr: str
    name: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    vpc_id: Optional[str] = None
    is_public: bool = False
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Vpc(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    vpc_id: str
    name: Optional[str] = None
    cidr: Optional[str] = None
    cloud_provider: CloudProvider
    region: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Vulnerability(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    severity: VulnSeverity = VulnSeverity.NONE
    description: Optional[str] = None
    exploitable: bool = False
    in_cisa_kev: bool = False
    published_date: Optional[datetime] = None
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
    version: Optional[str] = None
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


# ── Discriminated union for all node types ─────────────────────────

Node = Annotated[
    Union[
        Host,
        Service,
        Port,
        User,
        Group,
        Role,
        Policy,
        Subnet,
        Vpc,
        Vulnerability,
        Certificate,
        Application,
        McpServer,
    ],
    Field(discriminator=None),
]


# ── Edge Types ─────────────────────────────────────────────────────


class EdgeProperties(BaseModel):
    protocol: Optional[Protocol] = None
    port: Optional[int] = None
    encrypted: Optional[bool] = None
    permissions: list[str] = Field(default_factory=list)
    exploitability_score: Optional[float] = None
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
    technique: Optional[str] = None
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
