"""MITRE ATT&CK technique taxonomy for adversarial simulation.

Defines the top 20 techniques (5 per tactic) with graph query patterns
describing what to look for in the digital twin.
"""

from __future__ import annotations

from pydantic import BaseModel

from sentinel_agents.simulate.models import TacticType

# ── Graph Query Pattern ─────────────────────────────────────────


class GraphQueryPattern(BaseModel):
    """Describes what to query in the graph to test a technique."""

    node_labels: list[str]
    edge_types: list[str]
    required_properties: dict[str, object] = {}
    description: str


# ── MITRE Technique Model ──────────────────────────────────────


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique with graph query metadata."""

    technique_id: str
    technique_name: str
    tactic: TacticType
    description: str
    mitre_url: str
    severity_default: str
    graph_query: GraphQueryPattern


# ── Technique Definitions ──────────────────────────────────────

# --- Initial Access (5) ---

_T1190 = MitreTechnique(
    technique_id="T1190",
    technique_name="Exploit Public-Facing Application",
    tactic=TacticType.INITIAL_ACCESS,
    description=(
        "Adversaries may exploit vulnerabilities in internet-facing "
        "applications to gain initial access."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1190/",
    severity_default="critical",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service", "Vulnerability"],
        edge_types=["RUNS_ON", "HAS_CVE", "EXPOSES"],
        required_properties={"is_internet_facing": True, "exploitable": True},
        description=("Internet-facing Hosts with Services that have exploitable CVEs"),
    ),
)

_T1133 = MitreTechnique(
    technique_id="T1133",
    technique_name="External Remote Services",
    tactic=TacticType.INITIAL_ACCESS,
    description=(
        "Adversaries may leverage external remote services (RDP, SSH, VNC) "
        "as initial access vectors."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1133/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service", "User"],
        edge_types=["EXPOSES", "HAS_ACCESS"],
        required_properties={"is_internet_facing": True},
        description=(
            "Services on remote-access ports (22, 3389, 5900, 5985) on "
            "internet-facing Hosts without MFA"
        ),
    ),
)

_T1566 = MitreTechnique(
    technique_id="T1566",
    technique_name="Phishing",
    tactic=TacticType.INITIAL_ACCESS,
    description=(
        "Adversaries may send phishing messages to gain access to victim "
        "systems via user interaction."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1566/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Host"],
        edge_types=["HAS_ACCESS"],
        required_properties={"mfa_enabled": False},
        description=("Users without MFA who have access to critical systems"),
    ),
)

_T1078 = MitreTechnique(
    technique_id="T1078",
    technique_name="Valid Accounts",
    tactic=TacticType.INITIAL_ACCESS,
    description=(
        "Adversaries may use valid credentials to gain initial access, "
        "including service accounts and stale human accounts."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1078/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Role"],
        edge_types=["HAS_ACCESS", "MEMBER_OF"],
        required_properties={},
        description=("Service accounts with excessive access or stale human accounts"),
    ),
)

_T1199 = MitreTechnique(
    technique_id="T1199",
    technique_name="Trusted Relationship",
    tactic=TacticType.INITIAL_ACCESS,
    description=(
        "Adversaries may exploit trusted third-party relationships to "
        "gain initial access to a target network."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1199/",
    severity_default="medium",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Vpc"],
        edge_types=["TRUSTS"],
        description=("TRUSTS edges across VPCs or cloud boundaries"),
    ),
)

# --- Lateral Movement (5) ---

_T1021_001 = MitreTechnique(
    technique_id="T1021.001",
    technique_name="Remote Desktop Protocol",
    tactic=TacticType.LATERAL_MOVEMENT,
    description=("Adversaries may use RDP to move laterally between internal hosts."),
    mitre_url="https://attack.mitre.org/techniques/T1021/001/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service"],
        edge_types=["HAS_ACCESS", "CAN_REACH"],
        required_properties={"port": 3389},
        description="RDP lateral chains via port 3389",
    ),
)

_T1021_004 = MitreTechnique(
    technique_id="T1021.004",
    technique_name="SSH",
    tactic=TacticType.LATERAL_MOVEMENT,
    description=("Adversaries may use SSH to move laterally between internal hosts."),
    mitre_url="https://attack.mitre.org/techniques/T1021/004/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service"],
        edge_types=["HAS_ACCESS", "CAN_REACH"],
        required_properties={"port": 22},
        description="SSH lateral chains via port 22",
    ),
)

_T1550_002 = MitreTechnique(
    technique_id="T1550.002",
    technique_name="Pass the Hash",
    tactic=TacticType.LATERAL_MOVEMENT,
    description=(
        "Adversaries may use stolen password hashes to authenticate to "
        "systems without knowing the plaintext password."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1550/002/",
    severity_default="critical",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Host"],
        edge_types=["HAS_ACCESS"],
        required_properties={},
        description=("Admin users with HAS_ACCESS to multiple hosts (credential reuse)"),
    ),
)

_T1558 = MitreTechnique(
    technique_id="T1558",
    technique_name="Steal or Forge Kerberos Tickets",
    tactic=TacticType.LATERAL_MOVEMENT,
    description=(
        "Adversaries may steal or forge Kerberos tickets to move laterally within an environment."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1558/",
    severity_default="critical",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Group", "Host"],
        edge_types=["MEMBER_OF", "HAS_ACCESS"],
        description=("Privileged group members with access to domain controllers"),
    ),
)

_T1482 = MitreTechnique(
    technique_id="T1482",
    technique_name="Domain Trust Discovery",
    tactic=TacticType.LATERAL_MOVEMENT,
    description=(
        "Adversaries may enumerate trust relationships between domains "
        "to identify lateral movement opportunities."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1482/",
    severity_default="medium",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Vpc"],
        edge_types=["TRUSTS"],
        description="Transitive TRUSTS chains enabling cross-domain access",
    ),
)

# --- Privilege Escalation (5) ---

_T1068 = MitreTechnique(
    technique_id="T1068",
    technique_name="Exploitation for Privilege Escalation",
    tactic=TacticType.PRIVILEGE_ESCALATION,
    description=(
        "Adversaries may exploit software vulnerabilities to escalate privileges on a system."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1068/",
    severity_default="critical",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service", "Vulnerability"],
        edge_types=["RUNS_ON", "HAS_CVE"],
        required_properties={"exploitable": True},
        description=("Services with high-CVSS exploitable CVEs for privilege escalation"),
    ),
)

_T1078_001 = MitreTechnique(
    technique_id="T1078.001",
    technique_name="Valid Accounts: Default Accounts",
    tactic=TacticType.PRIVILEGE_ESCALATION,
    description=("Adversaries may use default account credentials to escalate privileges."),
    mitre_url="https://attack.mitre.org/techniques/T1078/001/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User"],
        edge_types=["HAS_ACCESS"],
        description=("Users with default names (admin, root, guest, sa) that are enabled"),
    ),
)

_T1548 = MitreTechnique(
    technique_id="T1548",
    technique_name="Abuse Elevation Control Mechanism",
    tactic=TacticType.PRIVILEGE_ESCALATION,
    description=(
        "Adversaries may circumvent elevation controls to gain higher privileges on a system."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1548/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Role"],
        edge_types=["MEMBER_OF"],
        description="Roles with wildcard or overly broad permissions",
    ),
)

_T1134 = MitreTechnique(
    technique_id="T1134",
    technique_name="Access Token Manipulation",
    tactic=TacticType.PRIVILEGE_ESCALATION,
    description=(
        "Adversaries may modify access tokens to operate under a different security context."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1134/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Host"],
        edge_types=["HAS_ACCESS", "TRUSTS"],
        description=("Service accounts accessing many critical hosts with trust edges"),
    ),
)

_T1098 = MitreTechnique(
    technique_id="T1098",
    technique_name="Account Manipulation",
    tactic=TacticType.PRIVILEGE_ESCALATION,
    description=(
        "Adversaries may manipulate accounts to maintain or elevate access to victim systems."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1098/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["User", "Role", "Policy"],
        edge_types=["MEMBER_OF", "HAS_ACCESS"],
        description=("Overly broad roles with identity management access"),
    ),
)

# --- Exfiltration (5) ---

_T1041 = MitreTechnique(
    technique_id="T1041",
    technique_name="Exfiltration Over C2 Channel",
    tactic=TacticType.EXFILTRATION,
    description=("Adversaries may exfiltrate data over an existing command and control channel."),
    mitre_url="https://attack.mitre.org/techniques/T1041/",
    severity_default="critical",
    graph_query=GraphQueryPattern(
        node_labels=["Host"],
        edge_types=["CAN_REACH", "CONNECTS_TO"],
        description=("Paths from crown jewels to internet-facing nodes"),
    ),
)

_T1048 = MitreTechnique(
    technique_id="T1048",
    technique_name="Exfiltration Over Alternative Protocol",
    tactic=TacticType.EXFILTRATION,
    description=("Adversaries may use non-standard protocols (DNS, ICMP) to exfiltrate data."),
    mitre_url="https://attack.mitre.org/techniques/T1048/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service"],
        edge_types=["CAN_REACH", "CONNECTS_TO"],
        required_properties={"port": 53},
        description=("DNS or non-standard services reachable from sensitive hosts"),
    ),
)

_T1567 = MitreTechnique(
    technique_id="T1567",
    technique_name="Exfiltration Over Web Service",
    tactic=TacticType.EXFILTRATION,
    description=("Adversaries may exfiltrate data to cloud storage or web services."),
    mitre_url="https://attack.mitre.org/techniques/T1567/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service", "Application"],
        edge_types=["CAN_REACH", "DEPENDS_ON"],
        description="Paths to cloud storage endpoints from internal hosts",
    ),
)

_T1537 = MitreTechnique(
    technique_id="T1537",
    technique_name="Transfer Data to Cloud Account",
    tactic=TacticType.EXFILTRATION,
    description=("Adversaries may transfer data to a cloud account they control."),
    mitre_url="https://attack.mitre.org/techniques/T1537/",
    severity_default="high",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Application"],
        edge_types=["CAN_REACH", "HAS_ACCESS"],
        description="Cloud storage applications accessible from internal hosts",
    ),
)

_T1029 = MitreTechnique(
    technique_id="T1029",
    technique_name="Scheduled Transfer",
    tactic=TacticType.EXFILTRATION,
    description=(
        "Adversaries may schedule data exfiltration to occur at certain times or intervals."
    ),
    mitre_url="https://attack.mitre.org/techniques/T1029/",
    severity_default="medium",
    graph_query=GraphQueryPattern(
        node_labels=["Host", "Service", "Application"],
        edge_types=["CAN_REACH", "HAS_ACCESS"],
        description=("Scheduler services with outbound reach to external nodes"),
    ),
)

# ── Lookup Tables ──────────────────────────────────────────────

MITRE_TECHNIQUES: dict[str, MitreTechnique] = {
    t.technique_id: t
    for t in [
        _T1190,
        _T1133,
        _T1566,
        _T1078,
        _T1199,
        _T1021_001,
        _T1021_004,
        _T1550_002,
        _T1558,
        _T1482,
        _T1068,
        _T1078_001,
        _T1548,
        _T1134,
        _T1098,
        _T1041,
        _T1048,
        _T1567,
        _T1537,
        _T1029,
    ]
}

TECHNIQUES_BY_TACTIC: dict[TacticType, list[MitreTechnique]] = {}
for _t in MITRE_TECHNIQUES.values():
    TECHNIQUES_BY_TACTIC.setdefault(_t.tactic, []).append(_t)


def get_techniques_for_tactic(tactic: TacticType) -> list[MitreTechnique]:
    """Return all techniques for a given tactic."""
    return TECHNIQUES_BY_TACTIC.get(tactic, [])


def get_technique(technique_id: str) -> MitreTechnique | None:
    """Look up a technique by ID. Returns None if not found."""
    return MITRE_TECHNIQUES.get(technique_id)
