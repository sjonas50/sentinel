# Project Sentinel: Enterprise Autonomous Cyber Defense Platform
## Build Plan — The Attic AI
### February 2026

---

## Executive Summary

Build an autonomous cyber defense platform for enterprise clients that combines Wraithwatch-style network defense (digital twin, attack path computation, agentic threat hunting) with Acuvity-style AI governance (shadow AI discovery, MCP security, agent behavior enforcement) — unified by Engram's reasoning audit trail, which no competitor offers.

**Product name (working):** Sentinel

**One-liner:** Autonomous cyber defense that sees your whole network, hunts threats at machine speed, and governs every AI agent in your environment — with a complete reasoning audit trail for every decision.

**Why this wins in enterprise:** Enterprise buyers don't just need defense — they need *provable* defense. SOC 2 auditors, board members, and cyber insurance underwriters all want evidence that defenses are working. Engram's reasoning capture gives every autonomous defensive action an auditable chain of custody that no competitor provides. This is the wedge.

---

## Market Timing

Three signals in the last 14 days confirm this market is ready:

1. **Wraithwatch's $30M federal contract (Feb 20, 2026)** — validates autonomous cyber defense as a funded category, not a science project
2. **Proofpoint's acquisition of Acuvity (Feb 12, 2026)** — validates AI governance/MCP security as acquisition-worthy for major enterprise security vendors
3. **Lightspeed's Cyber60 list** — 7AI, Litt, and multiple companies on the 2025-2026 list building autonomous defense, confirming VC appetite

The enterprise cybersecurity market is projected to reach $66.89B by 2032. AI-related cybersecurity investment is growing 20%+ YoY. 75% of CISOs surveyed by Lightspeed report confirmed or suspected AI-related security incidents in the past 12 months.

---

## Competitive Landscape

| Competitor | What They Do | What They Don't Do |
|---|---|---|
| **Wraithwatch** | Digital twin, attack paths, agent swarms, SIEM hunting | No AI governance, no MCP security, no reasoning audit trail. Federal-focused, not enterprise self-serve. |
| **Acuvity/Proofpoint** | Shadow AI discovery, MCP security, AI governance, policy enforcement | No network digital twin, no attack path analysis, no autonomous threat hunting. Governance only, not defense. |
| **SentinelOne** | XDR, endpoint protection, autonomous response | No digital twin, no AI-specific governance, no attack path computation. Traditional endpoint focus. |
| **CrowdStrike** | Endpoint, cloud, identity threat detection | Similar gaps to SentinelOne. Agent-based but not agentic-AI defense. |
| **Darktrace** | Network traffic anomaly detection, autonomous response | Closest to our approach but no digital twin, no AI governance, no reasoning capture. Expensive (~$100K+/yr). |
| **7AI** | Autonomous SOC investigations | Narrow focus on alert investigation only. No network modeling or governance. |

**Sentinel's unique position:** The ONLY platform that combines network-layer defense (like Wraithwatch) + AI/agent governance (like Acuvity) + auditable reasoning trails (Engram). Enterprise buyers currently need 3+ vendors to get this coverage. We unify it.

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SENTINEL PLATFORM                                │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │   DISCOVER    │  │    DEFEND     │  │    GOVERN    │  │   OBSERVE   │ │
│  │              │  │              │  │              │  │             │ │
│  │ Network Twin │  │ Threat Hunt  │  │ AI/Agent     │  │ Engram      │ │
│  │ Asset Map    │  │ Attack Sim   │  │ Governance   │  │ Audit Trail │ │
│  │ CVE Scan     │  │ Auto-Respond │  │ MCP Security │  │ Compliance  │ │
│  │ Config Audit │  │ SIEM Agents  │  │ Shadow AI    │  │ Reporting   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │         │
│  ┌──────┴─────────────────┴─────────────────┴─────────────────┴──────┐  │
│  │                    AGENT ORCHESTRATION LAYER                       │  │
│  │              (AgentOps Control Plane + OPA/Rego)                   │  │
│  ├───────────────────────────────────────────────────────────────────┤  │
│  │                    KNOWLEDGE GRAPH / DATA LAYER                   │  │
│  │         Neo4j (topology) + ClickHouse (events) + Git (engrams)    │  │
│  ├───────────────────────────────────────────────────────────────────┤  │
│  │                    INTEGRATION LAYER                               │  │
│  │  SIEM │ EDR │ IAM │ Cloud │ MCP │ Firewall │ Device Mgmt │ CI/CD │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Four Pillars

**Pillar 1: DISCOVER** — Continuous network modeling and digital twin
**Pillar 2: DEFEND** — Autonomous threat hunting and attack simulation
**Pillar 3: GOVERN** — AI agent governance, shadow AI, MCP security
**Pillar 4: OBSERVE** — Engram-powered audit trail and compliance reporting

---

## Pillar 1: DISCOVER (Network Digital Twin)

### What It Does
Autonomously maps and continuously models the entire IT environment — every asset, connection, permission, configuration, and vulnerability — as a living digital twin.

### Components

#### 1.1 Network Discovery Engine
**Purpose:** Automated asset discovery and topology mapping

**Implementation:**
- Active scanning via Nmap integration (configurable scan profiles for different network segments)
- Passive traffic analysis for environments where active scanning is restricted
- Cloud API discovery: AWS (boto3), Azure (azure-mgmt), GCP (google-cloud) — pull every resource, security group, IAM role, VPC configuration
- DNS enumeration and certificate transparency log mining for external surface mapping
- Agent-based local discovery for endpoints (lightweight Rust binary reporting to central)

**Tech:**
- Rust scanner daemon (`sentinel-discover`) — wraps Nmap, handles scheduling, deduplication, change detection
- Python orchestration layer for cloud API integrations
- Output: structured JSON asset records → Neo4j

#### 1.2 Knowledge Graph
**Purpose:** Store and query the network topology as a traversable graph

**Implementation:**
- **Neo4j** as the graph database (proven for attack path analysis at scale)
- Node types: `Host`, `Service`, `Port`, `User`, `Group`, `Role`, `Policy`, `Subnet`, `VPC`, `Certificate`, `Application`, `Container`, `MCP_Server`
- Edge types: `CONNECTS_TO`, `HAS_ACCESS`, `MEMBER_OF`, `RUNS_ON`, `TRUSTS`, `ROUTES_TO`, `EXPOSES`, `DEPENDS_ON`, `CAN_REACH`
- Properties on edges: protocol, port, encryption status, last verified timestamp, exploitability score
- Continuous delta updates (not full rebuilds) — scanner detects changes → graph mutations
- Cypher query API exposed for all other pillars to consume

**Schema example:**
```cypher
// An EC2 instance running a service with a known CVE
(h:Host {ip: "10.0.1.42", os: "Ubuntu 22.04", cloud: "aws", instance_id: "i-abc123"})
  -[:RUNS]->(s:Service {name: "nginx", version: "1.18.0", port: 443})
  -[:HAS_CVE]->(v:Vulnerability {cve: "CVE-2024-1234", cvss: 8.1, exploitable: true})

// A user who can reach that host through a chain
(u:User {name: "svc-deploy", type: "service_account"})
  -[:HAS_ACCESS {permissions: ["ssh"]}]->(h)
```

#### 1.3 Configuration Auditor
**Purpose:** Pull and audit security configurations from deployed tools

**Implementation:**
- API connectors for: Active Directory/Entra ID, Okta, AWS IAM, Azure RBAC, Palo Alto, Fortinet, CrowdStrike, SentinelOne, Intune, Jamf
- Configuration drift detection — snapshot configs, diff against baselines and CIS benchmarks
- Misconfiguration scoring using CIS Benchmark rules engine
- Findings feed into the knowledge graph as properties on affected nodes

#### 1.4 Vulnerability Correlation
**Purpose:** Match discovered software versions against known vulnerabilities

**Implementation:**
- NVD/CVE database ingestion (daily sync via NVD API v2)
- EPSS (Exploit Prediction Scoring System) integration for probability-of-exploitation scoring
- CISA KEV (Known Exploited Vulnerabilities) catalog matching
- Software bill of materials (SBOM) ingestion for container/application-level correlation
- Output: CVE nodes linked to Host/Service nodes in the graph

---

## Pillar 2: DEFEND (Autonomous Threat Hunting & Attack Simulation)

### What It Does
AI agents that autonomously hunt for threats across your SIEM data, simulate attacks against the digital twin to find exploitable paths, and generate defense plans — all at machine speed.

### Components

#### 2.1 Attack Path Calculator
**Purpose:** Compute every possible attack path through the network graph

**Implementation:**
- Graph traversal engine built on Neo4j Cypher + custom Rust pathfinding for performance
- Algorithms:
  - **All-paths enumeration** from internet-facing assets to crown jewels (databases, key servers, domain controllers)
  - **Shortest weighted path** (edge weights = 1/exploitability × 1/difficulty)
  - **Lateral movement chains** — find multi-hop paths using credential reuse, trust relationships
  - **Blast radius** — given a compromised node, compute all reachable nodes within N hops
- Each path scored: `risk = Σ(node_criticality × edge_exploitability × path_probability)`
- Continuously recomputed as the digital twin updates
- Output: ranked attack paths with step-by-step breakdown and remediation recommendations

**Differentiator:** Engram captures the reasoning chain for each computed path — why the system concluded this path is exploitable, what alternatives it considered, what mitigations it rejected. This is audit-grade evidence that no competitor provides.

#### 2.2 Adversarial Simulation Engine
**Purpose:** Offensive AI agents that test the digital twin

**Implementation:**
- **MITRE ATT&CK** framework as the base taxonomy (14 tactics, 200+ techniques)
- Offensive agent swarm:
  - Each agent specializes in a tactic category (Initial Access, Lateral Movement, Exfiltration, etc.)
  - Agents use LLM reasoning to chain techniques into novel attack sequences
  - Agents mutate known attack patterns to discover variants
  - All simulation runs against the digital twin — NEVER against production
- Defensive agent swarm:
  - Responds to offensive agent findings with mitigation proposals
  - Generates firewall rules, detection signatures, config changes
  - Proposes compensating controls where direct fixes aren't possible
- **Adversarial co-evolution loop:**
  1. Offensive agents find paths → 2. Defensive agents generate mitigations → 3. Digital twin is updated with proposed mitigations → 4. Offensive agents re-attack → 5. Repeat
  - Each cycle produces a "generation" recorded in Engram with full reasoning
  - Evolutionary fitness: offensive agents scored on paths found, defensive agents on paths closed

**Tech:**
- Python agent orchestration (LangGraph or custom, managed by AgentOps Control Plane)
- Claude API / local LLM for agent reasoning (configurable per customer)
- Engram captures every simulation session — intent, attack chain tried, defenses proposed, outcomes

#### 2.3 Agentic Threat Hunting (SIEM Integration)
**Purpose:** AI agents that autonomously explore SIEM data to find threats

**Implementation:**
- **Phase 1 target:** Elastic/OpenSearch (most common in enterprise mid-market)
- **Phase 2:** Splunk, Microsoft Sentinel, CrowdStrike LogScale
- Natural language → query translation:
  - User: "Show me all failed logins from service accounts in the last 24 hours"
  - Agent: translates to Elasticsearch DSL query, executes, interprets results
- Autonomous hunting mode:
  - Agent dispatches worker sub-agents to explore SIEM indices
  - Workers identify high-value data fields, unusual patterns, statistical anomalies
  - Correlation engine connects findings across indices (auth logs + network flows + endpoint events)
  - Converts findings into detection rules (Sigma format for portability)
- **Detection-as-code output:**
  - Every hunt finding → proposed Sigma rule → review queue
  - Approved rules auto-deploy to SIEM
  - Days of detection engineering → minutes

#### 2.4 Automated Response (with guardrails)
**Purpose:** Execute defensive actions at machine speed, with human approval gates

**Implementation:**
- Response taxonomy:
  - **Auto-execute (no approval needed):** Block known-malicious IPs, quarantine files matching YARA rules, disable compromised service accounts
  - **Fast-track (1-click approval):** Firewall rule changes, detection rule deployment, config hardening
  - **Full review (requires sign-off):** Network segment isolation, broad access revocations, production config changes
- Response actions execute via API integrations to existing tools (not replacing them)
- Every action recorded in Engram with full reasoning chain
- Rollback capability for every automated action

---

## Pillar 3: GOVERN (AI Agent Governance)

### What It Does
Discovers, monitors, and governs every AI agent and AI tool operating in the enterprise environment. This is the Acuvity competitor layer — but integrated with network defense rather than standalone.

### Components

#### 3.1 Shadow AI Discovery
**Purpose:** Find every AI tool, copilot, agent, and model being used — sanctioned or not

**Implementation:**
- Network traffic analysis: identify API calls to known AI services (OpenAI, Anthropic, Google, Cohere, Hugging Face, etc.)
- DNS monitoring for AI service domains
- Browser extension / endpoint agent that detects AI tool usage
- SaaS application inventory cross-referenced with known AI-integrated SaaS products
- MCP server discovery: scan for running MCP servers across the environment
- Shadow AI risk scoring: each discovered tool scored on data handling practices, service tier, integration depth

#### 3.2 MCP Security Layer
**Purpose:** Secure the Model Context Protocol infrastructure

**Implementation:**
- **MCP Interceptor Proxy** (leveraging your existing AgentOps Control Plane MCP interceptor design):
  - Sits between AI agents and MCP servers
  - Inspects every tool call in real-time
  - Enforces OPA/Rego policies on what tools agents can call and with what parameters
  - Detects MCP-specific threats: cross-server tool shadowing, rug pulls, prompt injection via tool descriptions, secrets leakage
  - TLS enforcement, authentication, and authorization
- This is the sharpest security wedge — it's the exact component your AgentOps architecture already designs for

#### 3.3 Agent Identity & Behavior
**Purpose:** Know which AI agents are operating, what they're doing, and whether they're authorized

**Implementation:**
- Agent registry: every AI agent gets a registered identity with defined permissions
- Behavioral baseline: monitor agent actions over time, establish "normal" patterns
- Drift detection: alert when an agent deviates from its behavioral baseline
- Intent verification: compare what an agent is doing vs. what it was asked to do
- Integrates directly with the AgentOps Control Plane identity management system

#### 3.4 AI Data Loss Prevention
**Purpose:** Prevent sensitive data from leaking through AI tools

**Implementation:**
- Inspect data flowing to/from AI services
- DLP policies: PII detection, code/IP scanning, classification-based rules
- Block or redact sensitive data before it reaches external AI services
- Audit log of all data interactions with AI tools

---

## Pillar 4: OBSERVE (Engram Audit Trail)

### What It Does
Every autonomous decision, every agent action, every attack path computation, every governance enforcement — captured as a versioned, auditable reasoning trail powered by Engram.

### Components

#### 4.1 Reasoning Capture
**Purpose:** Record the "why" behind every automated security decision

**Implementation:**
- Engram core library integrated into every Sentinel agent
- Each agent session produces an engram: intent, context, decisions made, alternatives considered, dead ends encountered, final actions taken
- Stored as Git objects under `refs/engrams/` in the Sentinel data repository
- Content-addressed with BLAKE3 hashing — tamper-evident by design

#### 4.2 Compliance Reporting
**Purpose:** Generate audit-ready reports from the reasoning trail

**Implementation:**
- SOC 2 Type II evidence generation: automated control evidence from Engram data
  - "Control: Vulnerability scanning occurs weekly" → Evidence: Engram sessions showing weekly scans with reasoning
  - "Control: Access reviews are performed quarterly" → Evidence: Agent sessions reviewing and remediating access
- ISO 27001 control mapping
- NIST CSF alignment
- CIS Controls coverage dashboard
- Board-ready executive summaries: threat posture, top risks, defense coverage, trend lines

#### 4.3 Cyber Insurance Evidence
**Purpose:** Provide insurers with machine-verified evidence of security posture

**This is a killer enterprise selling point.** Cyber insurance premiums are skyrocketing. Insurers want evidence of proactive defense. Sentinel provides:
- Continuous evidence of vulnerability scanning and remediation
- Proof of attack path analysis and mitigation
- Audit trail of every autonomous defensive action
- Trend data showing improving security posture over time
- All backed by tamper-evident Engram records

#### 4.4 Real-Time Dashboard
**Purpose:** Single pane of glass for security posture

**Implementation:**
- React frontend with real-time updates via WebSocket
- Views:
  - **Network map** — interactive visualization of the digital twin (force-directed graph)
  - **Attack paths** — ranked list with drill-down into each path's steps
  - **Threat hunt feed** — live feed of agent findings
  - **AI governance** — shadow AI inventory, agent activity, policy violations
  - **Compliance** — control coverage, evidence completeness, audit readiness
- Role-based views: CISO (executive), SOC analyst (operational), auditor (compliance)

---

## Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| Discovery agents | Rust | Performance for scanning, aligns with Engram core |
| Agent orchestration | Python (LangGraph) | Rich AI/ML ecosystem, rapid iteration |
| Knowledge graph | Neo4j | Best-in-class for attack path analysis |
| Event stream | Kafka | High-throughput event processing, AgentOps alignment |
| Policy engine | OPA/Rego | Industry standard, AgentOps alignment |
| Analytics DB | ClickHouse | Fast OLAP queries for security analytics |
| State DB | PostgreSQL | Reliable, well-understood |
| Reasoning capture | Engram (Rust) | Existing IP, tamper-evident audit trail |
| Agent governance | AgentOps Control Plane | Existing IP, MCP interceptor |
| LLM inference | Claude API + optional local (Llama) | Flexibility for airgapped environments |
| Frontend | React + D3.js | Interactive graph visualization |
| Deployment | Docker + Kubernetes | Enterprise standard |

---

## Build Phases

### Phase 0: Foundation (Weeks 1-4)
**Goal:** Core infrastructure, integration framework, and data model

**Deliverables:**
- Neo4j schema deployed with full node/edge type definitions
- Integration framework: abstract connector interface + first 3 connectors (AWS, Azure, Entra ID)
- Engram integration: every agent session auto-captures to Git
- AgentOps Control Plane: policy engine bootstrap with initial OPA/Rego rules
- Basic React dashboard shell with authentication
- CI/CD pipeline, testing framework, deployment automation

**Team:** 3 engineers
- 1 Rust engineer (discovery scanner + Engram integration)
- 1 Python engineer (integration connectors + agent framework)
- 1 full-stack engineer (dashboard + API layer)

### Phase 1: DISCOVER MVP (Weeks 5-10)
**Goal:** Working digital twin for a customer's environment

**Deliverables:**
- Network scanner operational: active + cloud API discovery
- Knowledge graph populated with real customer data (internal dogfood first)
- Configuration auditor for top 5 tools: AWS IAM, Entra ID, Okta, Palo Alto, CrowdStrike
- CVE correlation engine with NVD + EPSS + CISA KEV
- Dashboard: interactive network map, asset inventory, vulnerability overview
- First Engram audit trail: full reasoning capture for discovery sessions

**Milestone:** Can show a prospect their own network topology, misconfigurations, and vulnerabilities in a 30-minute setup

**Team:** 3-4 engineers

### Phase 2: DEFEND MVP (Weeks 11-18)
**Goal:** Attack path analysis + initial threat hunting

**Deliverables:**
- Attack path calculator: all-paths and shortest-path from internet to crown jewels
- Risk scoring engine with ranked output
- Remediation recommendation generator (LLM-powered, per path)
- SIEM integration v1: Elastic/OpenSearch connector
- Natural language SIEM querying
- First autonomous hunt agents: 3 pre-built hunt playbooks (credential abuse, lateral movement, data exfiltration)
- Adversarial simulation v1: top 20 MITRE ATT&CK techniques against digital twin
- Dashboard: attack path visualization, hunt findings feed, simulation results
- Engram: full reasoning capture for every hunt session and simulation run

**Milestone:** Can demonstrate "here are the 5 ways an attacker could reach your database, here's how we'd fix each one, and here's the audit trail proving we checked"

**Team:** 4-5 engineers

### Phase 3: GOVERN MVP (Weeks 19-24)
**Goal:** AI governance layer operational

**Deliverables:**
- Shadow AI discovery: network traffic analysis + DNS monitoring for AI services
- MCP Interceptor Proxy: policy enforcement on MCP tool calls
- Agent identity registry with behavioral baselining
- AI DLP: PII detection on data flowing to AI services
- Policy library: pre-built OPA/Rego policies for common AI governance scenarios
- Dashboard: AI tool inventory, agent activity, policy violations, data flow map
- Engram: governance enforcement decisions captured with reasoning

**Milestone:** Can show a CISO "here are all the AI tools your employees are using, here's what data is flowing to them, and here are the policies enforcing safe usage"

**Team:** 3-4 engineers

### Phase 4: Integration & Polish (Weeks 25-30)
**Goal:** Production-ready platform

**Deliverables:**
- Compliance reporting engine: SOC 2, ISO 27001, NIST CSF templates
- Cyber insurance evidence packages: automated report generation
- Automated response framework with approval gates
- Additional SIEM integrations: Splunk, Microsoft Sentinel
- Additional tool integrations: Fortinet, SentinelOne, Jamf, Intune
- Adversarial simulation v2: full MITRE ATT&CK coverage with co-evolution loop
- Performance optimization, security hardening, penetration testing
- Documentation, runbooks, customer onboarding automation
- Engram: compliance evidence auto-generation from reasoning trail

**Milestone:** First paying enterprise customer live in production

**Team:** 5-6 engineers

---

## Resource Requirements

### Team Allocation (from existing ~20 developers)

| Role | Count | Source |
|---|---|---|
| Rust engineers (scanner, Engram, performance) | 2 | Existing team or hire |
| Python AI/ML engineers (agents, LLM orchestration) | 2-3 | Existing team |
| Full-stack (React + API) | 1-2 | Existing team |
| Security domain expert | 1 | **Must hire** — need someone who's done pen testing, red teaming, or SOC work |
| DevOps/infrastructure | 1 | Existing team |
| **Total dedicated to Sentinel** | **7-9** | |

**Critical hire:** You need at least one person with real offensive security experience. The adversarial simulation engine and threat hunting playbooks need to be built by someone who's actually done this work. A former pen tester or red teamer who can code in Python would be ideal. This person doesn't need to be a senior hire — even a mid-level security engineer with 3-5 years of experience and a hunger to build something new would work. Without this hire, the DEFEND pillar will be surface-level.

### Impact on Other Products
Dedicating 7-9 to Sentinel means pulling resources. Suggested approach:
- **GenLLM:** Maintenance mode (2 devs). It's mature enough.
- **ACQ:** Maintenance + enhancement (2-3 devs). Revenue generator, keep it running.
- **Fisher / consulting:** Continue with current allocation
- **Delivery system:** Phase the build plan — the Sentinel agents can eventually dogfood the delivery system patterns
- **Engram / AgentOps:** These ARE Sentinel's core infrastructure. Development continues as part of Sentinel, not separate.

### Infrastructure Costs (Monthly)

| Component | Service | Estimated Cost |
|---|---|---|
| Neo4j Aura | Enterprise | $2,000-5,000 |
| ClickHouse Cloud | Production | $1,000-3,000 |
| Kafka (Confluent Cloud) | Standard | $500-2,000 |
| PostgreSQL (RDS) | db.r6g.xlarge | $500-1,000 |
| Compute (EKS/K8s) | Agent workers + API | $3,000-8,000 |
| LLM API (Claude/OpenAI) | Agent reasoning | $2,000-10,000 (usage-dependent) |
| S3 storage | Engram repos + logs | $200-500 |
| **Monthly total** | | **$9,200-29,500** |

For early stages, you can cut this significantly by self-hosting Neo4j Community, using Redpanda instead of Confluent, and running ClickHouse on your own infra.

---

## Pricing Model

| Tier | Target | Monthly Price | Includes |
|---|---|---|---|
| **Starter** | Companies 100-500 employees | $3,000-5,000/mo | DISCOVER + OBSERVE. Digital twin, vuln scanning, basic compliance reporting. |
| **Professional** | Companies 500-5,000 employees | $8,000-15,000/mo | All pillars. Threat hunting, attack paths, AI governance, full Engram audit trail. |
| **Enterprise** | Companies 5,000+ employees | $25,000-50,000/mo | Everything + custom integrations, dedicated support, advanced adversarial simulation, custom compliance frameworks. |

**ACV range:** $36K-$600K depending on tier and company size.

**Comparison:** Darktrace charges $100K-$300K/yr for network defense only. Wraithwatch is likely similar or higher for federal. CrowdStrike Falcon runs $80K-$200K/yr for large enterprises. Sentinel offers MORE capability (defense + governance + audit trail) at competitive pricing to these incumbents.

---

## Go-to-Market Strategy

### Initial Target: Mid-Market Enterprise (500-5,000 employees)

**Why mid-market:**
- Underserved by Wraithwatch (too federal-focused), Darktrace (too expensive), and Acuvity (now locked into Proofpoint's ecosystem)
- Large enough to have real security needs and budgets
- Small enough that one platform replacing 3-4 point tools is compelling
- CISOs at these companies are often one person or a small team — they need automation most

### Ideal Customer Profile
- 500-5,000 employees
- Deploying AI agents/copilots in production (or planning to)
- Has a SIEM (Elastic, Splunk, or Sentinel) but not a large SOC team
- Facing SOC 2 or similar compliance requirements
- Has cloud infrastructure (AWS/Azure/GCP)
- Sector: SaaS, fintech, healthtech, professional services

### Sales Motion

**Phase 1 (Months 1-6): Founder-led sales**
- Steve and Bo demo to prospects directly
- Free 30-minute "security assessment" using DISCOVER — show them their own network, vulns, and attack paths
- This is the same playbook Wraithwatch uses ("chat with founders, not sales")

**Phase 2 (Months 6-12): PLG + outbound**
- Free tier: DISCOVER-only (digital twin + vuln scanning) for companies under 100 assets
- This seeds the market, gets data, and creates upgrade opportunities
- Outbound targeting companies that just raised Series B+ (they're scaling fast, deploying AI, and need security)

**Phase 3 (12+ months): Channel partnerships**
- MSSPs (Managed Security Service Providers) white-labeling Sentinel
- Cyber insurance partnerships — insurers recommend Sentinel for premium discounts
- Compliance consultants bundling Sentinel with SOC 2/ISO audit engagements

### Content & Positioning
- Blog series: "The Agentic Attack Surface" — how AI agents create new attack vectors
- Open-source contribution: release the Engram-based compliance evidence library
- Speaking: RSA Conference, Black Hat (even as attendee/networker initially)
- Case studies: dogfood internally first, then document and publish

---

## Risk Analysis

| Risk | Severity | Mitigation |
|---|---|---|
| **Security domain expertise gap** | High | Must hire at least 1 security-experienced engineer. Non-negotiable. |
| **Scope creep across 4 pillars** | High | Ship DISCOVER first, validate with 3 paying customers before investing heavily in DEFEND and GOVERN |
| **Enterprise sales cycle length** | Medium | PLG free tier accelerates pipeline. Security assessment demo creates urgency. |
| **LLM reliability for security decisions** | Medium | Human-in-the-loop for all high-impact actions. Engram trail enables post-hoc review. |
| **Competition from well-funded incumbents** | Medium | Speed advantage — incumbents are slow. Unified platform vs. their point solutions. |
| **Team bandwidth with existing products** | Medium | Protect ACQ revenue. GenLLM to maintenance. Consolidate Engram/AgentOps into Sentinel. |

---

## Success Metrics

| Metric | Phase 1 (6 months) | Phase 2 (12 months) | Phase 3 (18 months) |
|---|---|---|---|
| Paying customers | 3 | 10 | 25 |
| ARR | $150K | $600K | $2M |
| Digital twins deployed | 10 | 30 | 75 |
| Engram audit sessions | 10K | 100K | 500K |
| Attack paths computed | 50K | 500K | 2M |
| AI tools governed | 500 | 5,000 | 25,000 |
| Team size (Sentinel) | 7 | 9 | 12 |

---

## Why The Attic AI Wins Here

1. **Engram is a genuine moat.** No other security platform captures the reasoning chain behind autonomous decisions. In a world where boards, auditors, and regulators are asking "how do we know the AI did the right thing?" — Engram provides the answer.

2. **AgentOps Control Plane is purpose-built for this.** The MCP interceptor, OPA/Rego policy engine, and agent identity system you've already designed are exactly what the GOVERN pillar needs. You're not starting from zero.

3. **The convergence play is unique.** Wraithwatch does defense. Acuvity does governance. Nobody does both. Enterprise CISOs are buying 5+ security tools today. A unified platform that covers network defense AND AI governance AND provides an audit trail is genuinely differentiated.

4. **Your team builds fast.** 20 developers with experience shipping AI products across multiple domains. The delivery system architecture you've designed shows you know how to manage complex, multi-pillar builds.

5. **Timing is perfect.** Two major market validation events in the last 2 weeks (Wraithwatch's $30M contract + Proofpoint/Acuvity acquisition). The enterprise market is ready to buy autonomous cyber defense. The question is who gets there first with a unified offering.