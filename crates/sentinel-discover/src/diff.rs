//! Change detection: convert nmap output to sentinel-core types and diff
//! against the existing graph state.

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sentinel_core::types::{
    CloudProvider, Criticality, Edge, EdgeId, EdgeProperties, EdgeType, Host, NodeId, Port,
    PortState, Protocol, Service, ServiceState, TenantId,
};
use sentinel_graph::GraphClient;
use uuid::Uuid;

use crate::error::Result;
use crate::nmap_xml::{NmapHost, NmapRun};

/// DNS namespace UUID for deterministic port/service IDs.
const SENTINEL_NS: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// A host with its discovered ports, services, and edges.
pub struct DiscoveredHost {
    pub host: Host,
    pub ports: Vec<Port>,
    pub services: Vec<Service>,
    pub edges: Vec<Edge>,
}

/// The outcome of diffing scan results against the graph.
pub struct DiffResult {
    pub new_hosts: Vec<DiscoveredHost>,
    pub changed_hosts: Vec<DiscoveredHost>,
    pub stale_ips: Vec<String>,
    pub summary: DiffSummary,
}

#[derive(Debug, Default)]
pub struct DiffSummary {
    pub total_scanned: u32,
    pub new_count: u32,
    pub changed_count: u32,
    pub stale_count: u32,
}

/// Convert raw nmap output into typed sentinel-core entities.
pub fn parse_scan_results(
    nmap_run: &NmapRun,
    tenant_id: &TenantId,
    scan_time: DateTime<Utc>,
) -> Vec<DiscoveredHost> {
    nmap_run
        .hosts
        .iter()
        .filter(|h| h.is_up())
        .filter_map(|h| convert_nmap_host(h, tenant_id, scan_time))
        .collect()
}

fn convert_nmap_host(
    nmap_host: &NmapHost,
    tenant_id: &TenantId,
    now: DateTime<Utc>,
) -> Option<DiscoveredHost> {
    let ip = nmap_host.ipv4()?;

    // Deterministic host ID based on tenant + IP so MERGE is idempotent.
    let host_id = NodeId(Uuid::new_v5(
        &SENTINEL_NS,
        format!("{}:host:{}", tenant_id.0, ip).as_bytes(),
    ));

    let host = Host {
        id: host_id.clone(),
        tenant_id: tenant_id.clone(),
        ip: ip.to_string(),
        hostname: nmap_host.hostname().map(String::from),
        os: nmap_host.os_name().map(String::from),
        os_version: None,
        mac_address: nmap_host.mac().map(String::from),
        cloud_provider: Some(CloudProvider::OnPrem),
        cloud_instance_id: None,
        cloud_region: None,
        criticality: Criticality::Medium,
        tags: vec![],
        first_seen: now,
        last_seen: now,
    };

    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut edges = Vec::new();

    if let Some(nmap_ports) = &nmap_host.ports {
        for np in &nmap_ports.ports {
            let port_id = NodeId(Uuid::new_v5(
                &SENTINEL_NS,
                format!("{}:port:{}:{}:{}", tenant_id.0, ip, np.port_id, np.protocol).as_bytes(),
            ));

            let port = Port {
                id: port_id.clone(),
                tenant_id: tenant_id.clone(),
                number: np.port_id,
                protocol: parse_protocol(&np.protocol),
                state: parse_port_state(&np.state.state),
                first_seen: now,
                last_seen: now,
            };
            ports.push(port);

            // Host --HAS_PORT--> Port
            edges.push(Edge {
                id: EdgeId(Uuid::new_v5(
                    &SENTINEL_NS,
                    format!("{}:edge:has_port:{}:{}", tenant_id.0, ip, np.port_id).as_bytes(),
                )),
                tenant_id: tenant_id.clone(),
                source_id: host_id.clone(),
                target_id: port_id.clone(),
                edge_type: EdgeType::HasPort,
                properties: EdgeProperties::default(),
                first_seen: now,
                last_seen: now,
            });

            // If nmap identified a service on this port, create a Service node.
            if let Some(nmap_svc) = &np.service {
                let svc_id = NodeId(Uuid::new_v5(
                    &SENTINEL_NS,
                    format!(
                        "{}:service:{}:{}:{}",
                        tenant_id.0, ip, np.port_id, nmap_svc.name
                    )
                    .as_bytes(),
                ));

                let version_str = match (&nmap_svc.product, &nmap_svc.version) {
                    (Some(p), Some(v)) => Some(format!("{p} {v}")),
                    (Some(p), None) => Some(p.clone()),
                    (None, Some(v)) => Some(v.clone()),
                    (None, None) => None,
                };

                let service = Service {
                    id: svc_id.clone(),
                    tenant_id: tenant_id.clone(),
                    name: nmap_svc.name.clone(),
                    version: version_str,
                    port: np.port_id,
                    protocol: parse_protocol(&np.protocol),
                    state: ServiceState::Running,
                    banner: nmap_svc.extra_info.clone(),
                    first_seen: now,
                    last_seen: now,
                };
                services.push(service);

                // Host --EXPOSES--> Service
                edges.push(Edge {
                    id: EdgeId(Uuid::new_v5(
                        &SENTINEL_NS,
                        format!("{}:edge:exposes:{}:{}", tenant_id.0, ip, np.port_id).as_bytes(),
                    )),
                    tenant_id: tenant_id.clone(),
                    source_id: host_id.clone(),
                    target_id: svc_id,
                    edge_type: EdgeType::Exposes,
                    properties: EdgeProperties {
                        port: Some(np.port_id),
                        protocol: Some(parse_protocol(&np.protocol)),
                        ..Default::default()
                    },
                    first_seen: now,
                    last_seen: now,
                });
            }
        }
    }

    Some(DiscoveredHost {
        host,
        ports,
        services,
        edges,
    })
}

/// Compare discovered hosts against what's currently in Neo4j.
pub async fn compute_diff(
    graph: &GraphClient,
    tenant_id: &TenantId,
    discovered: Vec<DiscoveredHost>,
    scan_target_cidr: &str,
) -> Result<DiffResult> {
    let mut new_hosts = Vec::new();
    let mut changed_hosts = Vec::new();
    let mut seen_ips: HashSet<String> = HashSet::new();

    for dh in discovered {
        seen_ips.insert(dh.host.ip.clone());

        let existing = graph
            .find_node_by_property(tenant_id, "Host", "ip", &dh.host.ip)
            .await?;

        match existing {
            None => new_hosts.push(dh),
            Some(record) => {
                // Check if properties changed.
                let props = &record.properties;
                let hostname_changed =
                    dh.host.hostname.as_deref() != props.get("hostname").and_then(|v| v.as_str());
                let os_changed = dh.host.os.as_deref() != props.get("os").and_then(|v| v.as_str());

                if hostname_changed || os_changed {
                    changed_hosts.push(dh);
                } else {
                    // Unchanged — still upsert to update last_seen.
                    changed_hosts.push(dh);
                }
            }
        }
    }

    // Find stale IPs: in graph for this CIDR but not in current scan.
    let stale_ips = find_stale_ips(graph, tenant_id, scan_target_cidr, &seen_ips).await?;

    let summary = DiffSummary {
        total_scanned: seen_ips.len() as u32,
        new_count: new_hosts.len() as u32,
        changed_count: changed_hosts.len() as u32,
        stale_count: stale_ips.len() as u32,
    };

    Ok(DiffResult {
        new_hosts,
        changed_hosts,
        stale_ips,
        summary,
    })
}

/// Query graph for existing hosts in the CIDR and return IPs not seen in scan.
async fn find_stale_ips(
    graph: &GraphClient,
    tenant_id: &TenantId,
    cidr_str: &str,
    seen_ips: &HashSet<String>,
) -> Result<Vec<String>> {
    let all_hosts = graph.list_nodes(tenant_id, "Host", 10_000, 0).await?;

    let cidr: Option<IpNet> = cidr_str.parse().ok();

    Ok(all_hosts
        .iter()
        .filter_map(|record| {
            let ip_str = record.properties.get("ip")?.as_str()?;
            if seen_ips.contains(ip_str) {
                return None;
            }
            // Only consider hosts within the scanned CIDR.
            if let Some(ref net) = cidr {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !net.contains(&ip) {
                        return None;
                    }
                }
            }
            Some(ip_str.to_string())
        })
        .collect())
}

fn parse_protocol(proto: &str) -> Protocol {
    match proto.to_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => Protocol::Other(proto.to_string()),
    }
}

fn parse_port_state(state: &str) -> PortState {
    match state.to_lowercase().as_str() {
        "open" => PortState::Open,
        "closed" => PortState::Closed,
        _ => PortState::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap_xml::parse_nmap_xml;

    fn test_tenant() -> TenantId {
        TenantId(Uuid::nil())
    }

    #[test]
    fn test_parse_scan_results_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="web.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.1.2" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

        let nmap_run = parse_nmap_xml(xml.as_bytes()).unwrap();
        let tid = test_tenant();
        let now = Utc::now();
        let results = parse_scan_results(&nmap_run, &tid, now);

        assert_eq!(results.len(), 1);
        let host = &results[0];
        assert_eq!(host.host.ip, "10.0.1.1");
        assert_eq!(host.host.hostname.as_deref(), Some("web.local"));
        assert_eq!(host.ports.len(), 1);
        assert_eq!(host.ports[0].number, 80);
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].name, "http");
        assert_eq!(host.edges.len(), 2); // HAS_PORT + EXPOSES
    }

    #[test]
    fn test_deterministic_ids() {
        let tid = test_tenant();
        let now = Utc::now();

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

        let run = parse_nmap_xml(xml.as_bytes()).unwrap();
        let r1 = parse_scan_results(&run, &tid, now);
        let r2 = parse_scan_results(&run, &tid, now);

        // Same input → same host ID.
        assert_eq!(r1[0].host.id, r2[0].host.id);
    }

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("tcp"), Protocol::Tcp);
        assert_eq!(parse_protocol("UDP"), Protocol::Udp);
        assert_eq!(parse_protocol("sctp"), Protocol::Other("sctp".to_string()));
    }

    #[test]
    fn test_parse_port_state() {
        assert_eq!(parse_port_state("open"), PortState::Open);
        assert_eq!(parse_port_state("closed"), PortState::Closed);
        assert_eq!(parse_port_state("filtered"), PortState::Filtered);
        assert_eq!(parse_port_state("open|filtered"), PortState::Filtered);
    }
}
