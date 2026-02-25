//! Nmap XML output deserialization.
//!
//! Nmap's `-oX -` flag outputs structured XML to stdout.
//! This module provides typed Rust structs that deserialize from that XML
//! using `quick-xml` with serde.

use serde::Deserialize;

use crate::error::{DiscoverError, Result};

/// Root element: `<nmaprun>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "nmaprun")]
pub struct NmapRun {
    #[serde(rename = "@scanner")]
    pub scanner: Option<String>,
    #[serde(rename = "@args")]
    pub args: Option<String>,
    #[serde(rename = "@startstr")]
    pub start_str: Option<String>,
    #[serde(rename = "host", default)]
    pub hosts: Vec<NmapHost>,
    pub runstats: Option<RunStats>,
}

/// A single host from scan results.
#[derive(Debug, Clone, Deserialize)]
pub struct NmapHost {
    pub status: Option<HostStatus>,
    #[serde(rename = "address", default)]
    pub addresses: Vec<Address>,
    pub hostnames: Option<Hostnames>,
    pub ports: Option<Ports>,
    pub os: Option<OsMatches>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostStatus {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@reason")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: String,
    #[serde(rename = "@addrtype")]
    pub addr_type: String,
    #[serde(rename = "@vendor")]
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hostnames {
    #[serde(rename = "hostname", default)]
    pub hostnames: Vec<Hostname>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hostname {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub hostname_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ports {
    #[serde(rename = "port", default)]
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NmapPort {
    #[serde(rename = "@protocol")]
    pub protocol: String,
    #[serde(rename = "@portid")]
    pub port_id: u16,
    pub state: PortState,
    pub service: Option<NmapService>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortState {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@reason")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NmapService {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@product")]
    pub product: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@extrainfo")]
    pub extra_info: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsMatches {
    #[serde(rename = "osmatch", default)]
    pub matches: Vec<OsMatch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsMatch {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@accuracy")]
    pub accuracy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunStats {
    pub finished: Option<Finished>,
    pub hosts: Option<RunStatsHosts>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finished {
    #[serde(rename = "@time")]
    pub time: Option<String>,
    #[serde(rename = "@elapsed")]
    pub elapsed: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunStatsHosts {
    #[serde(rename = "@up")]
    pub up: Option<String>,
    #[serde(rename = "@down")]
    pub down: Option<String>,
    #[serde(rename = "@total")]
    pub total: Option<String>,
}

impl NmapHost {
    /// Extract the IPv4 address, if present.
    pub fn ipv4(&self) -> Option<&str> {
        self.addresses
            .iter()
            .find(|a| a.addr_type == "ipv4")
            .map(|a| a.addr.as_str())
    }

    /// Extract the MAC address, if present.
    pub fn mac(&self) -> Option<&str> {
        self.addresses
            .iter()
            .find(|a| a.addr_type == "mac")
            .map(|a| a.addr.as_str())
    }

    /// Extract the first hostname, if present.
    pub fn hostname(&self) -> Option<&str> {
        self.hostnames
            .as_ref()
            .and_then(|hn| hn.hostnames.first())
            .map(|h| h.name.as_str())
    }

    /// Check if the host is up.
    pub fn is_up(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.state == "up")
    }

    /// Get the best OS match name (highest accuracy, first in list).
    pub fn os_name(&self) -> Option<&str> {
        self.os
            .as_ref()
            .and_then(|os| os.matches.first())
            .map(|m| m.name.as_str())
    }
}

/// Parse nmap XML bytes into a structured `NmapRun`.
pub fn parse_nmap_xml(xml: &[u8]) -> Result<NmapRun> {
    quick_xml::de::from_reader(xml).map_err(|e| DiscoverError::XmlParse(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUICK_SCAN_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 10.0.1.0/24" startstr="Mon Feb 24 10:00:00 2026">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="TestVendor"/>
    <hostnames>
      <hostname name="gateway.local" type="PTR"/>
    </hostnames>
  </host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="10.0.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:10" addrtype="mac"/>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.1.99" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1740400000" elapsed="2.50"/>
    <hosts up="2" down="1" total="3"/>
  </runstats>
</nmaprun>"#;

    const STANDARD_SCAN_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV --top-ports 1000 10.0.1.1" startstr="Mon Feb 24 10:05:00 2026">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web-server.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="95"/>
      <osmatch name="Linux 6.1" accuracy="90"/>
    </os>
  </host>
  <runstats>
    <finished time="1740400100" elapsed="15.30"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"#;

    #[test]
    fn test_parse_quick_scan() {
        let result = parse_nmap_xml(QUICK_SCAN_XML.as_bytes()).unwrap();
        assert_eq!(result.hosts.len(), 3);

        let up_hosts: Vec<_> = result.hosts.iter().filter(|h| h.is_up()).collect();
        assert_eq!(up_hosts.len(), 2);

        let gateway = &result.hosts[0];
        assert_eq!(gateway.ipv4(), Some("10.0.1.1"));
        assert_eq!(gateway.mac(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(gateway.hostname(), Some("gateway.local"));

        let stats = result.runstats.as_ref().unwrap();
        let host_stats = stats.hosts.as_ref().unwrap();
        assert_eq!(host_stats.up.as_deref(), Some("2"));
        assert_eq!(host_stats.total.as_deref(), Some("3"));
    }

    #[test]
    fn test_parse_standard_scan() {
        let result = parse_nmap_xml(STANDARD_SCAN_XML.as_bytes()).unwrap();
        assert_eq!(result.hosts.len(), 1);

        let host = &result.hosts[0];
        assert!(host.is_up());
        assert_eq!(host.ipv4(), Some("10.0.1.1"));
        assert_eq!(host.hostname(), Some("web-server.local"));
        assert_eq!(host.os_name(), Some("Linux 5.15"));

        let ports = host.ports.as_ref().unwrap();
        assert_eq!(ports.ports.len(), 4);

        let ssh = &ports.ports[0];
        assert_eq!(ssh.port_id, 22);
        assert_eq!(ssh.protocol, "tcp");
        assert_eq!(ssh.state.state, "open");
        let ssh_svc = ssh.service.as_ref().unwrap();
        assert_eq!(ssh_svc.name, "ssh");
        assert_eq!(ssh_svc.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh_svc.version.as_deref(), Some("9.6"));

        let filtered = &ports.ports[3];
        assert_eq!(filtered.port_id, 3306);
        assert_eq!(filtered.state.state, "filtered");
        assert!(filtered.service.is_none());
    }

    #[test]
    fn test_parse_empty_scan() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 192.168.99.0/24">
  <runstats>
    <finished elapsed="1.00"/>
    <hosts up="0" down="256" total="256"/>
  </runstats>
</nmaprun>"#;

        let result = parse_nmap_xml(xml.as_bytes()).unwrap();
        assert_eq!(result.hosts.len(), 0);
    }

    #[test]
    fn test_host_without_hostname() {
        let host = NmapHost {
            status: Some(HostStatus {
                state: "up".to_string(),
                reason: None,
            }),
            addresses: vec![Address {
                addr: "10.0.1.5".to_string(),
                addr_type: "ipv4".to_string(),
                vendor: None,
            }],
            hostnames: None,
            ports: None,
            os: None,
        };

        assert_eq!(host.ipv4(), Some("10.0.1.5"));
        assert_eq!(host.hostname(), None);
        assert_eq!(host.mac(), None);
        assert_eq!(host.os_name(), None);
        assert!(host.is_up());
    }
}
