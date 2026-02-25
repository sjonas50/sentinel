//! sentinel-discover: Network scanner for the Sentinel knowledge graph.
//!
//! Wraps nmap to scan subnets, detects changes against the Neo4j graph,
//! and records an Engram audit trail for every scan run.

pub mod config;
pub mod diff;
pub mod engram;
pub mod error;
pub mod nmap_xml;
pub mod persist;
pub mod scanner;
pub mod scheduler;
