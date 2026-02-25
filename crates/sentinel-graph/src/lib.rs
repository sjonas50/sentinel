//! Sentinel Graph — Neo4j client for the knowledge graph.
//!
//! This crate is the single mutation point for the Neo4j knowledge graph.
//! All graph reads and writes flow through this crate to ensure consistent
//! tenant isolation, schema compliance, and delta tracking.

pub mod client;
pub mod mutations;
pub mod queries;

pub use client::{GraphClient, GraphConfig, GraphError};
