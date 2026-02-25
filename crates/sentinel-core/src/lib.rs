//! sentinel-core: Shared types, configuration, and error handling for the Sentinel platform.
//!
//! This crate provides the foundational types used across all Sentinel components:
//! - Node types (Host, Service, User, etc.) for the knowledge graph
//! - Edge types (ConnectsTo, HasAccess, etc.) for graph relationships
//! - Event types for inter-service communication
//! - Configuration management
//! - Common error types

pub mod config;
pub mod error;
pub mod events;
pub mod types;

pub use error::SentinelError;
