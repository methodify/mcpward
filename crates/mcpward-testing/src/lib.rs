//! Testing tools for servers built with [mcpward](https://docs.rs/mcpward).
//!
//! - [`TestIssuer`]: an in-process identity provider that serves a JWKS and mints tokens,
//!   including every kind of bad token the validator must refuse.
//! - [`TestTokenEndpoint`]: a mock Entra token endpoint (On-Behalf-Of) and managed-identity
//!   endpoint.
//! - [`TestClient`]: drives a built `McpServer` in-process, in both protocol eras.
//! - [`conformance!`]: generates the conformance suite against your own server.
//!
//! The RSA keys under `keys/` are public test keys. Never trust them outside tests.
#![deny(missing_docs)]

mod client;
pub mod conformance;
mod issuer;
mod logs;
mod token_endpoint;

pub use client::{Era, TestClient, TestResponse};
pub use issuer::{TestIssuer, TestIssuerBuilder, TokenBuilder};
pub use logs::LogCapture;
pub use token_endpoint::{EntraError, TestTokenEndpoint, TokenRequest};

/// Client ID that [`TokenBuilder`] puts in `azp` and [`TestIssuer::auth_for`] allows.
pub const TEST_CLIENT_ID: &str = "test-client";
/// Default user object ID (`oid`) in Entra-shaped tokens.
pub const TEST_OID: &str = "00000000-0000-0000-0000-0000000000a1";
/// Default subject (`sub`) in generic tokens.
pub const TEST_SUBJECT: &str = "test-user";
/// Default audience of generic tokens.
pub const TEST_AUDIENCE: &str = "api://mcpward-test";
/// The base scope tokens carry by default.
pub const TEST_SCOPE: &str = "access_as_user";
