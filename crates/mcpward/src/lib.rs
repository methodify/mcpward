//! # mcpward
//!
//! An auth-first toolkit for remote [MCP](https://modelcontextprotocol.io) servers built on
//! [`rmcp`]. It turns an rmcp `ServerHandler` into an OAuth 2.1 *resource server*:
//!
//! - serves RFC 9728 Protected Resource Metadata at the path-inserted well-known URL,
//! - answers with the `401`/`403` `WWW-Authenticate` challenges MCP clients use to sign in
//!   and step up,
//! - validates every JWT against a hardened JWKS cache,
//! - enforces declarative per-tool scope and role requirements, deny by default,
//! - hands tool handlers a validated [`Principal`], never the raw token,
//! - mints downstream tokens with Entra On-Behalf-Of (feature `exchange`).
//!
//! mcpward issues no tokens. It is not an authorization server, a gateway, or a session store.
//!
//! ## Modules and features
//!
//! | Module | Feature | Contents |
//! |---|---|---|
//! | [`auth`] | always | Token validation, JWKS cache, claims, challenges, metadata. No rmcp, no axum. |
//! | `server` | `server` (default) | The builder, auth and policy layers, extractors, serving. |
//! | `exchange` | `exchange` (default) | `EntraObo`, `CachedExchanger`, `Downstream`. |
//!
//! `dev-auth` (off by default) adds `Auth::dev`, a local development mode with no token checks.
//!
//! Exactly one of the crypto features `aws-lc-rs` (default) and `rust-crypto` should be on. When
//! both are on, mcpward selects aws-lc-rs.
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(any(feature = "aws-lc-rs", feature = "rust-crypto")))]
compile_error!("mcpward needs a crypto backend: enable the `aws-lc-rs` (default) or `rust-crypto` feature");

pub mod auth;

#[cfg(feature = "exchange")]
pub mod exchange;

#[cfg(feature = "server")]
pub mod server;

mod error;
pub use error::{ConfigError, EnvErrors, Error};

/// Re-export of the rmcp crate mcpward is built against, for non-macro use.
///
/// rmcp's procedural macros emit `rmcp::` paths, so consumers must also depend on `rmcp`
/// directly with a compatible requirement (`"~3.8"`).
#[cfg(feature = "server")]
pub use rmcp;

/// Re-export of the reqwest crate mcpward uses (for `AuthorizedClient` request builders and
/// `Oidc::issuer_config`).
pub use reqwest;

#[cfg(feature = "server")]
pub use server::{
    Auth, AuthBuilder, Caller, McpServer, McpServerBuilder, Policies, ReadinessCheck, RequestMeta, Require, RoleDenial,
    ServeError, ToolFailure, server_info,
};

#[cfg(feature = "server")]
pub use server::docs::{DocEntry, DocsResources};

#[cfg(feature = "dev-auth")]
pub use server::DevIdentity;

pub use auth::{Entra, Oidc, Principal, PrincipalKind, Scope, Subject};

/// The names most servers need, in one import.
pub mod prelude {
    pub use crate::auth::{ClaimPath, Entra, Oidc, Principal, PrincipalKind, Scope, ScopeClaim, Subject, ToolDenied};
    pub use crate::{ConfigError, Error};

    #[cfg(feature = "server")]
    pub use crate::server::docs::{DocEntry, DocsResources};
    #[cfg(feature = "server")]
    pub use crate::server::{
        Auth, AuthBuilder, Caller, McpServer, McpServerBuilder, Policies, RequestMeta, Require, RoleDenial,
        ToolFailure, server_info,
    };
    #[cfg(feature = "server")]
    pub use rmcp::handler::server::wrapper::{Json, Parameters};

    #[cfg(feature = "dev-auth")]
    pub use crate::server::DevIdentity;

    #[cfg(feature = "exchange")]
    pub use crate::exchange::{
        AuthorizedClient, CachedExchanger, ClientCredential, Downstream, DownstreamError, EntraObo, ExchangeError,
        ExchangeTarget, TokenExchanger,
    };
}
