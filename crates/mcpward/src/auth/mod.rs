//! Token validation for an OAuth 2.1 resource server: JWKS cache, JWT checks, claims,
//! `WWW-Authenticate` challenges, and RFC 9728 Protected Resource Metadata.
//!
//! This module has no rmcp or axum dependency. A service that only needs the validator can
//! depend on `mcpward` with `default-features = false` and a crypto feature.

mod challenge;
mod claims;
mod crypto;
mod jwks;
mod metadata;
mod principal;
mod providers;
mod scope;
mod validator;

pub use challenge::{Challenge, ChallengeContext};
pub use claims::{ClaimEquals, ClaimMap, ClaimPath, ScopeClaim, SubjectClaims};
pub use crypto::ensure_crypto_provider;
#[cfg(feature = "exchange")]
pub(crate) use jwks::check_https_or_loopback as check_https_or_loopback_pub;
#[cfg(feature = "server")]
pub(crate) use jwks::truncate as truncate_for_log;
pub use jwks::{JwkSet, JwksCache, JwksConfig, JwksError, KeySource, StartupPolicy, StaticKeys};
#[cfg(feature = "dev-auth")]
pub(crate) use metadata::check_dev_host as metadata_check_dev_host;
pub use metadata::{ResourceMetadata, ResourceUrl};
pub use principal::{Principal, PrincipalKind, Subject, SubjectToken, ToolDenied};
#[cfg(feature = "server")]
pub(crate) use providers::is_guid as providers_is_guid;
pub use providers::{Entra, JwksSource, Oidc};
pub use scope::Scope;
pub use validator::{
    AuthError, ClaimCheck, IssuerConfig, JwtValidator, JwtValidatorBuilder, RejectReason, TokenValidator,
};

pub use jsonwebtoken::Algorithm;

/// A boxed, `Send` future, used by mcpward's object-safe traits.
pub type BoxFuture<'a, T> = futures_util::future::BoxFuture<'a, T>;
