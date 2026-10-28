//! Downstream calls as the user: token exchange (Entra On-Behalf-Of), a per-user cache, and
//! an HTTP client that only sends the downstream token to its configured host.
//!
//! There is no way to forward the incoming token. The MCP specification forbids passing it
//! through, and mcpward only hands it to a [`TokenExchanger`].

mod cache;
#[cfg(feature = "dev-auth")]
mod dev;
mod downstream;
mod obo;

use std::{fmt, time::SystemTime};

use secrecy::{ExposeSecret, SecretString};

pub use cache::CachedExchanger;
#[cfg(feature = "dev-auth")]
pub use dev::{NoAuth, StaticToken};
pub use downstream::{AuthorizedClient, Downstream, DownstreamBuilder, DownstreamError};
pub use obo::{ClientCredential, EntraObo, EntraOboBuilder};

use crate::auth::{BoxFuture, Principal, SubjectToken};

/// Which downstream API a token is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeTarget {
    /// Logical name for logs and the cache key, for example `orders-api`.
    pub name: &'static str,
    /// Scopes to request, for example `["api://<downstream>/access_as_user"]`.
    pub scopes: Vec<String>,
}

/// A token for a downstream API.
#[derive(Clone)]
pub struct DownstreamToken {
    token: SecretString,
    /// When the token expires.
    pub expires_at: SystemTime,
    /// Granted scopes, if the token endpoint said.
    pub scopes: Option<String>,
}

impl DownstreamToken {
    /// Wraps a token.
    pub fn new(token: impl Into<String>, expires_at: SystemTime) -> Self {
        DownstreamToken { token: SecretString::from(token.into()), expires_at, scopes: None }
    }

    /// The raw token, for the `Authorization` header.
    pub fn expose_secret(&self) -> &str {
        self.token.expose_secret()
    }
}

impl fmt::Debug for DownstreamToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownstreamToken").field("token", &"[redacted]").field("expires_at", &self.expires_at).finish()
    }
}

/// Exchanges the caller's token for a downstream token.
pub trait TokenExchanger: Send + Sync + 'static {
    /// Exchanges `subject` (the caller's validated token) for a token for `target`.
    fn exchange<'a>(
        &'a self,
        principal: &'a Principal,
        subject: &'a SubjectToken,
        target: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>>;

    /// Whether this exchanger needs the caller's real token. `false` only for the dev-mode
    /// exchangers.
    fn requires_user_token(&self) -> bool {
        true
    }

    /// A short name for logs.
    fn kind(&self) -> &'static str {
        "custom"
    }
}

/// Supplies a JWT the token endpoint accepts as `client_assertion`, for example a federated
/// managed-identity token.
pub trait ClientAssertionSource: Send + Sync + 'static {
    /// The current assertion.
    fn assertion(&self) -> BoxFuture<'_, Result<SecretString, ExchangeError>>;
}

/// Why an exchange failed. Converts into a [`ToolFailure`](crate::ToolFailure) with a
/// user-actionable message; the raw Entra error codes are kept for refinement.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExchangeError {
    /// MFA or Conditional Access on the downstream API.
    #[error("interaction required (codes {codes:?})")]
    InteractionRequired {
        /// Entra `error_codes`.
        codes: Vec<u32>,
    },
    /// The server isn't consented to call the downstream API for the user.
    #[error("consent required (codes {codes:?})")]
    ConsentRequired {
        /// Entra `error_codes`.
        codes: Vec<u32>,
    },
    /// The user's grant or session was revoked.
    #[error("session revoked (codes {codes:?})")]
    SessionRevoked {
        /// Entra `error_codes`.
        codes: Vec<u32>,
    },
    /// Configuration fault: bad credential, unknown client, audience mismatch, and any
    /// unrecognized `invalid_grant`.
    #[error("exchange misconfigured: {detail} (codes {codes:?})")]
    Misconfigured {
        /// Entra `error_codes`.
        codes: Vec<u32>,
        /// Operator-facing detail (never shown to users).
        detail: String,
    },
    /// Network failure, timeout, `5xx`, or `temporarily_unavailable`.
    #[error("token endpoint unavailable: {0}")]
    Unavailable(String),
}

impl ExchangeError {
    pub(crate) fn misconfigured(detail: impl Into<String>) -> Self {
        ExchangeError::Misconfigured { codes: Vec::new(), detail: detail.into() }
    }

    /// A snake_case code.
    pub fn code(&self) -> &'static str {
        match self {
            ExchangeError::InteractionRequired { .. } => "interaction_required",
            ExchangeError::ConsentRequired { .. } => "consent_required",
            ExchangeError::SessionRevoked { .. } => "session_revoked",
            ExchangeError::Misconfigured { .. } => "server_misconfigured",
            ExchangeError::Unavailable(_) => "sign_in_unavailable",
        }
    }

    /// The default user-facing message.
    pub fn user_message(&self) -> &'static str {
        match self {
            ExchangeError::InteractionRequired { .. } => {
                "The downstream service needs extra sign-in verification. Disconnect and reconnect this connector, then try again."
            }
            ExchangeError::ConsentRequired { .. } => {
                "This server isn't approved to call the downstream service for you. An administrator needs to grant consent."
            }
            ExchangeError::SessionRevoked { .. } => {
                "Your sign-in is no longer valid. Disconnect and reconnect this connector."
            }
            ExchangeError::Misconfigured { .. } => "The server isn't configured correctly. Contact its administrator.",
            ExchangeError::Unavailable(_) => "The sign-in service is unavailable. Try again shortly.",
        }
    }

    /// The Entra error codes, if any.
    pub fn codes(&self) -> &[u32] {
        match self {
            ExchangeError::InteractionRequired { codes }
            | ExchangeError::ConsentRequired { codes }
            | ExchangeError::SessionRevoked { codes }
            | ExchangeError::Misconfigured { codes, .. } => codes,
            ExchangeError::Unavailable(_) => &[],
        }
    }
}

impl From<ExchangeError> for crate::ToolFailure {
    fn from(e: ExchangeError) -> Self {
        crate::ToolFailure::new(e.code(), e.user_message())
    }
}

impl crate::server::Caller {
    /// Exchanges (or reuses a cached token) and returns a client bound to the downstream
    /// API's base URL.
    pub async fn client<'a>(&'a self, api: &'a Downstream) -> Result<AuthorizedClient<'a>, ExchangeError> {
        let principal = self.principal();
        let dev = principal.kind == crate::auth::PrincipalKind::Dev;
        let needs_user = api.requires_user_token();
        if dev && needs_user {
            return Err(ExchangeError::misconfigured("dev auth mode has no user token to exchange"));
        }
        if !dev && !needs_user {
            return Err(ExchangeError::misconfigured("dev-only exchanger used outside dev auth mode"));
        }
        let token = api.token_for(principal, self.subject_token()).await?;
        Ok(api.authorized(token, self.meta()))
    }
}
