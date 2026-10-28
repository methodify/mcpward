use std::fmt;

/// A configuration problem found while building a validator, server, or exchanger.
///
/// mcpward fails closed: anything ambiguous or unsafe in the configuration is an error at
/// startup, not a warning at request time.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Neither `required_scopes` (non-empty) nor `no_required_scopes()` was called.
    #[error(
        "no required scopes: call required_scopes([...]) or, to accept tokens without scopes, no_required_scopes()"
    )]
    NoRequiredScopes,
    /// Neither `allowed_clients` (non-empty) nor `allow_any_client()` was called.
    #[error("no client allowlist: call allowed_clients([...]) or, to accept any client, allow_any_client()")]
    NoClientAllowlist,
    /// A router tool has no policy and no default policy is set.
    #[error("tool `{name}` has no policy; add one with Policies::tool or set Policies::default")]
    UnpolicedTool {
        /// The tool or prompt name.
        name: String,
    },
    /// A policy names a tool or prompt the declared routers don't have.
    #[error("policy names `{name}`, which no declared router has (typo?)")]
    UnknownPolicyTarget {
        /// The name in the policy.
        name: String,
    },
    /// `.tools(&router)` was not called, so the policy table can't be checked.
    #[error("call .tools(&Handler::tool_router()) so mcpward can check every tool has a policy")]
    RoutersNotDeclared,
    /// No authentication was configured.
    #[error("no authentication configured: call .auth(Auth::entra(..)) or similar")]
    NoAuth,
    /// The resource URL is missing or invalid.
    #[error("resource URL: {0}")]
    ResourceUrl(String),
    /// A value is invalid.
    #[error("{field}: {reason}")]
    Invalid {
        /// The setting.
        field: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// The JWKS could not be loaded at startup.
    #[error("could not load signing keys from {uri}: {reason}")]
    JwksUnavailable {
        /// The JWKS URI.
        uri: String,
        /// Why the load failed.
        reason: String,
    },
    /// OIDC discovery failed.
    #[error("OIDC discovery for {issuer} failed: {reason}")]
    Discovery {
        /// The configured issuer.
        issuer: String,
        /// Why discovery failed.
        reason: String,
    },
    /// One or more environment variables are invalid.
    #[error("{0}")]
    Env(EnvErrors),
}

impl ConfigError {
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        ConfigError::Invalid { field, reason: reason.into() }
    }
}

/// Every problem found in the environment, each with the variable name.
#[derive(Debug, Clone, Default)]
pub struct EnvErrors {
    /// `(variable, problem)` pairs, in the order found.
    pub problems: Vec<(String, String)>,
}

impl fmt::Display for EnvErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mcpward configuration is invalid:")?;
        for (i, (var, problem)) in self.problems.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "  {var}: {problem}")?;
        }
        Ok(())
    }
}

/// Top-level error for `main` functions: configuration or serving.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The server failed while running.
    #[cfg(feature = "server")]
    #[error(transparent)]
    Serve(#[from] crate::server::ServeError),
    /// Anything else, for example a consumer's own setup code.
    #[error("{0}")]
    Other(String),
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::Other(format!("invalid URL: {e}"))
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::Other(format!("invalid address: {e}"))
    }
}

#[cfg(feature = "exchange")]
impl From<crate::exchange::ExchangeError> for Error {
    fn from(e: crate::exchange::ExchangeError) -> Self {
        Error::Other(e.to_string())
    }
}
