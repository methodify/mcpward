use std::{collections::BTreeSet, fmt, sync::Arc, time::SystemTime};

use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// The stable identity of a caller.
///
/// Use [`Subject::key`] for authorization, audit, and data ownership. Display fields on
/// [`Principal`] can change and must never be used for those.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Subject {
    issuer: String,
    tenant: Option<String>,
    id: String,
    key: String,
}

impl Subject {
    /// Creates a subject. With a tenant the key is `"<tenant>:<id>"`; without, it's `"<id>"`.
    pub fn new(issuer: impl Into<String>, tenant: Option<String>, id: impl Into<String>) -> Self {
        let id = id.into();
        let key = match &tenant {
            Some(t) => format!("{t}:{id}"),
            None => id.clone(),
        };
        Subject { issuer: issuer.into(), tenant, id, key }
    }

    /// The token issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The tenant (Entra `tid`), if subjects are tenant-scoped.
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// The user ID (Entra `oid`, generic `sub`).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Stable key for authorization, audit, and data ownership.
    /// Entra: `"<tid>:<oid>"`. Generic: `"<sub>"`.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// What kind of caller a principal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrincipalKind {
    /// A user, through a delegated token.
    User,
    /// An application with an app-only token (only when app tokens are allowed).
    Application,
    /// The development identity from `Auth::dev`.
    Dev,
}

/// A validated caller. Handlers receive this, never the raw token.
#[derive(Clone)]
pub struct Principal {
    /// Stable identity.
    pub subject: Subject,
    /// The client application (Entra `azp`; generic `azp`, `client_id`, or `cid`).
    pub client_id: Option<String>,
    /// Scopes in claim form.
    pub scopes: BTreeSet<String>,
    /// Roles from the configured role claims.
    pub roles: BTreeSet<String>,
    /// Display name. Never use for authorization.
    pub name: Option<String>,
    /// Username or email. Display only.
    pub username: Option<String>,
    /// Token issue time.
    pub issued_at: Option<SystemTime>,
    /// Token expiry.
    pub expires_at: SystemTime,
    /// Token ID (`uti` or `jti`) for log correlation.
    pub token_id: Option<String>,
    /// User, application, or dev.
    pub kind: PrincipalKind,
    claims: Arc<Map<String, Value>>,
}

impl Principal {
    /// Creates a principal with no scopes, roles, or claims. For custom
    /// [`TokenValidator`](super::TokenValidator)s and tests.
    pub fn new(subject: Subject, kind: PrincipalKind, expires_at: SystemTime) -> Self {
        Principal {
            subject,
            client_id: None,
            scopes: BTreeSet::new(),
            roles: BTreeSet::new(),
            name: None,
            username: None,
            issued_at: None,
            expires_at,
            token_id: None,
            kind,
            claims: Arc::new(Map::new()),
        }
    }

    /// Sets the verified claims map.
    pub fn with_claims(mut self, claims: Map<String, Value>) -> Self {
        self.claims = Arc::new(claims);
        self
    }

    /// Whether the token carries this scope (claim form).
    pub fn has_scope(&self, s: &str) -> bool {
        self.scopes.contains(s)
    }

    /// Whether the caller has this role.
    pub fn has_role(&self, r: &str) -> bool {
        self.roles.contains(r)
    }

    /// Returns [`ToolDenied`] unless the caller has the role. `?` turns it into an in-band
    /// tool error in a handler that returns `Result<_, ToolFailure>`.
    pub fn require_role(&self, r: &str) -> Result<(), ToolDenied> {
        if self.has_role(r) { Ok(()) } else { Err(ToolDenied::role(r)) }
    }

    /// Returns [`ToolDenied`] unless the token carries the scope.
    pub fn require_scope(&self, s: &str) -> Result<(), ToolDenied> {
        if self.has_scope(s) { Ok(()) } else { Err(ToolDenied::scope(s)) }
    }

    /// Reads any verified claim. An escape hatch: prefer the typed fields.
    pub fn claim<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.claims.get(name).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// All verified claims.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Claims can hold email and other personal data, so they're left out.
        f.debug_struct("Principal")
            .field("subject", &self.subject.key())
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("roles", &self.roles)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// The caller's access token, held only for token exchange.
///
/// mcpward never hands this to tool handlers. A custom
/// [`TokenExchanger`](crate::exchange::TokenExchanger) receives one as an argument. `Debug`
/// prints `[redacted]`.
#[derive(Clone)]
pub struct SubjectToken(SecretString);

impl SubjectToken {
    /// Wraps a token. mcpward creates these itself; this exists for testing custom
    /// [`TokenExchanger`](crate::exchange::TokenExchanger)s. Constructing one from a string
    /// you already hold exposes nothing.
    pub fn new(token: &str) -> Self {
        SubjectToken(SecretString::from(token.to_owned()))
    }

    /// The raw token. Only for sending to a token endpoint.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SubjectToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SubjectToken([redacted])")
    }
}

/// A handler-level authorization failure, from [`Principal::require_role`] and friends.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ToolDenied {
    /// The role that was required, if any.
    pub role: Option<String>,
    /// The scope that was required, if any.
    pub scope: Option<String>,
    /// User-facing text.
    pub message: String,
}

impl ToolDenied {
    /// Denied for lack of a role.
    pub fn role(role: &str) -> Self {
        ToolDenied {
            role: Some(role.to_owned()),
            scope: None,
            message: format!(
                "You don't have permission to do this. It requires the `{role}` role. Ask an administrator to assign it to you, then reconnect."
            ),
        }
    }

    /// Denied for lack of a scope.
    pub fn scope(scope: &str) -> Self {
        ToolDenied {
            role: None,
            scope: Some(scope.to_owned()),
            message: format!("You don't have permission to do this. It requires the `{scope}` scope."),
        }
    }

    /// Denied with custom text.
    pub fn message(message: impl Into<String>) -> Self {
        ToolDenied { role: None, scope: None, message: message.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn subject_keys() {
        assert_eq!(Subject::new("i", Some("t".into()), "o").key(), "t:o");
        assert_eq!(Subject::new("i", None, "s").key(), "s");
    }

    #[test]
    fn debug_hides_claims_and_tokens() {
        let mut claims = Map::new();
        claims.insert("email".into(), Value::String("person@example.com".into()));
        let p = Principal::new(
            Subject::new("i", None, "s"),
            PrincipalKind::User,
            SystemTime::now() + Duration::from_secs(5),
        )
        .with_claims(claims);
        assert!(!format!("{p:?}").contains("person@example.com"));
        assert!(!format!("{:?}", SubjectToken::new("secret-token")).contains("secret-token"));
        assert!(p.require_role("x").is_err());
    }
}
