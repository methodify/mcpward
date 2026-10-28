use http::{HeaderValue, StatusCode};
use serde_json::{Value, json};

use super::{RejectReason, Scope};

/// What a challenge needs to know about the server.
#[derive(Clone, Debug)]
pub struct ChallengeContext {
    /// The absolute Protected Resource Metadata URL.
    pub resource_metadata: String,
    /// The base scopes every token needs.
    pub base_scopes: Vec<Scope>,
}

/// An authentication or authorization failure, rendered as status, `WWW-Authenticate`, and a
/// JSON body.
///
/// Parameters are written in a fixed order: `resource_metadata`, `scope`, `error`,
/// `error_description`. Descriptions are fixed phrases, never token content.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Challenge {
    /// No token, or a non-Bearer scheme. `401`.
    Unauthorized,
    /// The token was refused. `401 invalid_token`.
    InvalidToken(RejectReason),
    /// The token lacks scopes. `403 insufficient_scope`; `scopes` is every scope needed.
    InsufficientScope {
        /// All scopes the operation needs, base scopes included.
        scopes: Vec<Scope>,
    },
    /// The client application isn't allowed. Terminal `403` with no challenge.
    ClientNotAllowed,
    /// The token was sent somewhere other than the `Authorization` header. `400`.
    InvalidRequest,
}

fn quote(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn scope_list(scopes: &[Scope]) -> String {
    let mut seen = Vec::<&str>::new();
    for s in scopes {
        if !seen.contains(&s.challenge()) {
            seen.push(s.challenge());
        }
    }
    seen.join(" ")
}

impl Challenge {
    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        match self {
            Challenge::Unauthorized | Challenge::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Challenge::InsufficientScope { .. } | Challenge::ClientNotAllowed => StatusCode::FORBIDDEN,
            Challenge::InvalidRequest => StatusCode::BAD_REQUEST,
        }
    }

    fn error_code(&self) -> Option<&'static str> {
        match self {
            Challenge::Unauthorized => None,
            Challenge::InvalidToken(_) => Some("invalid_token"),
            Challenge::InsufficientScope { .. } => Some("insufficient_scope"),
            Challenge::ClientNotAllowed => Some("client_not_allowed"),
            Challenge::InvalidRequest => Some("invalid_request"),
        }
    }

    fn description(&self) -> Option<&'static str> {
        match self {
            Challenge::InvalidToken(r) => Some(r.description()),
            Challenge::InsufficientScope { .. } => Some(RejectReason::InsufficientScope.description()),
            Challenge::ClientNotAllowed => Some(RejectReason::ClientNotAllowed.description()),
            _ => None,
        }
    }

    /// The `WWW-Authenticate` value, or `None` for [`Challenge::ClientNotAllowed`].
    pub fn www_authenticate(&self, ctx: &ChallengeContext) -> Option<HeaderValue> {
        let mut params: Vec<(&str, String)> = Vec::new();
        match self {
            Challenge::ClientNotAllowed => return None,
            Challenge::InvalidRequest => {
                params.push(("error", "invalid_request".into()));
            }
            _ => {
                params.push(("resource_metadata", ctx.resource_metadata.clone()));
                let scopes = match self {
                    Challenge::InsufficientScope { scopes } => scope_list(scopes),
                    _ => scope_list(&ctx.base_scopes),
                };
                if !scopes.is_empty() {
                    params.push(("scope", scopes));
                }
                if let Some(code) = self.error_code() {
                    params.push(("error", code.into()));
                }
                if let Some(d) = self.description() {
                    params.push(("error_description", d.into()));
                }
            }
        }
        let rendered = params.iter().map(|(k, v)| format!("{k}={}", quote(v))).collect::<Vec<_>>().join(", ");
        HeaderValue::from_str(&format!("Bearer {rendered}")).ok()
    }

    /// The JSON body.
    pub fn body(&self) -> Value {
        match (self.error_code(), self.description()) {
            (None, _) => json!({"error": "unauthorized"}),
            (Some(code), Some(d)) => json!({"error": code, "error_description": d}),
            (Some(code), None) => json!({"error": code}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ChallengeContext {
        ChallengeContext {
            resource_metadata: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp".into(),
            base_scopes: vec![
                Scope::new("access_as_user")
                    .with_challenge("api://00000000-0000-0000-0000-000000000002/access_as_user"),
            ],
        }
    }

    #[test]
    fn unauthorized_exact() {
        let h = Challenge::Unauthorized.www_authenticate(&ctx()).unwrap();
        assert_eq!(
            h,
            r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="api://00000000-0000-0000-0000-000000000002/access_as_user""#
        );
        assert_eq!(Challenge::Unauthorized.status(), 401);
    }

    #[test]
    fn invalid_token_order() {
        let h = Challenge::InvalidToken(RejectReason::Expired).www_authenticate(&ctx()).unwrap();
        assert!(
            h.to_str().unwrap().ends_with(r#", error="invalid_token", error_description="The access token expired""#)
        );
    }

    #[test]
    fn insufficient_scope_lists_all() {
        let c = Challenge::InsufficientScope { scopes: vec![Scope::new("a"), Scope::new("b"), Scope::new("a")] };
        let h = c.www_authenticate(&ctx()).unwrap();
        assert!(h.to_str().unwrap().contains(r#"scope="a b", error="insufficient_scope""#));
        assert_eq!(c.status(), 403);
    }

    #[test]
    fn client_not_allowed_has_no_challenge() {
        assert!(Challenge::ClientNotAllowed.www_authenticate(&ctx()).is_none());
        assert_eq!(Challenge::ClientNotAllowed.body()["error"], "client_not_allowed");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
