use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// A path to a claim: dotted segments into nested objects (`realm_access.roles`), or one
/// literal name that may itself contain dots ([`ClaimPath::literal`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimPath {
    segments: Vec<String>,
}

impl ClaimPath {
    /// Parses a dotted path. `resource_access.app.roles` has three segments.
    pub fn dotted(path: &str) -> Self {
        ClaimPath { segments: path.split('.').map(str::to_owned).collect() }
    }

    /// A single claim name, taken literally even when it contains dots.
    pub fn literal(name: impl Into<String>) -> Self {
        ClaimPath { segments: vec![name.into()] }
    }

    /// Looks the path up in a claims object.
    pub fn get<'a>(&self, claims: &'a Map<String, Value>) -> Option<&'a Value> {
        let (first, rest) = self.segments.split_first()?;
        let mut v = claims.get(first)?;
        for seg in rest {
            v = v.as_object()?.get(seg)?;
        }
        Some(v)
    }

    /// The path as written, segments joined with dots.
    pub fn display(&self) -> String {
        self.segments.join(".")
    }
}

impl From<&str> for ClaimPath {
    fn from(s: &str) -> Self {
        ClaimPath::dotted(s)
    }
}

impl From<String> for ClaimPath {
    fn from(s: String) -> Self {
        ClaimPath::dotted(&s)
    }
}

/// Where and how scopes appear in the token.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeClaim {
    /// One space-separated string (`scp` in Entra, `scope` in OAuth).
    SpaceSeparated(String),
    /// A JSON array of strings (`scp` in Okta).
    Array(String),
    /// Try `scope` and then `scp`, each as a string or an array.
    Auto,
}

impl ScopeClaim {
    pub(crate) fn parse(&self, claims: &Map<String, Value>) -> BTreeSet<String> {
        fn from_value(v: Option<&Value>, allow_string: bool, allow_array: bool) -> Option<BTreeSet<String>> {
            match v? {
                Value::String(s) if allow_string => {
                    Some(s.split(' ').filter(|p| !p.is_empty()).map(str::to_owned).collect())
                }
                Value::Array(items) if allow_array => {
                    Some(items.iter().filter_map(|i| i.as_str()).map(str::to_owned).collect())
                }
                _ => None,
            }
        }
        match self {
            ScopeClaim::SpaceSeparated(name) => from_value(claims.get(name), true, false),
            ScopeClaim::Array(name) => from_value(claims.get(name), false, true),
            ScopeClaim::Auto => {
                from_value(claims.get("scope"), true, true).or_else(|| from_value(claims.get("scp"), true, true))
            }
        }
        .unwrap_or_default()
    }

    pub(crate) fn is_present(&self, claims: &Map<String, Value>) -> bool {
        match self {
            ScopeClaim::SpaceSeparated(n) | ScopeClaim::Array(n) => claims.contains_key(n),
            ScopeClaim::Auto => claims.contains_key("scope") || claims.contains_key("scp"),
        }
    }
}

/// A claim that must equal a fixed string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEquals {
    /// The claim name.
    pub claim: String,
    /// The required value.
    pub value: String,
}

impl ClaimEquals {
    /// `claim == value`.
    pub fn new(claim: impl Into<String>, value: impl Into<String>) -> Self {
        ClaimEquals { claim: claim.into(), value: value.into() }
    }

    pub(crate) fn matches(&self, claims: &Map<String, Value>) -> bool {
        claims.get(&self.claim).and_then(Value::as_str) == Some(self.value.as_str())
    }
}

/// Which claims identify the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectClaims {
    /// The user ID claim (Entra `oid`, generic `sub`).
    pub id: String,
    /// The tenant claim, if subjects are scoped by tenant (Entra `tid`).
    pub tenant: Option<String>,
}

/// How mcpward reads a validated token's claims into a [`Principal`](super::Principal).
#[derive(Clone, Debug)]
pub struct ClaimMap {
    /// Subject claims.
    pub subject: SubjectClaims,
    /// Client ID claims, tried in order; the first present wins.
    pub client_id: Vec<String>,
    /// Scope claim.
    pub scopes: ScopeClaim,
    /// Role claims; values are unioned.
    pub roles: Vec<ClaimPath>,
    /// Display name claim.
    pub name: Option<String>,
    /// Username claims, tried in order (display only).
    pub username: Vec<String>,
    /// Token ID claims, tried in order (for log correlation).
    pub token_id: Vec<String>,
    /// Entra-style app-only token detection (`idtyp == "app"`, or `roles` without `scp`).
    pub entra_app_detection: bool,
}

impl ClaimMap {
    /// Defaults for a generic OIDC provider.
    pub fn generic() -> Self {
        ClaimMap {
            subject: SubjectClaims { id: "sub".into(), tenant: None },
            client_id: vec!["azp".into(), "client_id".into(), "cid".into()],
            scopes: ScopeClaim::Auto,
            roles: vec![ClaimPath::dotted("roles")],
            name: Some("name".into()),
            username: vec!["preferred_username".into(), "email".into()],
            token_id: vec!["jti".into()],
            entra_app_detection: false,
        }
    }

    /// Defaults for Microsoft Entra ID v2 access tokens.
    pub fn entra() -> Self {
        ClaimMap {
            subject: SubjectClaims { id: "oid".into(), tenant: Some("tid".into()) },
            client_id: vec!["azp".into()],
            scopes: ScopeClaim::SpaceSeparated("scp".into()),
            roles: vec![ClaimPath::dotted("roles")],
            name: Some("name".into()),
            username: vec!["preferred_username".into(), "email".into()],
            token_id: vec!["uti".into(), "jti".into()],
            entra_app_detection: true,
        }
    }

    pub(crate) fn roles(&self, claims: &Map<String, Value>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for path in &self.roles {
            match path.get(claims) {
                Some(Value::Array(items)) => out.extend(items.iter().filter_map(Value::as_str).map(str::to_owned)),
                Some(Value::String(s)) => out.extend(s.split(' ').filter(|p| !p.is_empty()).map(str::to_owned)),
                _ => {}
            }
        }
        out
    }

    pub(crate) fn first_str(names: &[String], claims: &Map<String, Value>) -> Option<String> {
        names.iter().find_map(|n| claims.get(n).and_then(Value::as_str).filter(|s| !s.is_empty())).map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn dotted_and_literal_paths() {
        let c = obj(json!({"realm_access": {"roles": ["a"]}, "cognito:groups": ["g"], "a.b": 1}));
        assert_eq!(ClaimPath::dotted("realm_access.roles").get(&c), Some(&json!(["a"])));
        assert_eq!(ClaimPath::literal("a.b").get(&c), Some(&json!(1)));
        assert_eq!(ClaimPath::dotted("a.b").get(&c), None);
    }

    #[test]
    fn scope_forms() {
        let c = obj(json!({"scp": "a b  c", "scope": ["x", "y"]}));
        assert_eq!(ScopeClaim::SpaceSeparated("scp".into()).parse(&c).len(), 3);
        assert!(ScopeClaim::Array("scp".into()).parse(&c).is_empty());
        let auto = ScopeClaim::Auto.parse(&c);
        assert!(auto.contains("x") && auto.contains("y"));
    }

    #[test]
    fn roles_union() {
        let mut m = ClaimMap::generic();
        m.roles = vec!["roles".into(), "groups".into()];
        let c = obj(json!({"roles": ["r1"], "groups": ["g1", "r1"]}));
        assert_eq!(m.roles(&c).len(), 2);
    }
}
