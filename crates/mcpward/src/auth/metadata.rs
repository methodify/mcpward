use serde_json::{Value, json};
use url::Url;

use super::{Scope, jwks::is_loopback_host};
use crate::ConfigError;

/// The canonical MCP URL and everything derived from it.
///
/// mcpward never builds URLs from request headers: `resource`, `resource_metadata`, and the
/// MCP route all come from this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUrl {
    canonical: String,
    origin: String,
    path: String,
    host: String,
    port: Option<u16>,
    loopback: bool,
}

impl ResourceUrl {
    /// Parses and checks a resource URL: `https` (or `http` on loopback, or any host when
    /// `allow_http` is set, for dev mode), no query, fragment, or userinfo, no trailing slash.
    pub fn parse(input: &str, allow_http: bool) -> Result<Self, ConfigError> {
        let bad = |m: String| ConfigError::ResourceUrl(m);
        // `Url::parse` trims whitespace but the raw-path slice below wouldn't, and a non-ASCII
        // URL can't go in a `WWW-Authenticate` header, so refuse both up front.
        if input != input.trim() {
            return Err(bad(format!("{input:?} has leading or trailing whitespace; remove it")));
        }
        if !input.is_ascii() {
            return Err(bad(format!("{input:?} has non-ASCII characters; percent-encode them")));
        }
        let url = Url::parse(input).map_err(|e| bad(format!("{input:?} is not a URL: {e}")))?;
        let loopback = is_loopback_host(&url);
        match url.scheme() {
            "https" => {}
            "http" if loopback || allow_http => {}
            s => return Err(bad(format!("{input:?} uses {s}; use https (http only for loopback)"))),
        }
        if url.query().is_some() || input.contains('?') {
            return Err(bad(format!("{input:?} has a query; remove it")));
        }
        if url.fragment().is_some() || input.contains('#') {
            return Err(bad(format!("{input:?} has a fragment; remove it")));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad(format!("{input:?} has userinfo; remove it")));
        }
        let host = url.host_str().ok_or_else(|| bad(format!("{input:?} has no host")))?.to_ascii_lowercase();
        // Keep the path byte-for-byte as written, after the authority.
        let after_scheme = &input[input.find("://").map(|i| i + 3).unwrap_or(0)..];
        let path = after_scheme.find('/').map(|i| &after_scheme[i..]).unwrap_or("");
        if path.ends_with('/') {
            return Err(bad(format!("{input:?} has a trailing slash; remove it")));
        }
        let port = url.port();
        let origin = match port {
            Some(p) => format!("{}://{host}:{p}", url.scheme()),
            None => format!("{}://{host}", url.scheme()),
        };
        let canonical = format!("{origin}{path}");
        if canonical != input {
            tracing::warn!(target: "mcpward", input, canonical = %canonical, "the resource URL was normalized; clients must use the canonical form, so configure that instead");
        }
        Ok(ResourceUrl { canonical, origin, path: path.to_owned(), host, port, loopback })
    }

    /// The canonical URL, for `resource` and audience matching.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The MCP route: the URL path, or `/` when empty.
    pub fn mcp_path(&self) -> &str {
        if self.path.is_empty() { "/" } else { &self.path }
    }

    /// The RFC 9728 path-inserted metadata path.
    pub fn prm_path(&self) -> String {
        format!("/.well-known/oauth-protected-resource{}", self.path)
    }

    /// The root metadata path.
    pub fn root_prm_path(&self) -> &'static str {
        "/.well-known/oauth-protected-resource"
    }

    /// The absolute metadata URL sent as `resource_metadata`.
    pub fn resource_metadata_url(&self) -> String {
        format!("{}{}", self.origin, self.prm_path())
    }

    /// The host, lowercased.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether the host is `localhost` or a loopback IP.
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// The `Host` values to accept: the host, and `host:port` when a port is set.
    pub fn allowed_hosts(&self) -> Vec<String> {
        let mut v = vec![self.host.clone()];
        if let Some(p) = self.port {
            v.push(format!("{}:{p}", self.host));
        }
        v
    }
}

/// An RFC 9728 Protected Resource Metadata document.
#[derive(Clone, Debug)]
pub struct ResourceMetadata {
    /// The resource URL.
    pub resource: ResourceUrl,
    /// The one authorization server (issuer) clients should use.
    pub authorization_server: String,
    /// Scopes to advertise, in challenge form.
    pub scopes_supported: Vec<Scope>,
    /// Optional human-readable name.
    pub resource_name: Option<String>,
    /// Optional documentation URL.
    pub resource_documentation: Option<String>,
    /// Also serve at the root well-known path (deviates from RFC 9728 §3.3).
    pub serve_root: bool,
}

impl ResourceMetadata {
    /// The JSON document.
    pub fn to_json(&self) -> Value {
        let mut scopes: Vec<&str> = Vec::new();
        for s in &self.scopes_supported {
            if !scopes.contains(&s.challenge()) {
                scopes.push(s.challenge());
            }
        }
        let mut doc = json!({
            "resource": self.resource.as_str(),
            "authorization_servers": [self.authorization_server],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
        });
        if let Some(n) = &self.resource_name {
            doc["resource_name"] = json!(n);
        }
        if let Some(d) = &self.resource_documentation {
            doc["resource_documentation"] = json!(d);
        }
        doc
    }

    /// The paths this document is served at.
    pub fn well_known_paths(&self) -> Vec<String> {
        let mut v = vec![self.resource.prm_path()];
        let root = self.resource.root_prm_path().to_owned();
        if (self.serve_root || self.resource.path.is_empty()) && !v.contains(&root) {
            v.push(root);
        }
        v
    }
}

/// Dev mode only accepts `localhost`, loopback IPs, and single-label hosts (compose service
/// names), whatever overrides are set.
#[cfg(feature = "dev-auth")]
pub(crate) fn check_dev_host(r: &ResourceUrl) -> Result<(), ConfigError> {
    let single_label = !r.host.contains('.') && !r.host.contains(':') && !r.host.starts_with('[');
    if r.loopback || single_label {
        Ok(())
    } else {
        Err(ConfigError::ResourceUrl(format!(
            "dev auth mode refuses resource host {:?}; use localhost, a loopback address, or a single-label name",
            r.host
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_paths() {
        let r = ResourceUrl::parse("https://MCP.example.com/mcp", false).unwrap();
        assert_eq!(r.as_str(), "https://mcp.example.com/mcp");
        assert_eq!(r.mcp_path(), "/mcp");
        assert_eq!(r.prm_path(), "/.well-known/oauth-protected-resource/mcp");
        assert_eq!(r.resource_metadata_url(), "https://mcp.example.com/.well-known/oauth-protected-resource/mcp");
        assert_eq!(r.allowed_hosts(), vec!["mcp.example.com"]);
        let r = ResourceUrl::parse("https://mcp.example.com", false).unwrap();
        assert_eq!(r.mcp_path(), "/");
        assert_eq!(r.prm_path(), "/.well-known/oauth-protected-resource");
        let r = ResourceUrl::parse("http://localhost:8080/a/b", false).unwrap();
        assert_eq!(r.allowed_hosts(), vec!["localhost", "localhost:8080"]);
    }

    #[test]
    fn rejects_bad_urls() {
        for bad in [
            "https://mcp.example.com/mcp/",
            "https://mcp.example.com/",
            "https://mcp.example.com/mcp?x=1",
            "https://mcp.example.com/mcp#f",
            "https://u:p@mcp.example.com/mcp",
            "http://mcp.example.com/mcp",
            "ftp://mcp.example.com/mcp",
        ] {
            assert!(ResourceUrl::parse(bad, false).is_err(), "{bad}");
        }
        assert!(ResourceUrl::parse("http://mcp/mcp", true).is_ok());
    }

    #[test]
    fn prm_document() {
        let m = ResourceMetadata {
            resource: ResourceUrl::parse("https://mcp.example.com/mcp", false).unwrap(),
            authorization_server: "https://login.example.com/".into(),
            scopes_supported: vec![Scope::new("a").with_challenge("api://x/a")],
            resource_name: Some("Example".into()),
            resource_documentation: None,
            serve_root: false,
        };
        let j = m.to_json();
        assert_eq!(j["resource"], "https://mcp.example.com/mcp");
        assert_eq!(j["scopes_supported"][0], "api://x/a");
        assert_eq!(m.well_known_paths().len(), 1);
    }
}
