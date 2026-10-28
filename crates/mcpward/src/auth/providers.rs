use std::collections::BTreeSet;

use serde_json::Value;
use url::Url;

use super::{
    ClaimEquals, ClaimMap, ClaimPath, IssuerConfig, JwksConfig, Scope, ScopeClaim,
    jwks::{check_https_or_loopback, read_capped},
};
use crate::ConfigError;

const ENTRA_AUTHORITY: &str = "https://login.microsoftonline.com";

pub(crate) fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Microsoft Entra ID (single tenant, v2 access tokens).
///
/// | Setting | Value |
/// |---|---|
/// | Issuer | `https://login.microsoftonline.com/{tenant}/v2.0` |
/// | JWKS | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
/// | Audiences | API client ID, `api://{client-id}`, each extra Application ID URI, the resource URL |
/// | Checks | `tid == tenant`, `ver == "2.0"`, `nbf` required, app-only tokens refused |
/// | Subject | `tid` + `oid` |
/// | Client | `azp` |
/// | Scopes | `scp`, space-separated |
/// | Roles | `roles` |
#[derive(Clone, Debug)]
pub struct Entra {
    /// The directory (tenant) ID, a GUID. `common`, `organizations`, and `consumers` are refused.
    pub tenant_id: String,
    /// The API registration's application (client) ID, a GUID.
    pub api_client_id: String,
    /// Extra Application ID URIs to accept as audiences. The resource URL is added automatically.
    pub app_id_uris: Vec<String>,
    /// Prefix that turns a short scope into its challenge form. Default `api://{client-id}/`.
    pub scope_prefix: Option<String>,
}

impl Entra {
    /// A tenant and API registration. GUIDs are stored in lowercase, the form Entra writes
    /// in tokens.
    pub fn new(tenant_id: impl Into<String>, api_client_id: impl Into<String>) -> Self {
        Entra {
            tenant_id: tenant_id.into().trim().to_ascii_lowercase(),
            api_client_id: api_client_id.into().trim().to_ascii_lowercase(),
            app_id_uris: Vec::new(),
            scope_prefix: None,
        }
    }

    /// Adds an Application ID URI to accept as an audience.
    pub fn app_id_uri(mut self, uri: impl Into<String>) -> Self {
        self.app_id_uris.push(uri.into());
        self
    }

    /// Overrides the scope prefix.
    pub fn scope_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.scope_prefix = Some(prefix.into());
        self
    }

    fn check(&self) -> Result<(), ConfigError> {
        if matches!(self.tenant_id.as_str(), "common" | "organizations" | "consumers") {
            return Err(ConfigError::invalid(
                "entra.tenant_id",
                "multi-tenant authorities are not supported; use your tenant ID",
            ));
        }
        if !is_guid(&self.tenant_id) {
            return Err(ConfigError::invalid("entra.tenant_id", format!("{:?} is not a GUID", self.tenant_id)));
        }
        if !is_guid(&self.api_client_id) {
            return Err(ConfigError::invalid("entra.api_client_id", format!("{:?} is not a GUID", self.api_client_id)));
        }
        Ok(())
    }

    /// The issuer, which is also the one authorization server in metadata.
    pub fn authorization_server(&self) -> String {
        format!("{ENTRA_AUTHORITY}/{}/v2.0", self.tenant_id)
    }

    /// The challenge form of a short scope: `access_as_user` becomes
    /// `api://{client-id}/access_as_user`.
    pub fn scope(&self, short: &str) -> Scope {
        let prefix = self.scope_prefix.clone().unwrap_or_else(|| format!("api://{}/", self.api_client_id));
        Scope::new(short).with_challenge(format!("{prefix}{short}"))
    }

    /// The validator configuration for a resource URL.
    pub fn issuer_config(&self, resource_url: &str) -> Result<IssuerConfig, ConfigError> {
        // The fields are public, so normalize again in case they were set directly.
        let mut me = self.clone();
        me.tenant_id = me.tenant_id.to_ascii_lowercase();
        me.api_client_id = me.api_client_id.to_ascii_lowercase();
        let me = &me;
        me.check()?;
        let jwks: Url = format!("{ENTRA_AUTHORITY}/{}/discovery/v2.0/keys", me.tenant_id)
            .parse()
            .map_err(|e: url::ParseError| ConfigError::invalid("entra.jwks", e.to_string()))?;
        let mut audiences: BTreeSet<String> = BTreeSet::new();
        audiences.insert(me.api_client_id.clone());
        audiences.insert(format!("api://{}", me.api_client_id));
        audiences.extend(me.app_id_uris.iter().cloned());
        audiences.insert(resource_url.to_owned());
        Ok(IssuerConfig {
            issuer: me.authorization_server(),
            jwks: JwksConfig::new(jwks),
            audiences,
            tenant: Some(ClaimEquals::new("tid", me.tenant_id.clone())),
            required_version: Some(ClaimEquals::new("ver", "2.0")),
            required_claims: Vec::new(),
            required_typ: None,
            require_nbf: true,
            claims: ClaimMap::entra(),
        })
    }
}

/// Where an OIDC provider's keys are.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum JwksSource {
    /// Read `jwks_uri` from discovery at startup.
    Discover,
    /// A fixed JWKS URI.
    Uri(Url),
}

/// A generic OpenID Connect provider that issues JWT access tokens (Okta custom authorization
/// servers, Auth0, Keycloak, and others).
#[derive(Clone, Debug)]
pub struct Oidc {
    /// Exact issuer.
    pub issuer: String,
    /// Key location.
    pub jwks: JwksSource,
    /// Accepted audiences. Required and non-empty.
    pub audiences: Vec<String>,
    /// Claim mapping. Default: `sub`, `azp`|`client_id`|`cid`, `scope`|`scp`, `roles`.
    pub claims: ClaimMap,
    /// Required header `typ`, for example `at+jwt`.
    pub required_typ: Option<String>,
    /// Other claims that must equal fixed values.
    pub required_claims: Vec<ClaimEquals>,
}

impl Oidc {
    /// An issuer with discovery and default claims.
    pub fn new(issuer: impl Into<String>) -> Self {
        Oidc {
            issuer: issuer.into(),
            jwks: JwksSource::Discover,
            audiences: Vec::new(),
            claims: ClaimMap::generic(),
            required_typ: None,
            required_claims: Vec::new(),
        }
    }

    /// Adds an accepted audience.
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.audiences.push(aud.into());
        self
    }

    /// Uses a fixed JWKS URI instead of discovery.
    pub fn jwks_uri(mut self, uri: Url) -> Self {
        self.jwks = JwksSource::Uri(uri);
        self
    }

    /// Replaces the role claims with one path.
    pub fn roles_claim(mut self, path: impl Into<ClaimPath>) -> Self {
        self.claims.roles = vec![path.into()];
        self
    }

    /// Sets the scope claim.
    pub fn scopes_claim(mut self, c: ScopeClaim) -> Self {
        self.claims.scopes = c;
        self
    }

    /// Requires a header `typ`.
    pub fn require_typ(mut self, typ: &str) -> Self {
        self.required_typ = Some(typ.to_owned());
        self
    }

    /// Requires a claim value, for example `token_use == "access"`.
    pub fn require_claim(mut self, claim: &str, value: &str) -> Self {
        self.required_claims.push(ClaimEquals::new(claim, value));
        self
    }

    /// Runs discovery (if needed) and returns the validator configuration.
    pub async fn issuer_config(&self, http: &reqwest::Client) -> Result<IssuerConfig, ConfigError> {
        if self.audiences.is_empty() {
            return Err(ConfigError::invalid("oidc.audiences", "at least one audience is required"));
        }
        let jwks_uri = match &self.jwks {
            JwksSource::Uri(u) => u.clone(),
            JwksSource::Discover => self.discover(http).await?,
        };
        check_https_or_loopback(&jwks_uri, "oidc.jwks_uri")?;
        Ok(IssuerConfig {
            issuer: self.issuer.clone(),
            jwks: JwksConfig::new(jwks_uri),
            audiences: self.audiences.iter().cloned().collect(),
            tenant: None,
            required_version: None,
            required_claims: self.required_claims.clone(),
            required_typ: self.required_typ.clone(),
            require_nbf: false,
            claims: self.claims.clone(),
        })
    }

    async fn discover(&self, http: &reqwest::Client) -> Result<Url, ConfigError> {
        let err = |reason: String| ConfigError::Discovery { issuer: self.issuer.clone(), reason };
        let base: Url = self.issuer.parse().map_err(|e: url::ParseError| err(e.to_string()))?;
        check_https_or_loopback(&base, "oidc.issuer")?;
        let trimmed = self.issuer.trim_end_matches('/');
        // OpenID discovery appends; RFC 8414 inserts the well-known segment before the path.
        let mut candidates = vec![format!("{trimmed}/.well-known/openid-configuration")];
        let path = base.path().trim_end_matches('/');
        let origin = base.origin().ascii_serialization();
        candidates.push(format!("{origin}/.well-known/oauth-authorization-server{path}"));
        let mut last = String::from("no discovery document found");
        for c in candidates {
            let resp = match http.get(&c).send().await {
                Ok(r) => r,
                Err(e) => {
                    last = e.without_url().to_string();
                    continue;
                }
            };
            if !resp.status().is_success() {
                last = format!("{c} returned {}", resp.status());
                continue;
            }
            let body = read_capped(resp, 256 * 1024).await.map_err(|e| err(e.to_string()))?;
            let doc: Value = serde_json::from_slice(&body).map_err(|e| err(e.to_string()))?;
            let iss = doc.get("issuer").and_then(Value::as_str).unwrap_or("");
            if iss != self.issuer {
                return Err(err(format!("discovery issuer {iss:?} does not equal the configured issuer")));
            }
            let jwks = doc.get("jwks_uri").and_then(Value::as_str).ok_or_else(|| err("no jwks_uri".into()))?;
            return jwks.parse().map_err(|e: url::ParseError| err(e.to_string()));
        }
        Err(err(last))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "00000000-0000-0000-0000-000000000001";
    const A: &str = "00000000-0000-0000-0000-000000000002";

    #[test]
    fn entra_preset() {
        let e = Entra::new(T, A).app_id_uri("api://orders.example.com");
        let c = e.issuer_config("https://mcp.example.com/mcp").unwrap();
        assert_eq!(c.issuer, format!("https://login.microsoftonline.com/{T}/v2.0"));
        assert!(c.audiences.contains(A));
        assert!(c.audiences.contains(&format!("api://{A}")));
        assert!(c.audiences.contains("https://mcp.example.com/mcp"));
        assert!(c.audiences.contains("api://orders.example.com"));
        assert!(c.require_nbf);
        assert_eq!(e.scope("access_as_user").challenge(), format!("api://{A}/access_as_user"));
        assert!(Entra::new("common", A).issuer_config("https://x.example.com").is_err());
        assert!(Entra::new(T, "abc").issuer_config("https://x.example.com").is_err());
    }

    #[test]
    fn oidc_requires_audience() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let err = rt.block_on(Oidc::new("https://id.example.com").issuer_config(&reqwest::Client::new())).unwrap_err();
        assert!(err.to_string().contains("audience"));
    }
}
