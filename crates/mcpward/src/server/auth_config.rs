//! [`Auth`] and [`AuthBuilder`]: which issuer to trust and the fail-closed checks.

use std::{fmt, sync::Arc, time::Duration};

use url::Url;

use crate::{
    ConfigError,
    auth::{
        Algorithm, ClaimCheck, ClaimPath, Entra, IssuerConfig, JwksConfig, JwtValidator, Oidc, Scope, TokenValidator,
    },
};

#[cfg(feature = "dev-auth")]
use crate::auth::{Principal, metadata_check_dev_host};

use super::AuthMode;

/// The identity used for every request in dev mode.
#[cfg(feature = "dev-auth")]
#[derive(Clone, Debug)]
pub struct DevIdentity {
    /// Subject ID. Default `dev-user`.
    pub subject: String,
    /// Display name. Default `Developer`.
    pub name: Option<String>,
    /// Scopes. Empty means "the required scopes".
    pub scopes: Vec<String>,
    /// Roles. Default none.
    pub roles: Vec<String>,
    /// Client ID. Default `dev-client`.
    pub client_id: Option<String>,
}

#[cfg(feature = "dev-auth")]
impl Default for DevIdentity {
    fn default() -> Self {
        DevIdentity {
            subject: "dev-user".into(),
            name: Some("Developer".into()),
            scopes: Vec::new(),
            roles: Vec::new(),
            client_id: Some("dev-client".into()),
        }
    }
}

pub(crate) enum Provider {
    Entra(Box<Entra>),
    Oidc(Box<Oidc>),
    Issuer(Box<IssuerConfig>),
    Validator {
        v: Arc<dyn TokenValidator>,
        authorization_server: String,
        base_scopes: Vec<Scope>,
    },
    #[cfg(feature = "dev-auth")]
    Dev(DevIdentity),
}

type JwksTweak = Box<dyn FnOnce(JwksConfig) -> JwksConfig + Send>;

/// Entry points for authentication configuration.
#[derive(Debug)]
pub struct Auth;

impl Auth {
    /// Microsoft Entra ID.
    pub fn entra(e: Entra) -> AuthBuilder {
        AuthBuilder::new(Provider::Entra(Box::new(e)))
    }

    /// A generic OIDC provider.
    pub fn oidc(o: Oidc) -> AuthBuilder {
        AuthBuilder::new(Provider::Oidc(Box::new(o)))
    }

    /// A hand-built issuer configuration. Its `issuer` is the authorization server in metadata.
    pub fn issuer(cfg: IssuerConfig) -> AuthBuilder {
        AuthBuilder::new(Provider::Issuer(Box::new(cfg)))
    }

    /// A custom [`TokenValidator`]. It is responsible for its own client and scope checks;
    /// mcpward still checks `base_scopes` on the returned principal.
    pub fn validator(v: Arc<dyn TokenValidator>, authorization_server: Url, base_scopes: Vec<Scope>) -> AuthBuilder {
        AuthBuilder::new(Provider::Validator { v, authorization_server: authorization_server.to_string(), base_scopes })
    }

    /// Development mode: every request is `identity`, and no token is checked.
    ///
    /// Refuses to start unless the bind address is loopback (or the override is set) and the
    /// resource URL host is `localhost`, a loopback IP, or a single-label name.
    #[cfg(feature = "dev-auth")]
    pub fn dev(identity: DevIdentity) -> AuthBuilder {
        AuthBuilder::new(Provider::Dev(identity))
    }
}

/// Authentication settings. One of `required_scopes`/`no_required_scopes` and one of
/// `allowed_clients`/`allow_any_client` must be called, or `build()` fails.
pub struct AuthBuilder {
    pub(crate) provider: Provider,
    required_scopes: Option<Vec<String>>,
    no_required_scopes: bool,
    allowed_clients: Option<Vec<String>>,
    allow_any_client: bool,
    leeway: Option<Duration>,
    algorithms: Option<Vec<Algorithm>>,
    roles_claim: Option<ClaimPath>,
    jwks: Vec<JwksTweak>,
    checks: Vec<Arc<dyn ClaimCheck>>,
    allow_app_tokens: bool,
    scope_prefix: Option<String>,
    http: Option<reqwest::Client>,
    #[cfg_attr(not(feature = "dev-auth"), allow(dead_code))]
    dev_allow_non_loopback: bool,
}

impl fmt::Debug for AuthBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthBuilder")
            .field("required_scopes", &self.required_scopes)
            .field("allowed_clients", &self.allowed_clients)
            .finish_non_exhaustive()
    }
}

/// The value `DEV_ALLOW_NON_LOOPBACK` must have to allow dev mode on a non-loopback bind.
pub const DEV_NON_LOOPBACK_ACK: &str = "i-understand-this-disables-auth";

pub(crate) struct BuiltAuth {
    pub(crate) mode: AuthMode,
    pub(crate) authorization_server: String,
    pub(crate) base_scopes: Vec<Scope>,
    pub(crate) scope_prefix: Option<String>,
    pub(crate) summary: String,
    pub(crate) dev_banner: Option<String>,
}

impl AuthBuilder {
    fn new(provider: Provider) -> Self {
        AuthBuilder {
            provider,
            required_scopes: None,
            no_required_scopes: false,
            allowed_clients: None,
            allow_any_client: false,
            leeway: None,
            algorithms: None,
            roles_claim: None,
            jwks: Vec::new(),
            checks: Vec::new(),
            allow_app_tokens: false,
            scope_prefix: None,
            http: None,
            dev_allow_non_loopback: false,
        }
    }

    /// Scopes every token must carry, in claim form. The challenge form is derived.
    pub fn required_scopes<I, S>(mut self, s: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_scopes = Some(s.into_iter().map(Into::into).collect());
        self
    }

    /// Explicit opt-out of base scopes. Logs a warning at startup.
    pub fn no_required_scopes(mut self) -> Self {
        self.no_required_scopes = true;
        self
    }

    /// Client IDs (`azp`) allowed to call this server.
    pub fn allowed_clients<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_clients = Some(ids.into_iter().map(Into::into).collect());
        self
    }

    /// Explicit opt-out of the client allowlist. Logs a warning at startup.
    pub fn allow_any_client(mut self) -> Self {
        self.allow_any_client = true;
        self
    }

    /// Clock skew allowance. Default 120 s, at most 300 s.
    pub fn leeway(mut self, d: Duration) -> Self {
        self.leeway = Some(d);
        self
    }

    /// Allowed signing algorithms. Default `[RS256]`.
    pub fn algorithms(mut self, a: &[Algorithm]) -> Self {
        self.algorithms = Some(a.to_vec());
        self
    }

    /// Replaces the role claim.
    pub fn roles_claim(mut self, path: impl Into<ClaimPath>) -> Self {
        self.roles_claim = Some(path.into());
        self
    }

    /// Adjusts JWKS settings, for example the refresh interval or a test JWKS URI.
    pub fn jwks(mut self, f: impl FnOnce(JwksConfig) -> JwksConfig + Send + 'static) -> Self {
        self.jwks.push(Box::new(f));
        self
    }

    /// Adds a custom claim check.
    pub fn claim_check(mut self, c: impl ClaimCheck) -> Self {
        self.checks.push(Arc::new(c));
        self
    }

    /// Accept app-only tokens. Off by default.
    pub fn allow_app_tokens(mut self, allow: bool) -> Self {
        self.allow_app_tokens = allow;
        self
    }

    /// Prefix that turns a claim-form scope into its challenge form. Entra defaults to
    /// `api://<api-client-id>/`; other providers to none.
    pub fn scope_prefix(mut self, p: impl Into<String>) -> Self {
        self.scope_prefix = Some(p.into());
        self
    }

    /// HTTP client for discovery and JWKS.
    ///
    /// Build it with `redirect(reqwest::redirect::Policy::none())`: a key endpoint that
    /// redirects shouldn't be followed. `fetch_timeout` still bounds every fetch.
    pub fn http_client(mut self, c: reqwest::Client) -> Self {
        self.http = Some(c);
        self
    }

    /// Allows dev mode on a non-loopback bind (needed inside containers). `ack` must be
    /// `"i-understand-this-disables-auth"`.
    #[cfg(feature = "dev-auth")]
    pub fn dev_allow_non_loopback(mut self, ack: &str) -> Self {
        self.dev_allow_non_loopback = ack == DEV_NON_LOOPBACK_ACK;
        self
    }

    /// Dev mode without the non-loopback acknowledgment: the served socket must be loopback.
    pub(crate) fn dev_requires_loopback(&self) -> bool {
        self.is_dev() && !self.dev_allow_non_loopback
    }

    pub(crate) fn is_dev(&self) -> bool {
        #[cfg(feature = "dev-auth")]
        {
            matches!(self.provider, Provider::Dev(_))
        }
        #[cfg(not(feature = "dev-auth"))]
        {
            false
        }
    }

    fn scopes(&self, prefix: Option<&str>) -> Vec<Scope> {
        self.required_scopes
            .iter()
            .flatten()
            .map(|s| match prefix {
                Some(p) if !s.contains("://") => Scope::new(s.clone()).with_challenge(format!("{p}{s}")),
                _ => Scope::new(s.clone()),
            })
            .collect()
    }

    async fn jwt(
        mut self,
        mut cfg: IssuerConfig,
        entra: bool,
        prefix: Option<String>,
    ) -> Result<BuiltAuth, ConfigError> {
        let base_scopes = self.scopes(prefix.as_deref());
        for f in std::mem::take(&mut self.jwks) {
            cfg.jwks = f(cfg.jwks);
        }
        if entra && cfg.jwks.uri.query().is_some_and(|q| q.contains("appid=")) {
            return Err(ConfigError::invalid(
                "jwks.uri",
                "app-specific signing keys (keys?appid=) are not supported; remove claims mapping or the custom signing key",
            ));
        }
        if let Some(r) = self.roles_claim.clone() {
            cfg.claims.roles = vec![r];
        }
        let mut b = JwtValidator::builder().issuer(cfg.clone()).allow_app_tokens(self.allow_app_tokens);
        if let Some(s) = &self.required_scopes {
            b = b.required_scopes(s.clone());
        }
        if self.no_required_scopes {
            b = b.no_required_scopes();
        }
        if let Some(c) = &self.allowed_clients {
            b = b.allowed_clients(c.clone());
        }
        if self.allow_any_client {
            b = b.allow_any_client();
        }
        if let Some(l) = self.leeway {
            b = b.leeway(l);
        }
        if let Some(a) = &self.algorithms {
            b = b.algorithms(a);
        }
        if let Some(h) = self.http.clone() {
            b = b.http_client(h);
        }
        for c in self.checks {
            b = b.claim_check_arc(c);
        }
        let v = b.build().await?;
        let summary = format!(
            "issuer={} audiences={:?} allowed_clients={} required_scopes={:?}",
            cfg.issuer,
            cfg.audiences,
            match &self.allowed_clients {
                Some(c) if !self.allow_any_client => format!("{c:?}"),
                _ => "any".into(),
            },
            self.required_scopes.unwrap_or_default()
        );
        Ok(BuiltAuth {
            mode: AuthMode::Token(Arc::new(v)),
            authorization_server: cfg.issuer,
            base_scopes,
            scope_prefix: prefix,
            summary,
            dev_banner: None,
        })
    }

    pub(crate) async fn build(
        self,
        resource: &crate::auth::ResourceUrl,
        bind: std::net::SocketAddr,
    ) -> Result<BuiltAuth, ConfigError> {
        let _ = bind;
        match &self.provider {
            Provider::Entra(e) => {
                let e = (**e).clone();
                let cfg = e.issuer_config(resource.as_str())?;
                let prefix = self
                    .scope_prefix
                    .clone()
                    .or(e.scope_prefix.clone())
                    .unwrap_or_else(|| format!("api://{}/", e.api_client_id));
                self.jwt(cfg, true, Some(prefix)).await
            }
            Provider::Oidc(o) => {
                let o = (**o).clone();
                let http = self.http.clone().unwrap_or_else(default_http);
                let cfg = o.issuer_config(&http).await?;
                let prefix = self.scope_prefix.clone();
                self.jwt(cfg, false, prefix).await
            }
            Provider::Issuer(cfg) => {
                let cfg = (**cfg).clone();
                let prefix = self.scope_prefix.clone();
                self.jwt(cfg, false, prefix).await
            }
            Provider::Validator { v, authorization_server, base_scopes } => Ok(BuiltAuth {
                mode: AuthMode::Token(v.clone()),
                authorization_server: authorization_server.clone(),
                base_scopes: base_scopes.clone(),
                scope_prefix: self.scope_prefix.clone(),
                summary: format!("custom validator, authorization_server={authorization_server}"),
                dev_banner: None,
            }),
            #[cfg(feature = "dev-auth")]
            Provider::Dev(id) => {
                if !bind.ip().is_loopback() && !self.dev_allow_non_loopback {
                    return Err(ConfigError::invalid(
                        "dev auth",
                        format!(
                            "refusing to bind {bind} in dev auth mode; bind a loopback address or set DEV_ALLOW_NON_LOOPBACK={DEV_NON_LOOPBACK_ACK}"
                        ),
                    ));
                }
                metadata_check_dev_host(resource)?;
                let base_scopes = self.scopes(self.scope_prefix.as_deref());
                let mut p = Principal::new(
                    crate::auth::Subject::new("http://localhost/dev", None, id.subject.clone()),
                    crate::auth::PrincipalKind::Dev,
                    std::time::SystemTime::now() + Duration::from_secs(100 * 365 * 24 * 3600),
                );
                p.name = id.name.clone();
                p.client_id = id.client_id.clone();
                p.roles = id.roles.iter().cloned().collect();
                p.scopes = if id.scopes.is_empty() {
                    base_scopes.iter().map(|s| s.claim().to_owned()).collect()
                } else {
                    id.scopes.iter().cloned().collect()
                };
                let banner = format!(
                    "mcpward DEV AUTH MODE: every request is authenticated as \"{}\" with roles {:?}. Never use this in production.",
                    id.subject, id.roles
                );
                Ok(BuiltAuth {
                    mode: AuthMode::Dev(Arc::new(p)),
                    authorization_server: "http://localhost/dev".into(),
                    base_scopes,
                    scope_prefix: self.scope_prefix.clone(),
                    summary: format!("dev identity {}", id.subject),
                    dev_banner: Some(banner),
                })
            }
        }
    }
}

pub(crate) fn default_http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("mcpward/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}
