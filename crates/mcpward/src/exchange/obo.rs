use std::{
    fmt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tracing::Instrument;
use url::Url;

use super::{CachedExchanger, ClientAssertionSource, DownstreamToken, ExchangeError, ExchangeTarget, TokenExchanger};
use crate::{
    ConfigError, EnvErrors,
    auth::{BoxFuture, Principal, SubjectToken, providers_is_guid},
};

const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";
const FEDERATION_AUDIENCE: &str = "api://AzureADTokenExchange";

/// The API registration's credential for On-Behalf-Of.
#[derive(Clone)]
#[non_exhaustive]
pub enum ClientCredential {
    /// A client secret from the platform's secret store.
    Secret(SecretString),
    /// A user-assigned managed identity, federated with the API registration (Container Apps
    /// and App Service: `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`).
    ManagedIdentity {
        /// The user-assigned identity's client ID.
        client_id: String,
    },
    /// A JWT read from a file on every use (Kubernetes workload identity:
    /// `AZURE_FEDERATED_TOKEN_FILE`).
    AssertionFile {
        /// The file.
        path: PathBuf,
    },
    /// Consumer-supplied assertions.
    Custom(Arc<dyn ClientAssertionSource>),
}

impl ClientCredential {
    fn kind(&self) -> &'static str {
        match self {
            ClientCredential::Secret(_) => "secret",
            ClientCredential::ManagedIdentity { .. } => "managed-identity",
            ClientCredential::AssertionFile { .. } => "assertion-file",
            ClientCredential::Custom(_) => "custom",
        }
    }
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientCredential::{}", self.kind())
    }
}

/// Builds an [`EntraObo`].
pub struct EntraOboBuilder {
    tenant_id: String,
    client_id: String,
    credential: ClientCredential,
    authority: String,
    identity_endpoint: Option<(Url, Option<SecretString>)>,
    margin: Duration,
    capacity: u64,
    http: Option<reqwest::Client>,
}

impl fmt::Debug for EntraOboBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraOboBuilder")
            .field("tenant_id", &self.tenant_id)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl EntraOboBuilder {
    /// Cache expiry margin (1 to 10 min). Default 3 min.
    pub fn expiry_margin(mut self, d: Duration) -> Self {
        self.margin = d;
        self
    }

    /// Cache capacity. Default 10,000 entries.
    pub fn cache_capacity(mut self, n: u64) -> Self {
        self.capacity = n;
        self
    }

    /// The authority base URL. Default `https://login.microsoftonline.com`. For tests.
    pub fn authority(mut self, url: &str) -> Self {
        self.authority = url.trim_end_matches('/').to_owned();
        self
    }

    /// Overrides `IDENTITY_ENDPOINT` (and, when given, `IDENTITY_HEADER`) for the managed
    /// identity credential. For tests.
    pub fn identity_endpoint(mut self, endpoint: Url, header: Option<String>) -> Self {
        self.identity_endpoint = Some((endpoint, header.map(SecretString::from)));
        self
    }

    /// HTTP client for the token and identity endpoints.
    pub fn http_client(mut self, c: reqwest::Client) -> Self {
        self.http = Some(c);
        self
    }

    /// Validates and builds.
    pub fn build(self) -> Result<EntraObo, ConfigError> {
        if !providers_is_guid(&self.tenant_id) {
            return Err(ConfigError::invalid("obo.tenant_id", format!("{:?} is not a GUID", self.tenant_id)));
        }
        if self.client_id.is_empty() {
            return Err(ConfigError::invalid("obo.client_id", "required"));
        }
        let http = match self.http {
            Some(h) => h,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .user_agent(concat!("mcpward/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| ConfigError::invalid("obo.http", e.to_string()))?,
        };
        let token_url: Url = format!("{}/{}/oauth2/v2.0/token", self.authority, self.tenant_id)
            .parse()
            .map_err(|e: url::ParseError| ConfigError::invalid("obo.authority", e.to_string()))?;
        crate::auth::check_https_or_loopback_pub(&token_url, "obo.authority")?;
        let kind = self.credential.kind();
        let credential = match self.credential {
            ClientCredential::Secret(s) => Resolved::Secret(s),
            ClientCredential::AssertionFile { path } => Resolved::File(path),
            ClientCredential::Custom(c) => Resolved::Custom(c),
            ClientCredential::ManagedIdentity { client_id } => {
                if client_id.is_empty() {
                    return Err(ConfigError::invalid(
                        "obo.managed_identity.client_id",
                        "a user-assigned identity client ID is required",
                    ));
                }
                let (endpoint, header) = match self.identity_endpoint {
                    Some(e) => e,
                    None => {
                        let raw = std::env::var("IDENTITY_ENDPOINT").map_err(|_| {
                            ConfigError::invalid(
                                "IDENTITY_ENDPOINT",
                                "not set; the managed identity credential needs a platform identity endpoint",
                            )
                        })?;
                        (raw.parse().map_err(|_| ConfigError::invalid("IDENTITY_ENDPOINT", "not a URL"))?, None)
                    }
                };
                Resolved::ManagedIdentity(Arc::new(ManagedIdentity {
                    endpoint,
                    header,
                    client_id,
                    http: http.clone(),
                    cached: tokio::sync::Mutex::new(None),
                }))
            }
        };
        let inner = OboExchanger { token_url, client_id: self.client_id, credential, http, kind };
        Ok(EntraObo { cache: CachedExchanger::with_settings(inner, self.margin, self.capacity)? })
    }
}

enum Resolved {
    Secret(SecretString),
    ManagedIdentity(Arc<ManagedIdentity>),
    File(PathBuf),
    Custom(Arc<dyn ClientAssertionSource>),
}

struct ManagedIdentity {
    endpoint: Url,
    header: Option<SecretString>,
    client_id: String,
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(SecretString, Instant)>>,
}

impl ClientAssertionSource for ManagedIdentity {
    fn assertion(&self) -> BoxFuture<'_, Result<SecretString, ExchangeError>> {
        Box::pin(async move {
            let mut cached = self.cached.lock().await;
            if let Some((tok, until)) = &*cached
                && Instant::now() < *until
            {
                return Ok(tok.clone());
            }
            // The platform rotates IDENTITY_HEADER, so it's read on every fetch.
            let header = match &self.header {
                Some(h) => h.expose_secret().to_owned(),
                None => std::env::var("IDENTITY_HEADER")
                    .map_err(|_| ExchangeError::misconfigured("IDENTITY_HEADER is not set"))?,
            };
            let resp = self
                .http
                .get(self.endpoint.clone())
                .query(&[
                    ("resource", FEDERATION_AUDIENCE),
                    ("api-version", "2019-08-01"),
                    ("client_id", self.client_id.as_str()),
                ])
                .header("X-IDENTITY-HEADER", header)
                .send()
                .await
                .map_err(|e| ExchangeError::Unavailable(format!("identity endpoint: {}", e.without_url())))?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if !status.is_success() {
                return Err(if status.is_server_error() {
                    ExchangeError::Unavailable(format!("identity endpoint returned {status}"))
                } else {
                    ExchangeError::misconfigured(format!("identity endpoint returned {status}"))
                });
            }
            let token = body
                .get("access_token")
                .and_then(Value::as_str)
                .ok_or_else(|| ExchangeError::misconfigured("identity endpoint returned no access_token"))?;
            let expires_on = body
                .get("expires_on")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(0);
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
            let valid_for =
                Duration::from_secs(expires_on.saturating_sub(now)).saturating_sub(Duration::from_secs(300));
            let secret = SecretString::from(token.to_owned());
            *cached = Some((secret.clone(), Instant::now() + valid_for));
            Ok(secret)
        })
    }
}

struct OboExchanger {
    token_url: Url,
    client_id: String,
    credential: Resolved,
    http: reqwest::Client,
    kind: &'static str,
}

const INTERACTION: &[u32] = &[50076, 50079, 50158];
const CONSENT: &[u32] = &[65001];
// 500133: the user's assertion expired. The validator's leeway lets a token a little past
// `exp` through, so this is the user's session needing a refresh, not a server fault.
const REVOKED: &[u32] = &[50173, 50132, 50133, 50089, 500133];
const MISCONFIGURED: &[u32] = &[500131, 50013, 700016, 7000215, 700024, 70021];

/// Maps an Entra token endpoint error to an [`ExchangeError`], keyed on `error_codes` first.
pub(crate) fn map_entra_error(status: u16, body: &Value) -> ExchangeError {
    let error = body.get("error").and_then(Value::as_str).unwrap_or("");
    let codes: Vec<u32> = body
        .get("error_codes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).map(|c| c as u32).collect())
        .unwrap_or_default();
    let has = |set: &[u32]| codes.iter().any(|c| set.contains(c));
    if has(INTERACTION) || error == "interaction_required" {
        ExchangeError::InteractionRequired { codes }
    } else if has(CONSENT) || error == "consent_required" {
        ExchangeError::ConsentRequired { codes }
    } else if has(REVOKED) {
        ExchangeError::SessionRevoked { codes }
    } else if has(MISCONFIGURED) || matches!(error, "invalid_client" | "unauthorized_client") {
        ExchangeError::Misconfigured { codes, detail: format!("token endpoint error {error}") }
    } else if status >= 500 || error == "temporarily_unavailable" {
        ExchangeError::Unavailable(format!("token endpoint returned {status} {error}"))
    } else {
        ExchangeError::Misconfigured { codes, detail: format!("token endpoint error {error} ({status})") }
    }
}

impl OboExchanger {
    async fn client_auth(&self) -> Result<Vec<(&'static str, String)>, ExchangeError> {
        let assertion = match &self.credential {
            Resolved::Secret(s) => return Ok(vec![("client_secret", s.expose_secret().to_owned())]),
            Resolved::ManagedIdentity(mi) => mi.assertion().await?,
            Resolved::Custom(c) => c.assertion().await?,
            Resolved::File(p) => {
                let raw = tokio::fs::read_to_string(p).await.map_err(|e| {
                    ExchangeError::misconfigured(format!("could not read assertion file: {}", e.kind()))
                })?;
                SecretString::from(raw.trim().to_owned())
            }
        };
        Ok(vec![
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned()),
            ("client_assertion", assertion.expose_secret().to_owned()),
        ])
    }

    async fn exchange_inner(
        &self,
        subject: &SubjectToken,
        target: &ExchangeTarget,
    ) -> Result<DownstreamToken, ExchangeError> {
        let mut form: Vec<(&'static str, String)> = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer".into()),
            ("client_id", self.client_id.clone()),
            ("assertion", subject.expose_secret().to_owned()),
            ("scope", target.scopes.join(" ")),
            ("requested_token_use", "on_behalf_of".into()),
        ];
        form.extend(self.client_auth().await?);
        let resp = self
            .http
            .post(self.token_url.clone())
            .form(&form)
            .send()
            .await
            .map_err(|e| ExchangeError::Unavailable(e.without_url().to_string()))?;
        drop(form);
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let span = tracing::Span::current();
        if !(200..300).contains(&status) {
            let err = map_entra_error(status, &body);
            let codes = format!("{:?}", err.codes());
            let correlation = body.get("correlation_id").and_then(Value::as_str).unwrap_or("");
            let trace_id = body.get("trace_id").and_then(Value::as_str).unwrap_or("");
            span.record("outcome", err.code());
            span.record("entra.error_codes", codes.as_str());
            span.record("entra.correlation_id", correlation);
            match &err {
                ExchangeError::InteractionRequired { .. } | ExchangeError::Unavailable(_) => {
                    tracing::warn!(target: "mcpward::exchange", status, error_codes = %codes, correlation_id = correlation, trace_id, outcome = err.code(), "on-behalf-of exchange failed")
                }
                ExchangeError::SessionRevoked { .. } => {
                    tracing::info!(target: "mcpward::exchange", status, error_codes = %codes, correlation_id = correlation, trace_id, outcome = err.code(), "on-behalf-of exchange failed")
                }
                _ => {
                    tracing::error!(target: "mcpward::exchange", status, error_codes = %codes, correlation_id = correlation, trace_id, outcome = err.code(), "on-behalf-of exchange failed")
                }
            }
            return Err(err);
        }
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| ExchangeError::misconfigured("token endpoint returned no access_token"))?;
        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(300);
        let mut t = DownstreamToken::new(token, SystemTime::now() + Duration::from_secs(expires_in));
        t.scopes = body.get("scope").and_then(Value::as_str).map(str::to_owned);
        span.record("outcome", "ok");
        Ok(t)
    }
}

impl TokenExchanger for OboExchanger {
    fn exchange<'a>(
        &'a self,
        principal: &'a Principal,
        subject: &'a SubjectToken,
        target: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
        let span = tracing::info_span!(
            target: "mcpward::exchange",
            "mcp.exchange",
            target = target.name,
            subject = %principal.subject.key(),
            credential = self.kind,
            outcome = tracing::field::Empty,
            entra.error_codes = tracing::field::Empty,
            entra.correlation_id = tracing::field::Empty,
        );
        Box::pin(
            async move {
                // A token accepted inside the clock-skew leeway is already expired for Entra;
                // don't send it.
                if principal.expires_at <= SystemTime::now() {
                    tracing::Span::current().record("outcome", "session_revoked");
                    return Err(ExchangeError::SessionRevoked { codes: Vec::new() });
                }
                self.exchange_inner(subject, target).await
            }
            .instrument(span),
        )
    }

    fn kind(&self) -> &'static str {
        "entra-obo"
    }
}

/// Microsoft Entra On-Behalf-Of, cached per user and target.
///
/// Posts the caller's token to `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
/// with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and
/// `requested_token_use=on_behalf_of`, authenticating with a secret or a federated assertion.
/// Never requests `offline_access`.
pub struct EntraObo {
    cache: CachedExchanger<OboExchanger>,
}

impl fmt::Debug for EntraObo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraObo")
            .field("token_url", &self.cache.inner().token_url.as_str())
            .field("credential", &self.cache.inner().kind)
            .finish()
    }
}

impl EntraObo {
    /// Starts a builder. `client_id` is the API (resource server) registration's client ID.
    pub fn builder(tenant_id: &str, client_id: &str, credential: ClientCredential) -> EntraOboBuilder {
        EntraOboBuilder {
            tenant_id: tenant_id.to_owned(),
            client_id: client_id.to_owned(),
            credential,
            authority: DEFAULT_AUTHORITY.to_owned(),
            identity_endpoint: None,
            margin: Duration::from_secs(180),
            capacity: 10_000,
            http: None,
        }
    }

    /// Reads `MCPWARD_EXCHANGE*` settings. `Ok(None)` when `EXCHANGE` is unset or `none`.
    pub fn from_env() -> Result<Option<EntraObo>, ConfigError> {
        Self::from_env_with("MCPWARD_", |k| std::env::var(k).ok())
    }

    /// Reads settings with a custom prefix through `lookup`. `AZURE_CLIENT_ID` and
    /// `AZURE_FEDERATED_TOKEN_FILE` are read without the prefix as fallbacks.
    pub fn from_env_with(
        prefix: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<EntraObo>, ConfigError> {
        let get = |k: &str| lookup(&format!("{prefix}{k}")).filter(|v| !v.trim().is_empty());
        let mut problems: Vec<(String, String)> = Vec::new();
        let mut problem = |k: &str, m: &str| problems.push((format!("{prefix}{k}"), m.to_owned()));
        match get("EXCHANGE").as_deref() {
            None | Some("none") => return Ok(None),
            Some("entra-obo") => {}
            Some(other) => {
                problem("EXCHANGE", &format!("{other:?} is not entra-obo or none"));
                return Err(ConfigError::Env(EnvErrors { problems }));
            }
        }
        let tenant = get("ENTRA_TENANT_ID");
        if tenant.is_none() {
            problem("ENTRA_TENANT_ID", "required when EXCHANGE=entra-obo");
        }
        let client = get("EXCHANGE_CLIENT_ID").or_else(|| get("ENTRA_API_CLIENT_ID"));
        if client.is_none() {
            problem("EXCHANGE_CLIENT_ID", "required (defaults to ENTRA_API_CLIENT_ID)");
        }
        let cred = match get("EXCHANGE_CREDENTIAL").as_deref() {
            Some("secret") => match get("EXCHANGE_CLIENT_SECRET") {
                Some(s) => Some(ClientCredential::Secret(SecretString::from(s))),
                None => {
                    problem("EXCHANGE_CLIENT_SECRET", "required when EXCHANGE_CREDENTIAL=secret");
                    None
                }
            },
            Some("managed-identity") => match get("MANAGED_IDENTITY_CLIENT_ID").or_else(|| lookup("AZURE_CLIENT_ID")) {
                Some(id) => Some(ClientCredential::ManagedIdentity { client_id: id }),
                None => {
                    problem(
                        "MANAGED_IDENTITY_CLIENT_ID",
                        "required (or AZURE_CLIENT_ID) when EXCHANGE_CREDENTIAL=managed-identity",
                    );
                    None
                }
            },
            Some("assertion-file") => match get("ASSERTION_FILE").or_else(|| lookup("AZURE_FEDERATED_TOKEN_FILE")) {
                Some(p) => Some(ClientCredential::AssertionFile { path: p.into() }),
                None => {
                    problem(
                        "ASSERTION_FILE",
                        "required (or AZURE_FEDERATED_TOKEN_FILE) when EXCHANGE_CREDENTIAL=assertion-file",
                    );
                    None
                }
            },
            Some(other) => {
                problem(
                    "EXCHANGE_CREDENTIAL",
                    &format!("{other:?} is not secret, managed-identity, or assertion-file"),
                );
                None
            }
            None => {
                problem("EXCHANGE_CREDENTIAL", "required when EXCHANGE=entra-obo");
                None
            }
        };
        match (tenant, client, cred) {
            (Some(t), Some(c), Some(cred)) if problems.is_empty() => EntraObo::builder(&t, &c, cred).build().map(Some),
            _ => Err(ConfigError::Env(EnvErrors { problems })),
        }
    }
}

impl TokenExchanger for EntraObo {
    fn exchange<'a>(
        &'a self,
        principal: &'a Principal,
        subject: &'a SubjectToken,
        target: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
        if target.scopes.iter().any(|s| s == "offline_access") {
            return Box::pin(async { Err(ExchangeError::misconfigured("offline_access is never requested")) });
        }
        self.cache.exchange(principal, subject, target)
    }

    fn kind(&self) -> &'static str {
        "entra-obo"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn error_mapping() {
        let m = |codes: &[u32], err: &str| map_entra_error(400, &json!({"error": err, "error_codes": codes}));
        assert!(matches!(m(&[50076], "invalid_grant"), ExchangeError::InteractionRequired { .. }));
        assert!(matches!(m(&[], "interaction_required"), ExchangeError::InteractionRequired { .. }));
        assert!(matches!(m(&[65001], "invalid_grant"), ExchangeError::ConsentRequired { .. }));
        assert!(matches!(m(&[50173], "invalid_grant"), ExchangeError::SessionRevoked { .. }));
        assert!(matches!(m(&[70021], "invalid_request"), ExchangeError::Misconfigured { .. }));
        assert!(matches!(m(&[], "invalid_client"), ExchangeError::Misconfigured { .. }));
        assert!(matches!(m(&[12345], "invalid_grant"), ExchangeError::Misconfigured { .. }));
        assert!(matches!(map_entra_error(503, &json!({})), ExchangeError::Unavailable(_)));
        assert!(matches!(m(&[], "temporarily_unavailable"), ExchangeError::Unavailable(_)));
        assert_eq!(m(&[65001], "invalid_grant").codes(), &[65001]);
    }

    #[test]
    fn env_collects_problems() {
        let env = |k: &str| match k {
            "X_EXCHANGE" => Some("entra-obo".to_owned()),
            "X_EXCHANGE_CREDENTIAL" => Some("secret".to_owned()),
            _ => None,
        };
        let err = EntraObo::from_env_with("X_", env).unwrap_err().to_string();
        assert!(err.contains("X_ENTRA_TENANT_ID") && err.contains("X_EXCHANGE_CLIENT_SECRET"), "{err}");
        assert!(EntraObo::from_env_with("X_", |_| None).unwrap().is_none());
    }
}
