use std::{
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use jsonwebtoken::{Algorithm, Validation, errors::ErrorKind};
use serde_json::{Map, Value};

use super::{
    BoxFuture, ClaimEquals, ClaimMap, JwksCache, JwksConfig, KeySource, Principal, PrincipalKind, Subject,
    jwks::{HttpKeySource, KeyLookup, parse_alg, truncate},
};
use crate::ConfigError;

/// Maximum accepted token length.
pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Validates a bearer token and returns the caller.
///
/// [`JwtValidator`] is the default. Implement this for other token types, for example opaque
/// tokens checked with RFC 7662 introspection; the rest of the pipeline is unchanged.
pub trait TokenValidator: Send + Sync + 'static {
    /// Validates `token` (the part after `Bearer `).
    fn validate<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<Principal, AuthError>>;

    /// Whether the validator can serve requests (for example, keys are loaded).
    fn ready(&self) -> bool {
        true
    }
}

/// Why a token was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectReason {
    /// No `Authorization: Bearer` header.
    MissingToken,
    /// Token in the query string or body, or several `Authorization` headers.
    InvalidRequest,
    /// Not a well-formed JWS compact token.
    Malformed,
    /// `alg` not in the allowlist (including `none` and `HS*`).
    AlgorithmNotAllowed,
    /// Header `typ` doesn't match the required value.
    WrongType,
    /// No `kid` in the header.
    MissingKid,
    /// `kid` not in the key set, after at most one refetch.
    UnknownKid,
    /// The signature doesn't verify.
    BadSignature,
    /// `iss` isn't the configured issuer.
    WrongIssuer,
    /// No `aud` value is accepted.
    WrongAudience,
    /// `exp` has passed.
    Expired,
    /// `nbf` or `iat` is in the future.
    NotYetValid,
    /// A required registered claim (`exp`, `iss`, `aud`, `nbf`) is missing.
    MissingClaim,
    /// The tenant claim doesn't match.
    WrongTenant,
    /// The token version claim doesn't match (Entra v1 tokens).
    WrongTokenVersion,
    /// A required claim value doesn't match (for example `token_use`).
    WrongTokenUse,
    /// The subject claim is missing or empty.
    MissingSubject,
    /// An app-only token where only user tokens are accepted.
    AppTokenNotAllowed,
    /// The client (`azp`) isn't in the allowlist. Terminal `403`.
    ClientNotAllowed,
    /// A required base scope is missing. `403 insufficient_scope`.
    InsufficientScope,
    /// A consumer [`ClaimCheck`] refused the token.
    Custom(&'static str),
}

impl RejectReason {
    /// A snake_case code for logs and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectReason::MissingToken => "missing_token",
            RejectReason::InvalidRequest => "invalid_request",
            RejectReason::Malformed => "malformed",
            RejectReason::AlgorithmNotAllowed => "algorithm_not_allowed",
            RejectReason::WrongType => "wrong_type",
            RejectReason::MissingKid => "missing_kid",
            RejectReason::UnknownKid => "unknown_kid",
            RejectReason::BadSignature => "bad_signature",
            RejectReason::WrongIssuer => "wrong_issuer",
            RejectReason::WrongAudience => "wrong_audience",
            RejectReason::Expired => "expired",
            RejectReason::NotYetValid => "not_yet_valid",
            RejectReason::MissingClaim => "missing_claim",
            RejectReason::WrongTenant => "wrong_tenant",
            RejectReason::WrongTokenVersion => "wrong_token_version",
            RejectReason::WrongTokenUse => "wrong_token_use",
            RejectReason::MissingSubject => "missing_subject",
            RejectReason::AppTokenNotAllowed => "app_token_not_allowed",
            RejectReason::ClientNotAllowed => "client_not_allowed",
            RejectReason::InsufficientScope => "insufficient_scope",
            RejectReason::Custom(c) => c,
        }
    }

    /// The fixed, generic phrase used in `error_description`. Never token content.
    pub fn description(&self) -> &'static str {
        match self {
            RejectReason::Expired => "The access token expired",
            RejectReason::NotYetValid => "The access token is not yet valid",
            RejectReason::WrongAudience => "The access token was issued for another resource",
            RejectReason::WrongIssuer | RejectReason::WrongTenant => {
                "The access token was issued by an untrusted issuer"
            }
            RejectReason::InsufficientScope => "The token is missing a required scope",
            RejectReason::ClientNotAllowed => "This client application is not allowed to call this server",
            _ => "The access token is invalid",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validation failure.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The token was refused. `401 invalid_token`, or `403` for `ClientNotAllowed` and
    /// `InsufficientScope`.
    #[error("token rejected: {0}")]
    Rejected(RejectReason),
    /// Keys aren't available. `503`, no challenge.
    #[error("token validation unavailable: {0}")]
    Unavailable(String),
}

/// A consumer-supplied check on the validated principal. Runs after every built-in check.
pub trait ClaimCheck: Send + Sync + 'static {
    /// Returns an error to refuse the token.
    fn check(&self, principal: &Principal) -> Result<(), RejectReason>;
}

impl<F> ClaimCheck for F
where
    F: Fn(&Principal) -> Result<(), RejectReason> + Send + Sync + 'static,
{
    fn check(&self, principal: &Principal) -> Result<(), RejectReason> {
        self(principal)
    }
}

/// One trusted issuer: where its keys are and what its tokens must look like.
/// Built by [`Entra`](super::Entra) and [`Oidc`](super::Oidc), or by hand.
#[derive(Clone, Debug)]
pub struct IssuerConfig {
    /// Exact `iss` value.
    pub issuer: String,
    /// Key set settings.
    pub jwks: JwksConfig,
    /// Accepted `aud` values. Non-empty.
    pub audiences: BTreeSet<String>,
    /// Tenant claim check (Entra `tid`).
    pub tenant: Option<ClaimEquals>,
    /// Token version check (Entra `ver == "2.0"`).
    pub required_version: Option<ClaimEquals>,
    /// Other claims that must equal fixed values (for example `token_use == "access"`).
    pub required_claims: Vec<ClaimEquals>,
    /// Required header `typ`, compared case-insensitively (for example `at+jwt`).
    pub required_typ: Option<String>,
    /// Whether `nbf` is required.
    pub require_nbf: bool,
    /// How claims map to the principal.
    pub claims: ClaimMap,
}

/// Builds a [`JwtValidator`]. Fails closed: see [`JwtValidatorBuilder::build`].
pub struct JwtValidatorBuilder {
    issuer: Option<IssuerConfig>,
    algorithms: Vec<Algorithm>,
    leeway: Duration,
    allowed_clients: Option<BTreeSet<String>>,
    allow_any_client: bool,
    required_scopes: Option<BTreeSet<String>>,
    no_required_scopes: bool,
    allow_app_tokens: bool,
    checks: Vec<Arc<dyn ClaimCheck>>,
    http: Option<reqwest::Client>,
    key_source: Option<Arc<dyn KeySource>>,
}

impl fmt::Debug for JwtValidatorBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtValidatorBuilder")
            .field("issuer", &self.issuer.as_ref().map(|i| &i.issuer))
            .finish_non_exhaustive()
    }
}

impl JwtValidatorBuilder {
    /// Sets the issuer.
    pub fn issuer(mut self, cfg: IssuerConfig) -> Self {
        self.issuer = Some(cfg);
        self
    }

    /// Sets the allowed algorithms. Default `[RS256]`. `HS*` is refused at build.
    pub fn algorithms(mut self, algs: &[Algorithm]) -> Self {
        self.algorithms = algs.to_vec();
        self
    }

    /// Clock-skew allowance for `exp`, `nbf`, and `iat`. Default 120 s, maximum 300 s.
    pub fn leeway(mut self, d: Duration) -> Self {
        self.leeway = d;
        self
    }

    /// Accept only tokens whose client claim is one of these. GUIDs compare case-insensitively.
    pub fn allowed_clients<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_clients = Some(ids.into_iter().map(|c| normalize_guid(c.into())).collect());
        self
    }

    /// Explicit opt-out of the client allowlist. Logs a warning at build.
    pub fn allow_any_client(mut self) -> Self {
        self.allow_any_client = true;
        self
    }

    /// Scopes (claim form) every token must carry.
    pub fn required_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_scopes = Some(scopes.into_iter().map(Into::into).collect());
        self
    }

    /// Explicit opt-out of base scopes. Logs a warning at build.
    pub fn no_required_scopes(mut self) -> Self {
        self.no_required_scopes = true;
        self
    }

    /// Accept app-only tokens (client credentials). Off by default.
    pub fn allow_app_tokens(mut self, allow: bool) -> Self {
        self.allow_app_tokens = allow;
        self
    }

    /// Adds a custom check.
    pub fn claim_check(mut self, c: impl ClaimCheck) -> Self {
        self.checks.push(Arc::new(c));
        self
    }

    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    pub(crate) fn claim_check_arc(mut self, c: Arc<dyn ClaimCheck>) -> Self {
        self.checks.push(c);
        self
    }

    /// HTTP client for JWKS fetches. By default mcpward builds one with no redirects.
    ///
    /// Build it with `redirect(reqwest::redirect::Policy::none())`: a key endpoint that
    /// redirects shouldn't be followed. `fetch_timeout` still bounds every fetch.
    pub fn http_client(mut self, c: reqwest::Client) -> Self {
        self.http = Some(c);
        self
    }

    /// Replaces the HTTP key source, for tests and air-gapped setups.
    pub fn key_source(mut self, s: Arc<dyn KeySource>) -> Self {
        self.key_source = Some(s);
        self
    }

    /// Builds the validator and performs the startup key load.
    ///
    /// Fails with [`ConfigError::NoRequiredScopes`] unless `required_scopes` (non-empty) or
    /// `no_required_scopes()` was called, and with [`ConfigError::NoClientAllowlist`] unless
    /// `allowed_clients` (non-empty) or `allow_any_client()` was called.
    pub async fn build(self) -> Result<JwtValidator, ConfigError> {
        super::ensure_crypto_provider();
        let issuer = self.issuer.ok_or_else(|| ConfigError::invalid("issuer", "required"))?;
        let required_scopes = match (self.required_scopes, self.no_required_scopes) {
            (Some(s), _) if !s.is_empty() => s,
            (_, true) => {
                tracing::warn!(target: "mcpward", "no_required_scopes(): tokens without any scope are accepted");
                BTreeSet::new()
            }
            _ => return Err(ConfigError::NoRequiredScopes),
        };
        let allowed_clients = match (self.allowed_clients, self.allow_any_client) {
            (Some(c), _) if !c.is_empty() => Some(c),
            (_, true) => {
                tracing::warn!(target: "mcpward", "allow_any_client(): tokens from any client application are accepted");
                None
            }
            _ => return Err(ConfigError::NoClientAllowlist),
        };
        if self.algorithms.is_empty() {
            return Err(ConfigError::invalid("algorithms", "must not be empty"));
        }
        if self.algorithms.iter().any(|a| matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)) {
            return Err(ConfigError::invalid("algorithms", "HMAC algorithms are never allowed for access tokens"));
        }
        if self.leeway > Duration::from_secs(300) {
            return Err(ConfigError::invalid("leeway", "at most 300 s"));
        }
        if issuer.audiences.is_empty() {
            return Err(ConfigError::invalid("audiences", "at least one audience is required"));
        }
        if issuer.issuer.is_empty() {
            return Err(ConfigError::invalid("issuer", "must not be empty"));
        }
        issuer.jwks.validate()?;
        let source: Arc<dyn KeySource> = match self.key_source {
            Some(s) => {
                tracing::warn!(target: "mcpward", "using a custom key source; never pin keys in production");
                s
            }
            None => Arc::new(HttpKeySource::new(&issuer.jwks, self.http)?),
        };
        let jwks = JwksCache::new(issuer.jwks.clone(), source, self.algorithms.clone());
        jwks.start().await?;
        Ok(JwtValidator {
            inner: Arc::new(ValidatorInner {
                issuer,
                jwks,
                algorithms: self.algorithms,
                leeway: self.leeway,
                allowed_clients,
                required_scopes,
                allow_app_tokens: self.allow_app_tokens,
                checks: self.checks,
            }),
        })
    }
}

struct ValidatorInner {
    issuer: IssuerConfig,
    jwks: JwksCache,
    algorithms: Vec<Algorithm>,
    leeway: Duration,
    allowed_clients: Option<BTreeSet<String>>,
    required_scopes: BTreeSet<String>,
    allow_app_tokens: bool,
    checks: Vec<Arc<dyn ClaimCheck>>,
}

/// The default [`TokenValidator`]: a JWT validator for one issuer with a JWKS cache.
///
/// Checks, in order, stopping at the first failure: transport and length, shape, `alg`
/// allowlist, `typ`, `kid` lookup (one rate-limited refetch), signature, `iss`, `aud`, `exp`,
/// `nbf`, `iat`, tenant, version, required claims, subject and app-only tokens, client
/// allowlist, base scopes, and custom checks.
#[derive(Clone)]
pub struct JwtValidator {
    inner: Arc<ValidatorInner>,
}

impl fmt::Debug for JwtValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtValidator")
            .field("issuer", &self.inner.issuer.issuer)
            .field("audiences", &self.inner.issuer.audiences)
            .field("jwks", &self.inner.jwks)
            .finish_non_exhaustive()
    }
}

impl JwtValidator {
    /// Starts a builder. Defaults: `RS256`, 120 s leeway, no app-only tokens.
    pub fn builder() -> JwtValidatorBuilder {
        JwtValidatorBuilder {
            issuer: None,
            algorithms: vec![Algorithm::RS256],
            leeway: Duration::from_secs(120),
            allowed_clients: None,
            allow_any_client: false,
            required_scopes: None,
            no_required_scopes: false,
            allow_app_tokens: false,
            checks: Vec::new(),
            http: None,
            key_source: None,
        }
    }

    /// The issuer configuration.
    pub fn issuer_config(&self) -> &IssuerConfig {
        &self.inner.issuer
    }

    /// The JWKS cache.
    pub fn jwks(&self) -> &JwksCache {
        &self.inner.jwks
    }

    /// The base scopes every token must carry (claim form).
    pub fn required_scopes(&self) -> &BTreeSet<String> {
        &self.inner.required_scopes
    }

    /// The client allowlist, or `None` after `allow_any_client()`.
    pub fn allowed_clients(&self) -> Option<&BTreeSet<String>> {
        self.inner.allowed_clients.as_ref()
    }

    async fn validate_inner(&self, token: &str) -> Result<Principal, AuthError> {
        let me = &*self.inner;
        let rej = |r| Err(AuthError::Rejected(r));
        // 1. Transport and length
        if token.is_empty() {
            return rej(RejectReason::MissingToken);
        }
        if token.len() > MAX_TOKEN_BYTES {
            return rej(RejectReason::Malformed);
        }
        // 2. Shape
        let mut parts = token.split('.');
        let (Some(h), Some(_), Some(_), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return rej(RejectReason::Malformed);
        };
        let Some(header) = decode_segment(h) else {
            return rej(RejectReason::Malformed);
        };
        // 3. alg
        let alg_str = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let Some(alg) = parse_alg(alg_str).filter(|a| me.algorithms.contains(a)) else {
            return rej(RejectReason::AlgorithmNotAllowed);
        };
        // 4. typ
        if let Some(want) = &me.issuer.required_typ {
            let typ = header.get("typ").and_then(Value::as_str).unwrap_or("");
            if !typ.eq_ignore_ascii_case(want) {
                return rej(RejectReason::WrongType);
            }
        }
        // 5. kid
        let Some(kid) = header.get("kid").and_then(Value::as_str).filter(|k| !k.is_empty()) else {
            return rej(RejectReason::MissingKid);
        };
        let key = match me.jwks.key(kid).await {
            KeyLookup::Found(k) => k,
            KeyLookup::Unknown => return rej(RejectReason::UnknownKid),
            KeyLookup::Unavailable => {
                return Err(AuthError::Unavailable(format!("signing keys from {} are not loaded", me.jwks.uri())));
            }
        };
        // 6-10. Signature and registered claims
        let mut v = Validation::new(alg);
        v.algorithms = me.algorithms.clone();
        v.leeway = me.leeway.as_secs();
        v.validate_exp = true;
        v.validate_nbf = true;
        v.validate_aud = true;
        let mut required = vec!["exp", "iss", "aud"];
        if me.issuer.require_nbf {
            required.push("nbf");
        }
        v.set_required_spec_claims(&required);
        v.set_issuer(&[&me.issuer.issuer]);
        let auds: Vec<&String> = me.issuer.audiences.iter().collect();
        v.set_audience(&auds);
        let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &v).map_err(|e| {
            AuthError::Rejected(match e.kind() {
                ErrorKind::InvalidSignature => RejectReason::BadSignature,
                ErrorKind::ExpiredSignature => RejectReason::Expired,
                ErrorKind::ImmatureSignature => RejectReason::NotYetValid,
                ErrorKind::InvalidIssuer => RejectReason::WrongIssuer,
                ErrorKind::InvalidAudience => RejectReason::WrongAudience,
                ErrorKind::MissingRequiredClaim(_) => RejectReason::MissingClaim,
                ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => RejectReason::AlgorithmNotAllowed,
                _ => RejectReason::Malformed,
            })
        })?;
        let claims = data.claims;
        // 11. iat
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // A non-integer `iat` is compared as a float, so it can't skip the check.
        if let Some(iat) = claims.get("iat").and_then(Value::as_f64)
            && iat > (now + me.leeway.as_secs()) as f64
        {
            return rej(RejectReason::NotYetValid);
        }
        // 12. tenant
        if let Some(t) = &me.issuer.tenant
            && !t.matches(&claims)
        {
            return rej(RejectReason::WrongTenant);
        }
        // 13. version
        if let Some(ver) = &me.issuer.required_version
            && !ver.matches(&claims)
        {
            return rej(RejectReason::WrongTokenVersion);
        }
        // 14. token use and other fixed claims
        if me.issuer.required_claims.iter().any(|c| !c.matches(&claims)) {
            return rej(RejectReason::WrongTokenUse);
        }
        // 15. subject and app-only tokens
        let map = &me.issuer.claims;
        let id = claims.get(&map.subject.id).and_then(Value::as_str).filter(|s| !s.is_empty());
        let tenant = match &map.subject.tenant {
            Some(tc) => match claims.get(tc).and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(t) => Some(t.to_owned()),
                None => return rej(RejectReason::MissingSubject),
            },
            None => None,
        };
        let Some(id) = id else {
            return rej(RejectReason::MissingSubject);
        };
        let scopes = map.scopes.parse(&claims);
        let roles = map.roles(&claims);
        // An Entra token without `scp` is app-only (client credentials), whether or not it
        // carries `roles` or the optional `idtyp` claim: delegated tokens always have `scp`.
        let is_app = map.entra_app_detection
            && (claims.get("idtyp").and_then(Value::as_str) == Some("app") || !map.scopes.is_present(&claims));
        if is_app && !me.allow_app_tokens {
            return rej(RejectReason::AppTokenNotAllowed);
        }
        // 16. client
        let client_id = ClaimMap::first_str(&map.client_id, &claims);
        if let Some(allowed) = &me.allowed_clients
            && !client_id.as_ref().is_some_and(|c| allowed.contains(c) || allowed.contains(&normalize_guid(c.clone())))
        {
            return rej(RejectReason::ClientNotAllowed);
        }
        // 17. base scopes
        if !me.required_scopes.iter().all(|s| scopes.contains(s)) {
            return rej(RejectReason::InsufficientScope);
        }
        let secs = |n: &str| claims.get(n).and_then(Value::as_u64).map(|s| UNIX_EPOCH + Duration::from_secs(s));
        let mut p = Principal::new(
            Subject::new(me.issuer.issuer.clone(), tenant, id),
            if is_app { PrincipalKind::Application } else { PrincipalKind::User },
            secs("exp").unwrap_or(UNIX_EPOCH),
        );
        p.client_id = client_id;
        p.scopes = scopes;
        p.roles = roles;
        p.name = map.name.as_ref().and_then(|n| claims.get(n)).and_then(Value::as_str).map(str::to_owned);
        p.username = ClaimMap::first_str(&map.username, &claims);
        p.issued_at = secs("iat");
        p.token_id = ClaimMap::first_str(&map.token_id, &claims);
        let p = p.with_claims(claims);
        // 18. custom
        for c in &me.checks {
            c.check(&p).map_err(AuthError::Rejected)?;
        }
        Ok(p)
    }
}

fn decode_segment(seg: &str) -> Option<Map<String, Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(seg).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// Logs the unverified `iss`, `aud`, and `kid` of a rejected token at debug level, truncated
/// and escaped: the "wrong audience" mismatch is the most common setup error.
fn debug_unverified(token: &str, reason: RejectReason) {
    if !tracing::enabled!(target: "mcpward::auth", tracing::Level::DEBUG) {
        return;
    }
    let mut parts = token.split('.');
    let header = parts.next().and_then(decode_segment).unwrap_or_default();
    let payload = parts.next().and_then(decode_segment).unwrap_or_default();
    let s = |m: &Map<String, Value>, k: &str| m.get(k).map(|v| truncate(&v.to_string())).unwrap_or_default();
    tracing::debug!(
        target: "mcpward::auth",
        reject_reason = reason.as_str(),
        unverified_iss = %s(&payload, "iss"),
        unverified_aud = %s(&payload, "aud"),
        unverified_kid = %s(&header, "kid"),
        "token rejected"
    );
}

impl TokenValidator for JwtValidator {
    fn validate<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<Principal, AuthError>> {
        Box::pin(async move {
            let res = self.validate_inner(token).await;
            if let Err(AuthError::Rejected(r)) = &res {
                debug_unverified(token, *r);
            }
            res
        })
    }

    fn ready(&self) -> bool {
        self.inner.jwks.is_loaded()
    }
}

/// GUIDs are case-insensitive; Entra writes them in lowercase.
pub(crate) fn normalize_guid(s: String) -> String {
    if super::providers::is_guid(&s) { s.to_ascii_lowercase() } else { s }
}
