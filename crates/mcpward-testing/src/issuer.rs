use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, Router, extract::State, routing::get};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, jwk::Jwk};
use mcpward::{Auth, AuthBuilder, Entra, Oidc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use crate::{TEST_AUDIENCE, TEST_CLIENT_ID, TEST_OID, TEST_SCOPE, TEST_SUBJECT};

const KEYS: [(&str, &str, &str); 3] = [
    ("test-key-0", include_str!("../keys/TEST-ONLY-key0.pem"), include_str!("../keys/TEST-ONLY-key0.pub.pem")),
    ("test-key-1", include_str!("../keys/TEST-ONLY-key1.pem"), include_str!("../keys/TEST-ONLY-key1.pub.pem")),
    ("test-key-2", include_str!("../keys/TEST-ONLY-key2.pem"), include_str!("../keys/TEST-ONLY-key2.pub.pem")),
];

struct Key {
    kid: &'static str,
    enc: EncodingKey,
    public_pem: &'static str,
    jwk: Value,
}

#[derive(Clone)]
enum Kind {
    Generic,
    Entra { tenant: String, api: String },
}

struct Shared {
    keys: Vec<Key>,
    current: AtomicUsize,
    fetches: AtomicUsize,
    issuer: String,
}

/// An in-process identity provider: a JWKS (and OIDC discovery) on `127.0.0.1:<random>`,
/// and a token minter.
pub struct TestIssuer {
    shared: Arc<Shared>,
    kind: Kind,
    base: Url,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestIssuer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Configures a [`TestIssuer`] before it starts.
pub struct TestIssuerBuilder {
    kind: Kind,
}

impl TestIssuerBuilder {
    /// Starts the issuer.
    pub async fn start(self) -> TestIssuer {
        TestIssuer::start_kind(self.kind).await
    }
}

async fn jwks(State(s): State<Arc<Shared>>) -> Json<Value> {
    s.fetches.fetch_add(1, Ordering::SeqCst);
    let cur = s.current.load(Ordering::SeqCst);
    Json(json!({"keys": [s.keys[cur].jwk]}))
}

async fn discovery(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({"issuer": s.issuer, "jwks_uri": format!("{}/jwks", s.issuer.trim_end_matches('/'))}))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl TestIssuer {
    /// A generic OIDC issuer whose issuer string is its own base URL (discovery works).
    pub async fn start() -> TestIssuer {
        Self::start_kind(Kind::Generic).await
    }

    /// An issuer that mints Entra-shaped v2 tokens (`iss` in Entra form, `tid`, `oid`, `scp`,
    /// `ver`, `azp`), with the JWKS served locally.
    pub fn entra(tenant_id: &str, api_client_id: &str) -> TestIssuerBuilder {
        TestIssuerBuilder { kind: Kind::Entra { tenant: tenant_id.to_owned(), api: api_client_id.to_owned() } }
    }

    async fn start_kind(kind: Kind) -> TestIssuer {
        mcpward::auth::ensure_crypto_provider();
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.expect("bind test issuer");
        let addr = listener.local_addr().expect("addr");
        let base: Url = format!("http://{addr}").parse().expect("url");
        let issuer = match &kind {
            Kind::Generic => format!("http://{addr}"),
            Kind::Entra { tenant, .. } => format!("https://login.microsoftonline.com/{tenant}/v2.0"),
        };
        let keys = KEYS
            .iter()
            .map(|(kid, pem, public_pem)| {
                let enc = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("test key");
                let mut jwk = serde_json::to_value(Jwk::from_encoding_key(&enc, Algorithm::RS256).expect("jwk"))
                    .expect("jwk json");
                jwk["kid"] = json!(kid);
                jwk["use"] = json!("sig");
                Key { kid, enc, public_pem, jwk }
            })
            .collect();
        let shared = Arc::new(Shared { keys, current: AtomicUsize::new(0), fetches: AtomicUsize::new(0), issuer });
        let app = Router::new()
            .route("/jwks", get(jwks))
            .route("/.well-known/openid-configuration", get(discovery))
            .with_state(shared.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestIssuer { shared, kind, base, task }
    }

    /// The `iss` value.
    pub fn issuer(&self) -> &str {
        &self.shared.issuer
    }

    /// The local JWKS URI.
    pub fn jwks_uri(&self) -> Url {
        self.base.join("/jwks").expect("url")
    }

    /// How many times the JWKS has been fetched.
    pub fn jwks_fetches(&self) -> usize {
        self.shared.fetches.load(Ordering::SeqCst)
    }

    /// Rotates: a new current key, and the old one is dropped from the JWKS.
    pub fn rotate(&self) {
        let cur = self.shared.current.load(Ordering::SeqCst);
        self.shared.current.store(1 - cur, Ordering::SeqCst);
    }

    /// The tenant ID, for Entra-shaped issuers.
    pub fn tenant_id(&self) -> Option<&str> {
        match &self.kind {
            Kind::Entra { tenant, .. } => Some(tenant),
            Kind::Generic => None,
        }
    }

    /// Whether tokens are Entra-shaped.
    pub fn is_entra(&self) -> bool {
        matches!(self.kind, Kind::Entra { .. })
    }

    /// The subject key a default token produces (`tid:oid` for Entra, `sub` otherwise).
    pub fn default_subject_key(&self) -> String {
        match &self.kind {
            Kind::Entra { tenant, .. } => format!("{tenant}:{TEST_OID}"),
            Kind::Generic => TEST_SUBJECT.to_owned(),
        }
    }

    /// A token with valid defaults for this issuer.
    pub fn token(&self) -> TokenBuilder {
        let t = now();
        let mut c = Map::new();
        c.insert("iss".into(), json!(self.issuer()));
        c.insert("iat".into(), json!(t));
        c.insert("nbf".into(), json!(t));
        c.insert("exp".into(), json!(t + 3600));
        c.insert("azp".into(), json!(TEST_CLIENT_ID));
        c.insert("name".into(), json!("Test User"));
        c.insert("preferred_username".into(), json!("test.user@example.com"));
        match &self.kind {
            Kind::Entra { tenant, api } => {
                c.insert("aud".into(), json!(api));
                c.insert("tid".into(), json!(tenant));
                c.insert("oid".into(), json!(TEST_OID));
                c.insert("sub".into(), json!("pairwise-subject"));
                c.insert("scp".into(), json!(TEST_SCOPE));
                c.insert("ver".into(), json!("2.0"));
                c.insert("uti".into(), json!(ulid::Ulid::new().to_string()));
            }
            Kind::Generic => {
                c.insert("aud".into(), json!(TEST_AUDIENCE));
                c.insert("sub".into(), json!(TEST_SUBJECT));
                c.insert("scope".into(), json!(TEST_SCOPE));
                c.insert("jti".into(), json!(ulid::Ulid::new().to_string()));
            }
        }
        TokenBuilder {
            shared: self.shared.clone(),
            entra: self.is_entra(),
            claims: c,
            mode: Mode::Normal,
            kid: None,
            typ: Some("JWT".into()),
        }
    }

    /// Authentication pointing at this issuer, with `required_scopes(["access_as_user"])` and
    /// `allowed_clients(["test-client"])` to match [`TokenBuilder`]'s defaults.
    ///
    /// Entra-shaped issuers use the Entra preset with the JWKS URI swapped for the local one;
    /// generic issuers use OIDC discovery and accept both [`TEST_AUDIENCE`] and
    /// `resource_url`.
    pub fn auth_for(&self, resource_url: &str) -> AuthBuilder {
        let jwks = self.jwks_uri();
        let auth = match &self.kind {
            Kind::Entra { tenant, api } => Auth::entra(Entra::new(tenant.clone(), api.clone())),
            Kind::Generic => Auth::oidc(Oidc::new(self.issuer()).audience(TEST_AUDIENCE).audience(resource_url)),
        };
        auth.jwks(move |mut j| {
            j.uri = jwks;
            j.min_refetch_interval = Duration::from_secs(10);
            j
        })
        .required_scopes([TEST_SCOPE])
        .allowed_clients([TEST_CLIENT_ID])
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    AlgNone,
    Hs256PublicKey,
    UnknownKid,
    Untrusted,
}

/// Builds one token. Start from [`TestIssuer::token`].
#[derive(Clone)]
pub struct TokenBuilder {
    shared: Arc<Shared>,
    entra: bool,
    claims: Map<String, Value>,
    mode: Mode,
    kid: Option<Option<String>>,
    typ: Option<String>,
}

impl TokenBuilder {
    /// Sets `sub`.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, s: &str) -> Self {
        self.claim("sub", s)
    }
    /// Sets `oid`.
    pub fn oid(self, s: &str) -> Self {
        self.claim("oid", s)
    }
    /// Sets `tid`.
    pub fn tid(self, s: &str) -> Self {
        self.claim("tid", s)
    }
    /// Sets `aud`.
    pub fn aud(self, a: &str) -> Self {
        self.claim("aud", a)
    }
    /// Sets `iss`.
    pub fn iss(self, i: &str) -> Self {
        self.claim("iss", i)
    }
    /// Sets `azp`.
    pub fn azp(self, c: &str) -> Self {
        self.claim("azp", c)
    }
    /// Sets the scopes (`scp` for Entra, `scope` otherwise), space-separated.
    pub fn scopes(self, s: &[&str]) -> Self {
        let k = if self.entra { "scp" } else { "scope" };
        self.claim(k, s.join(" "))
    }
    /// Sets `roles`.
    pub fn roles(self, r: &[&str]) -> Self {
        self.claim("roles", r)
    }
    /// Expires `d` from now.
    pub fn expires_in(self, d: Duration) -> Self {
        let e = now() + d.as_secs();
        self.claim("exp", e)
    }
    /// Expired an hour ago (beyond any allowed leeway).
    pub fn expired(self) -> Self {
        let t = now();
        self.claim("exp", t - 3600).claim("iat", t - 7200).claim("nbf", t - 7200)
    }
    /// Not valid until `d` from now.
    pub fn not_before_in(self, d: Duration) -> Self {
        let t = now() + d.as_secs();
        self.claim("nbf", t)
    }
    /// An app-only token: no scopes, roles, and `idtyp=app` (Entra).
    pub fn app_only(self) -> Self {
        let k = if self.entra { "scp" } else { "scope" };
        self.without(k).claim("idtyp", "app").claim("roles", ["App.Read"])
    }
    /// Sets any claim.
    pub fn claim(mut self, k: &str, v: impl Serialize) -> Self {
        self.claims.insert(k.to_owned(), serde_json::to_value(v).expect("claim value"));
        self
    }
    /// Removes a claim.
    pub fn without(mut self, k: &str) -> Self {
        self.claims.remove(k);
        self
    }
    /// Sets header `typ` (default `JWT`), or removes it with `None`.
    pub fn typ(mut self, t: Option<&str>) -> Self {
        self.typ = t.map(str::to_owned);
        self
    }
    /// Removes the header `kid`.
    pub fn without_kid(mut self) -> Self {
        self.kid = Some(None);
        self
    }
    /// An unsigned token with `alg: none`.
    pub fn alg_none(mut self) -> Self {
        self.mode = Mode::AlgNone;
        self
    }
    /// HS256 signed with the issuer's *public* key as the secret (key-confusion attempt).
    pub fn hs256_with_public_key(mut self) -> Self {
        self.mode = Mode::Hs256PublicKey;
        self
    }
    /// Signed with the current key but a `kid` the JWKS doesn't have.
    pub fn unknown_kid(mut self) -> Self {
        self.mode = Mode::UnknownKid;
        self
    }
    /// Signed with an untrusted key under the current key's `kid` (bad signature).
    pub fn signed_by_untrusted_key(mut self) -> Self {
        self.mode = Mode::Untrusted;
        self
    }

    /// Signs and returns the compact token.
    pub fn mint(self) -> String {
        mcpward::auth::ensure_crypto_provider();
        let cur = &self.shared.keys[self.shared.current.load(Ordering::SeqCst)];
        let default_kid = match self.mode {
            Mode::UnknownKid => format!("unknown-{}", ulid::Ulid::new()),
            _ => cur.kid.to_owned(),
        };
        let kid = match self.kid {
            Some(k) => k,
            None => Some(default_kid),
        };
        let b64 = |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        match self.mode {
            Mode::AlgNone => {
                let mut h = json!({"alg": "none"});
                if let Some(k) = &kid {
                    h["kid"] = json!(k);
                }
                format!("{}.{}.", b64(&h), b64(&Value::Object(self.claims)))
            }
            mode => {
                let (alg, key) = match mode {
                    Mode::Hs256PublicKey => (Algorithm::HS256, EncodingKey::from_secret(cur.public_pem.as_bytes())),
                    Mode::Untrusted => (Algorithm::RS256, self.shared.keys[2].enc.clone()),
                    _ => (Algorithm::RS256, cur.enc.clone()),
                };
                let mut header = Header::new(alg);
                header.kid = kid;
                header.typ = self.typ;
                jsonwebtoken::encode(&header, &Value::Object(self.claims), &key).expect("sign test token")
            }
        }
    }
}
