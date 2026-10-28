use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use mcpward::exchange::{ClientCredential, EntraObo, EntraOboBuilder};
use serde_json::{Value, json};
use url::Url;

/// A token endpoint failure to return.
#[derive(Clone, Debug)]
pub struct EntraError {
    status: u16,
    error: String,
    codes: Vec<u32>,
}

impl EntraError {
    /// `400 invalid_grant` with these `error_codes`.
    pub fn codes(codes: &[u32]) -> Self {
        EntraError { status: 400, error: "invalid_grant".into(), codes: codes.to_vec() }
    }
    /// A `503 temporarily_unavailable`.
    pub fn unavailable() -> Self {
        EntraError { status: 503, error: "temporarily_unavailable".into(), codes: vec![] }
    }
    /// Sets the `error` string.
    pub fn error(mut self, e: &str) -> Self {
        self.error = e.to_owned();
        self
    }
    /// Sets the HTTP status.
    pub fn status(mut self, s: u16) -> Self {
        self.status = s;
        self
    }
}

/// One recorded token request. Secrets and the user token itself are not kept; the user
/// token's payload is decoded (unverified) so tests can check which user it was for.
#[derive(Clone, Debug)]
pub struct TokenRequest {
    /// Tenant from the URL path.
    pub tenant: String,
    /// `grant_type`.
    pub grant_type: String,
    /// `client_id`.
    pub client_id: String,
    /// `scope`.
    pub scope: String,
    /// `requested_token_use`.
    pub requested_token_use: String,
    /// `client_assertion_type`, if sent.
    pub client_assertion_type: Option<String>,
    /// Whether `client_secret` was sent.
    pub has_client_secret: bool,
    /// Whether the `client_assertion` was one this mock's identity endpoint issued.
    pub assertion_from_identity_endpoint: bool,
    /// Whether some `client_assertion` was sent.
    pub has_client_assertion: bool,
    /// The decoded payload of the user token in `assertion`.
    pub assertion_claims: Value,
}

type Minter = Arc<dyn Fn(&TokenRequest) -> String + Send + Sync>;

struct EpState {
    requests: Mutex<Vec<TokenRequest>>,
    fail: Mutex<VecDeque<EntraError>>,
    minter: Mutex<Option<Minter>>,
    counter: AtomicUsize,
    identity_requests: AtomicUsize,
    identity_header: String,
    expires_in: AtomicUsize,
}

/// A mock Entra token endpoint for On-Behalf-Of, plus a mock managed-identity endpoint
/// (`IDENTITY_ENDPOINT` style). Both listen on `127.0.0.1:<random>`.
pub struct TestTokenEndpoint {
    state: Arc<EpState>,
    base: Url,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestTokenEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn decode_payload(jwt: &str) -> Value {
    jwt.split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

async fn token(
    State(s): State<Arc<EpState>>,
    Path(tenant): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();
    let assertion = f.get("client_assertion");
    let req = TokenRequest {
        tenant,
        grant_type: get("grant_type"),
        client_id: get("client_id"),
        scope: get("scope"),
        requested_token_use: get("requested_token_use"),
        client_assertion_type: f.get("client_assertion_type").cloned(),
        has_client_secret: f.contains_key("client_secret"),
        assertion_from_identity_endpoint: assertion.is_some_and(|a| a.starts_with("mock-identity-assertion-")),
        has_client_assertion: assertion.is_some(),
        assertion_claims: decode_payload(&get("assertion")),
    };
    s.requests.lock().unwrap().push(req.clone());
    if let Some(e) = s.fail.lock().unwrap().pop_front() {
        let body = json!({
            "error": e.error,
            "error_description": format!("AADSTS{}: mock failure", e.codes.first().copied().unwrap_or(0)),
            "error_codes": e.codes,
            "trace_id": "00000000-0000-0000-0000-0000000000f1",
            "correlation_id": "00000000-0000-0000-0000-0000000000f2",
        });
        return (StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST), Json(body)).into_response();
    }
    let n = s.counter.fetch_add(1, Ordering::SeqCst);
    let minter = s.minter.lock().unwrap().clone();
    let access_token = match minter {
        Some(m) => m(&req),
        None => format!("mock-obo-token-{n}"),
    };
    Json(json!({
        "token_type": "Bearer",
        "scope": req.scope,
        "expires_in": s.expires_in.load(Ordering::SeqCst),
        "ext_expires_in": 3600,
        "access_token": access_token,
    }))
    .into_response()
}

async fn identity(
    State(s): State<Arc<EpState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if headers.get("x-identity-header").and_then(|v| v.to_str().ok()) != Some(s.identity_header.as_str()) {
        return (StatusCode::UNAUTHORIZED, "bad identity header").into_response();
    }
    if q.get("resource").map(String::as_str) != Some("api://AzureADTokenExchange") || !q.contains_key("client_id") {
        return (StatusCode::BAD_REQUEST, "bad identity request").into_response();
    }
    let n = s.identity_requests.fetch_add(1, Ordering::SeqCst);
    let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + 3600;
    Json(json!({
        "access_token": format!("mock-identity-assertion-{n}"),
        "expires_on": exp.to_string(),
        "resource": "api://AzureADTokenExchange",
        "token_type": "Bearer",
        "client_id": q.get("client_id"),
    }))
    .into_response()
}

impl TestTokenEndpoint {
    /// Starts the mock endpoints.
    pub async fn start() -> TestTokenEndpoint {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.expect("bind token endpoint");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(EpState {
            requests: Mutex::new(Vec::new()),
            fail: Mutex::new(VecDeque::new()),
            minter: Mutex::new(None),
            counter: AtomicUsize::new(0),
            identity_requests: AtomicUsize::new(0),
            identity_header: format!("mock-identity-header-{}", ulid::Ulid::new()),
            expires_in: AtomicUsize::new(3600),
        });
        let app = Router::new()
            .route("/{tenant}/oauth2/v2.0/token", post(token))
            .route("/msi/token", get(identity))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestTokenEndpoint { state, base: format!("http://{addr}").parse().expect("url"), task }
    }

    /// The authority base URL to pass to `EntraOboBuilder::authority`.
    pub fn authority(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_owned()
    }

    /// The managed-identity endpoint URL.
    pub fn identity_endpoint(&self) -> Url {
        self.base.join("/msi/token").expect("url")
    }

    /// The `X-IDENTITY-HEADER` value the identity endpoint expects.
    pub fn identity_header(&self) -> &str {
        &self.state.identity_header
    }

    /// The next token request fails with `e`. Calls queue.
    pub fn fail_next(&self, e: EntraError) {
        self.state.fail.lock().unwrap().push_back(e);
    }

    /// Returns `f(request)` as the access token instead of an opaque string, for example a
    /// JWT from a second [`TestIssuer`](crate::TestIssuer) that a downstream API trusts.
    pub fn mint_with(&self, f: impl Fn(&TokenRequest) -> String + Send + Sync + 'static) {
        *self.state.minter.lock().unwrap() = Some(Arc::new(f));
    }

    /// Sets `expires_in` on successful responses. Default 3600.
    pub fn set_expires_in(&self, secs: usize) {
        self.state.expires_in.store(secs, Ordering::SeqCst);
    }

    /// Every token request so far.
    pub fn requests(&self) -> Vec<TokenRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    /// The number of token requests so far.
    pub fn request_count(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }

    /// The number of identity endpoint requests so far.
    pub fn identity_requests(&self) -> usize {
        self.state.identity_requests.load(Ordering::SeqCst)
    }

    /// A client-secret credential the mock accepts.
    pub fn obo_credential(&self) -> ClientCredential {
        ClientCredential::Secret("mock-client-secret".to_owned().into())
    }

    /// An [`EntraObo`] builder pointed at this mock.
    pub fn obo_builder(&self, tenant_id: &str, client_id: &str, credential: ClientCredential) -> EntraOboBuilder {
        EntraObo::builder(tenant_id, client_id, credential)
            .authority(&self.authority())
            .identity_endpoint(self.identity_endpoint(), Some(self.identity_header().to_owned()))
    }

    /// An [`EntraObo`] builder using a managed-identity credential against this mock.
    pub fn managed_identity_obo(&self, tenant_id: &str, client_id: &str, identity_client_id: &str) -> EntraOboBuilder {
        self.obo_builder(
            tenant_id,
            client_id,
            ClientCredential::ManagedIdentity { client_id: identity_client_id.to_owned() },
        )
    }
}
