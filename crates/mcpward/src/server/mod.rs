//! The axum + rmcp server: [`McpServer`], its builder, the auth and policy layers, handler
//! extractors, and serving with graceful shutdown.
//!
//! Layers for `POST {mcp_path}`, outermost first: request ID and timeout, the `mcp.request`
//! span, the auth layer (token checks, base scopes, principal into extensions, `Authorization`
//! removed), the policy layer (per-call requirements, list filtering), and rmcp's stateless
//! Streamable HTTP service. Metadata and health routes bypass auth.

mod auth_config;
mod auth_layer;
pub mod docs;
mod env;
mod extract;
mod failure;
mod info;
mod obs;
mod policy;
pub mod schema;

use std::{
    collections::BTreeSet,
    fmt,
    future::{Future, IntoFuture},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    middleware::{from_fn, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::get,
};
use http::{HeaderValue, StatusCode, header};
use rmcp::{
    ServerHandler,
    handler::server::router::{prompt::PromptRouter, tool::ToolRouter},
    service::MaybeSend,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;

#[cfg(feature = "dev-auth")]
pub use auth_config::DevIdentity;
pub use auth_config::{Auth, AuthBuilder, DEV_NON_LOOPBACK_ACK};
pub use extract::{Caller, RequestMeta};
pub use failure::ToolFailure;
pub use info::server_info;
pub use policy::{Policies, Require, RoleDenial};

use crate::{
    ConfigError,
    auth::{BoxFuture, Challenge, ChallengeContext, ResourceMetadata, ResourceUrl, Scope, TokenValidator},
};

#[cfg(feature = "dev-auth")]
use crate::auth::Principal;

pub(crate) enum AuthMode {
    Token(Arc<dyn TokenValidator>),
    #[cfg(feature = "dev-auth")]
    Dev(Arc<Principal>),
}

pub(crate) struct ServerState {
    pub(crate) auth: AuthMode,
    pub(crate) ctx: ChallengeContext,
    pub(crate) base_scopes: Vec<Scope>,
    pub(crate) scope_prefix: Option<String>,
    pub(crate) policies: Policies,
    pub(crate) max_body_bytes: usize,
    pub(crate) trust_forwarded_for: usize,
    prm: Value,
    readiness: Vec<Arc<dyn ReadinessCheck>>,
}

impl ServerState {
    pub(crate) fn challenge(&self, c: &Challenge) -> Response {
        let mut r = (c.status(), c.body().to_string()).into_response();
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(h) = c.www_authenticate(&self.ctx) {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, h);
        }
        r
    }

    pub(crate) fn scope_form(&self, claim: &str) -> Scope {
        match &self.scope_prefix {
            Some(p) if !claim.contains("://") => Scope::new(claim).with_challenge(format!("{p}{claim}")),
            _ => Scope::new(claim),
        }
    }

    fn validator_ready(&self) -> bool {
        match &self.auth {
            AuthMode::Token(v) => v.ready(),
            #[cfg(feature = "dev-auth")]
            AuthMode::Dev(_) => true,
        }
    }
}

/// A readiness check for `/readyz`.
pub trait ReadinessCheck: Send + Sync + 'static {
    /// The name reported when the check fails.
    fn name(&self) -> &str;
    /// Whether the dependency is ready.
    fn check(&self) -> BoxFuture<'_, bool>;
}

/// Why serving failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The listener couldn't bind.
    #[error("could not bind {addr}: {source}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The cause.
        source: std::io::Error,
    },
    /// The server failed.
    #[error("server error: {0}")]
    Io(#[from] std::io::Error),
    /// Dev auth mode was asked to serve on a socket that isn't loopback.
    #[error("refusing to serve dev auth mode on {0}; listen on a loopback address")]
    DevNonLoopback(SocketAddr),
}

type RmcpTweak = Box<dyn FnOnce(StreamableHttpServerConfig) -> StreamableHttpServerConfig + Send>;

/// Builds an [`McpServer`].
pub struct McpServerBuilder<H> {
    handler: H,
    resource_url: Option<String>,
    resource_name: Option<String>,
    resource_documentation: Option<String>,
    serve_root_prm: bool,
    advertise_tool_scopes: bool,
    auth: Option<AuthBuilder>,
    tools: Option<Vec<rmcp::model::Tool>>,
    prompts: Option<Vec<String>>,
    policies: Option<Policies>,
    #[cfg(feature = "exchange")]
    downstreams: Vec<Arc<crate::exchange::Downstream>>,
    readiness: Vec<Arc<dyn ReadinessCheck>>,
    bind: SocketAddr,
    allowed_origins: Vec<String>,
    extra_allowed_hosts: Vec<String>,
    shutdown_timeout: Duration,
    request_timeout: Duration,
    trust_forwarded_for: usize,
    health_paths: Option<(String, String)>,
    max_body_bytes: usize,
    rmcp_config: Option<RmcpTweak>,
}

impl<H> fmt::Debug for McpServerBuilder<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpServerBuilder")
            .field("resource_url", &self.resource_url)
            .field("bind", &self.bind)
            .field("policies", &self.policies)
            .finish_non_exhaustive()
    }
}

/// A built server: serve it, or mount its router in a larger app.
pub struct McpServer {
    router: Router,
    bind: SocketAddr,
    shutdown_timeout: Duration,
    cancel: CancellationToken,
    resource: ResourceUrl,
    dev_banner: Option<String>,
    dev_requires_loopback: bool,
}

impl fmt::Debug for McpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpServer")
            .field("resource", &self.resource.as_str())
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl McpServer {
    /// Starts a builder for an rmcp handler. The handler is cloned per request; keep shared
    /// state behind `Arc`.
    pub fn builder<H>(handler: H) -> McpServerBuilder<H>
    where
        H: ServerHandler + Clone + Send + Sync + 'static,
    {
        McpServerBuilder {
            handler,
            resource_url: None,
            resource_name: None,
            resource_documentation: None,
            serve_root_prm: false,
            advertise_tool_scopes: false,
            auth: None,
            tools: None,
            prompts: None,
            policies: None,
            #[cfg(feature = "exchange")]
            downstreams: Vec::new(),
            readiness: Vec::new(),
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            allowed_origins: Vec::new(),
            extra_allowed_hosts: Vec::new(),
            shutdown_timeout: Duration::from_secs(25),
            request_timeout: Duration::from_secs(120),
            trust_forwarded_for: 0,
            health_paths: Some(("/healthz".into(), "/readyz".into())),
            max_body_bytes: 1024 * 1024,
            rmcp_config: None,
        }
    }

    /// The canonical resource URL.
    pub fn resource_url(&self) -> &str {
        self.resource.as_str()
    }

    /// The MCP route path.
    pub fn mcp_path(&self) -> &str {
        self.resource.mcp_path()
    }

    /// The bind address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind
    }

    /// The axum router, to mount in a larger app or drive in tests.
    ///
    /// In dev auth mode the loopback check covers only the configured bind address and
    /// [`serve_listener`](Self::serve_listener); when you serve the router yourself, you are
    /// responsible for listening on loopback.
    pub fn router(self) -> Router {
        self.router
    }

    /// Binds, serves, and shuts down gracefully on SIGTERM or Ctrl-C.
    pub async fn serve(self) -> Result<(), ServeError> {
        self.serve_with_shutdown(shutdown_signal()).await
    }

    /// Binds and serves until `signal` completes, then stops accepting connections and drains
    /// in-flight requests for up to the shutdown timeout.
    pub async fn serve_with_shutdown(
        self,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServeError> {
        let listener = tokio::net::TcpListener::bind(self.bind)
            .await
            .map_err(|source| ServeError::Bind { addr: self.bind, source })?;
        let addr = listener.local_addr().unwrap_or(self.bind);
        tracing::info!(target: "mcpward", %addr, resource = %self.resource.as_str(), "listening");
        self.serve_listener(listener, signal).await
    }

    /// Serves on an existing listener (for example one bound to port 0 in tests).
    pub async fn serve_listener(
        self,
        listener: tokio::net::TcpListener,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServeError> {
        if self.dev_requires_loopback {
            let addr = listener.local_addr()?;
            if !addr.ip().is_loopback() {
                return Err(ServeError::DevNonLoopback(addr));
            }
        }
        let banner_task = self.dev_banner.clone().map(|banner| {
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    tracing::warn!(target: "mcpward", "{banner}");
                }
            })
        });
        let notify = Arc::new(tokio::sync::Notify::new());
        let n2 = notify.clone();
        let app = self.router.into_make_service_with_connect_info::<SocketAddr>();
        let server = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                signal.await;
                n2.notify_one();
            })
            .into_future();
        tokio::pin!(server);
        let result = tokio::select! {
            r = &mut server => r,
            _ = notify.notified() => {
                tracing::info!(target: "mcpward", "shutting down; draining in-flight requests");
                match tokio::time::timeout(self.shutdown_timeout, &mut server).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(target: "mcpward", timeout = ?self.shutdown_timeout, "requests still running at the shutdown timeout; stopping");
                        Ok(())
                    }
                }
            }
        };
        self.cancel.cancel();
        if let Some(t) = banner_task {
            t.abort();
        }
        result.map_err(ServeError::Io)
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

impl<H> McpServerBuilder<H>
where
    H: ServerHandler + Clone + Send + Sync + 'static,
{
    /// The canonical MCP URL, for example `https://mcp.example.com/mcp`.
    pub fn resource_url(mut self, url: &str) -> Result<Self, ConfigError> {
        ResourceUrl::parse(url, true)?;
        self.resource_url = Some(url.to_owned());
        Ok(self)
    }

    /// `resource_name` in metadata.
    pub fn resource_name(mut self, name: &str) -> Self {
        self.resource_name = Some(name.to_owned());
        self
    }

    /// `resource_documentation` in metadata.
    pub fn resource_documentation(mut self, url: &str) -> Self {
        self.resource_documentation = Some(url.to_owned());
        self
    }

    /// Also serve metadata at the root well-known path. Off by default: RFC 9728 ties the
    /// document to the path-inserted URL, and mcpward always sends `resource_metadata`.
    pub fn serve_root_prm(mut self, on: bool) -> Self {
        self.serve_root_prm = on;
        self
    }

    /// Also list per-tool scopes in `scopes_supported`. Off by default.
    pub fn advertise_tool_scopes(mut self, on: bool) -> Self {
        self.advertise_tool_scopes = on;
        self
    }

    /// Authentication.
    pub fn auth(mut self, auth: AuthBuilder) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Declares a tool router so `build()` can check every tool has a policy. Pass the same
    /// router the handler holds. May be called more than once.
    pub fn tools<S: MaybeSend + 'static>(mut self, router: &ToolRouter<S>) -> Self {
        self.tools.get_or_insert_with(Vec::new).extend(router.list_all());
        self
    }

    /// Declares a prompt router for the same check.
    pub fn prompts<S: MaybeSend + 'static>(mut self, router: &PromptRouter<S>) -> Self {
        self.prompts.get_or_insert_with(Vec::new).extend(router.list_all().into_iter().map(|p| p.name.to_string()));
        self
    }

    /// The policy table.
    pub fn policies(mut self, p: Policies) -> Self {
        self.policies = Some(p);
        self
    }

    /// Registers a downstream API (logged at startup; checked against dev mode).
    #[cfg(feature = "exchange")]
    pub fn downstream(mut self, d: Arc<crate::exchange::Downstream>) -> Self {
        self.downstreams.push(d);
        self
    }

    /// Adds a `/readyz` check.
    pub fn readiness(mut self, c: impl ReadinessCheck) -> Self {
        self.readiness.push(Arc::new(c));
        self
    }

    /// Listen address. Default `0.0.0.0:8080`.
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind = addr;
        self
    }

    /// Browser origins allowed to call the MCP endpoint. Origin validation is always on;
    /// requests without `Origin` pass.
    pub fn allowed_origins<I, S>(mut self, o: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_origins = o.into_iter().map(Into::into).collect();
        self
    }

    /// Extra `Host` values to accept besides the resource URL's host.
    pub fn extra_allowed_hosts<I, S>(mut self, h: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extra_allowed_hosts = h.into_iter().map(Into::into).collect();
        self
    }

    /// How long to drain requests on shutdown. Default 25 s.
    pub fn shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }

    /// Per-request timeout. Default 120 s.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// Take the client IP for logs from the n-th hop from the right of `X-Forwarded-For`.
    /// Default 0 (off).
    pub fn trust_forwarded_for(mut self, hops: usize) -> Self {
        self.trust_forwarded_for = hops;
        self
    }

    /// Health and readiness paths, or `None` to disable them. Default `/healthz`, `/readyz`.
    pub fn health_paths(mut self, paths: Option<(&str, &str)>) -> Self {
        self.health_paths = paths.map(|(a, b)| (a.to_owned(), b.to_owned()));
        self
    }

    /// Maximum request body. Default 1 MiB.
    pub fn max_body_bytes(mut self, n: usize) -> Self {
        self.max_body_bytes = n;
        self
    }

    /// Adjusts rmcp's transport configuration. mcpward re-applies `legacy_session_mode(false)`
    /// and `json_response(true)` afterwards and refuses a session store.
    pub fn rmcp_config(
        mut self,
        f: impl FnOnce(StreamableHttpServerConfig) -> StreamableHttpServerConfig + Send + 'static,
    ) -> Self {
        self.rmcp_config = Some(Box::new(f));
        self
    }

    /// Reads `MCPWARD_*` environment variables. Programmatic calls after this win.
    pub fn from_env(self) -> Result<Self, ConfigError> {
        self.from_env_prefixed("MCPWARD_")
    }

    /// Reads environment variables with a custom prefix, for example `MYAPP_MCP_`.
    pub fn from_env_prefixed(self, prefix: &str) -> Result<Self, ConfigError> {
        self.from_env_with(prefix, |k| std::env::var(k).ok())
    }

    /// Reads settings through `lookup` instead of the process environment (for tests).
    pub fn from_env_with(self, prefix: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        env::apply(self, prefix, &lookup)
    }

    /// Validates everything, loads signing keys, and assembles the router.
    pub async fn build(self) -> Result<McpServer, ConfigError> {
        let auth = self.auth.ok_or(ConfigError::NoAuth)?;
        let dev = auth.is_dev();
        let dev_requires_loopback = auth.dev_requires_loopback();
        let raw = self
            .resource_url
            .as_deref()
            .ok_or_else(|| ConfigError::ResourceUrl("required; call resource_url(..)".into()))?;
        let resource = ResourceUrl::parse(raw, dev)?;

        // Policies: deny by default, checked against the declared routers.
        let policies = self.policies.unwrap_or_default();
        let Some(tools) = self.tools else {
            return Err(ConfigError::RoutersNotDeclared);
        };
        let tool_names: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
        for t in &tools {
            let req = policies.for_tool(&t.name);
            match req {
                None => return Err(ConfigError::UnpolicedTool { name: t.name.to_string() }),
                Some(r) => {
                    let destructive = t.annotations.as_ref().and_then(|a| a.destructive_hint) == Some(true);
                    if destructive && !r.has_role_rule() && !r.has_scope_rule() {
                        tracing::warn!(target: "mcpward", tool = %t.name, "destructive tool open to every authenticated user");
                    }
                }
            }
        }
        for name in policies.tools.keys() {
            if !tool_names.contains(name) {
                return Err(ConfigError::UnknownPolicyTarget { name: name.clone() });
            }
        }
        if let Some(prompts) = &self.prompts {
            for p in prompts {
                if policies.for_prompt(p).is_none() {
                    return Err(ConfigError::UnpolicedTool { name: p.clone() });
                }
            }
            for name in policies.prompts.keys() {
                if !prompts.contains(name) {
                    return Err(ConfigError::UnknownPolicyTarget { name: name.clone() });
                }
            }
        }

        #[cfg(feature = "exchange")]
        if dev && self.downstreams.iter().any(|d| d.requires_user_token()) {
            return Err(ConfigError::invalid(
                "downstream",
                "dev auth mode can't be combined with a token exchanger; use StaticToken or NoAuth for downstream calls in dev",
            ));
        }

        let built = auth.build(&resource, self.bind).await?;

        let mut scopes_supported = built.base_scopes.clone();
        if self.advertise_tool_scopes {
            let st_prefix = built.scope_prefix.clone();
            for r in policies.tools.values() {
                for s in r.scope_names() {
                    let sc = match &st_prefix {
                        Some(p) if !s.contains("://") => Scope::new(s).with_challenge(format!("{p}{s}")),
                        _ => Scope::new(s),
                    };
                    if !scopes_supported.contains(&sc) {
                        scopes_supported.push(sc);
                    }
                }
            }
        }
        let prm = ResourceMetadata {
            resource: resource.clone(),
            authorization_server: built.authorization_server.clone(),
            scopes_supported,
            resource_name: self.resource_name.clone(),
            resource_documentation: self.resource_documentation.clone(),
            serve_root: self.serve_root_prm,
        };

        let cancel = CancellationToken::new();
        let mut cfg = StreamableHttpServerConfig::default();
        if let Some(f) = self.rmcp_config {
            cfg = f(cfg);
        }
        if cfg.session_store.is_some() {
            return Err(ConfigError::invalid(
                "rmcp_config",
                "sessions conflict with per-request auth; remove the session store",
            ));
        }
        let mut hosts = resource.allowed_hosts();
        hosts.extend(self.extra_allowed_hosts.iter().cloned());
        let cfg = cfg
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            .with_allowed_hosts(hosts)
            .with_allowed_origins(self.allowed_origins.clone())
            .enforce_origin_validation()
            .with_max_request_body_bytes(self.max_body_bytes)
            .with_cancellation_token(cancel.child_token());
        let handler = self.handler;
        let service =
            StreamableHttpService::new(move || Ok(handler.clone()), Arc::new(NeverSessionManager::default()), cfg);

        let state = Arc::new(ServerState {
            auth: built.mode,
            ctx: ChallengeContext {
                resource_metadata: resource.resource_metadata_url(),
                base_scopes: built.base_scopes.clone(),
            },
            base_scopes: built.base_scopes,
            scope_prefix: built.scope_prefix,
            policies,
            max_body_bytes: self.max_body_bytes,
            trust_forwarded_for: self.trust_forwarded_for,
            prm: prm.to_json(),
            readiness: self.readiness,
        });

        let mcp = ServiceBuilder::new()
            .layer(from_fn_with_state(state.clone(), obs::trace_mw))
            .layer(from_fn_with_state(state.clone(), auth_layer::auth_mw))
            .layer(from_fn_with_state(state.clone(), policy::policy_mw))
            .service(service);

        let mut router = Router::new();
        for path in prm.well_known_paths() {
            router = router.route(&path, get(prm_handler));
        }
        if let Some((health, ready)) = &self.health_paths {
            router = router.route(health, get(|| async { "ok" })).route(ready, get(ready_handler));
        }
        router = router.route_service(resource.mcp_path(), mcp);
        let router = router.with_state(state.clone()).layer(
            ServiceBuilder::new()
                .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(obs::UlidRequestId))
                .layer(tower_http::request_id::PropagateRequestIdLayer::x_request_id())
                .layer(tower_http::timeout::TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    self.request_timeout,
                )),
        );
        let router = if built.dev_banner.is_some() {
            router.layer(from_fn(|req: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut r = next.run(req).await;
                r.headers_mut().insert("x-mcpward-dev-auth", HeaderValue::from_static("true"));
                r
            }))
        } else {
            router
        };

        if let Some(b) = &built.dev_banner {
            tracing::error!(target: "mcpward", "{b}");
        }
        #[cfg(feature = "exchange")]
        let downstreams: Vec<String> = self.downstreams.iter().map(|d| d.describe()).collect();
        #[cfg(not(feature = "exchange"))]
        let downstreams: Vec<String> = Vec::new();
        tracing::info!(
            target: "mcpward",
            resource = %resource.as_str(),
            mode = if dev { "dev" } else { "token" },
            auth = %built.summary,
            policies = state.policies.len(),
            default_policy = state.policies.default.is_some(),
            role_denial = ?state.policies.role_denial,
            downstreams = ?downstreams,
            "mcpward configured"
        );

        Ok(McpServer {
            router,
            bind: self.bind,
            shutdown_timeout: self.shutdown_timeout,
            cancel,
            resource,
            dev_banner: built.dev_banner,
            dev_requires_loopback,
        })
    }
}

async fn prm_handler(State(st): State<Arc<ServerState>>) -> Response {
    let mut r = st.prm.to_string().into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    r
}

async fn ready_handler(State(st): State<Arc<ServerState>>) -> Response {
    let mut failing = Vec::new();
    if !st.validator_ready() {
        failing.push("signing_keys".to_owned());
    }
    for c in &st.readiness {
        if !c.check().await {
            failing.push(c.name().to_owned());
        }
    }
    if failing.is_empty() {
        (StatusCode::OK, "ready").into_response()
    } else {
        let mut r = (StatusCode::SERVICE_UNAVAILABLE, json!({"failing": failing}).to_string()).into_response();
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        r
    }
}
