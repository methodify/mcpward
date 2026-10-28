//! Request observability: the `mcp.request` span and its fields.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use tracing::{Instrument, field::Empty};

use super::{RequestMeta, ServerState};
use crate::auth::truncate_for_log;

#[derive(Default)]
struct ObsData {
    outcome: Option<&'static str>,
    reject_reason: Option<&'static str>,
    subject: Option<String>,
    tenant: Option<String>,
    client_id: Option<String>,
    method: Option<String>,
    tool: Option<String>,
}

/// Collects fields as the request passes through the layers; written to the span once at the
/// end.
#[derive(Clone, Default)]
pub(crate) struct Obs(Arc<Mutex<ObsData>>);

impl Obs {
    fn with(&self, f: impl FnOnce(&mut ObsData)) {
        if let Ok(mut d) = self.0.lock() {
            f(&mut d);
        }
    }
    pub(crate) fn outcome(&self, o: &'static str) {
        self.with(|d| d.outcome = Some(o));
    }
    pub(crate) fn reject(&self, r: &'static str) {
        self.with(|d| d.reject_reason = Some(r));
    }
    pub(crate) fn principal(&self, subject: &str, tenant: Option<&str>, client: Option<&str>) {
        self.with(|d| {
            d.subject = Some(subject.to_owned());
            d.tenant = tenant.map(str::to_owned);
            d.client_id = client.map(str::to_owned);
        });
    }
    pub(crate) fn method(&self, m: &str) {
        self.with(|d| d.method = Some(truncate_for_log(m)));
    }
    pub(crate) fn tool(&self, t: &str) {
        self.with(|d| d.tool = Some(truncate_for_log(t)));
    }
}

fn client_ip(req: &Request, trust_hops: usize) -> Option<IpAddr> {
    let socket = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    if trust_hops == 0 {
        return socket;
    }
    let xff: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    xff.len().checked_sub(trust_hops).and_then(|i| xff.get(i)).and_then(|s| s.parse().ok()).or(socket)
}

/// Opens `mcp.request`, inserts [`RequestMeta`] and [`Obs`], and records the outcome.
pub(crate) async fn trace_mw(State(st): State<Arc<ServerState>>, mut req: Request, next: Next) -> Response {
    let start = Instant::now();
    let request_id =
        req.headers().get("x-request-id").and_then(|v| v.to_str().ok()).map(truncate_for_log).unwrap_or_default();
    let protocol_version =
        req.headers().get("mcp-protocol-version").and_then(|v| v.to_str().ok()).map(truncate_for_log);
    let meta = RequestMeta {
        request_id: request_id.clone(),
        protocol_version: protocol_version.clone(),
        client_ip: client_ip(&req, st.trust_forwarded_for),
        traceparent: req.headers().get("traceparent").and_then(|v| v.to_str().ok()).map(truncate_for_log),
    };
    let obs = Obs::default();
    req.extensions_mut().insert(obs.clone());
    req.extensions_mut().insert(meta.clone());
    let span = tracing::info_span!(
        target: "mcpward::request",
        "mcp.request",
        request_id = %request_id,
        http.method = %req.method(),
        http.status = Empty,
        mcp.method = Empty,
        mcp.tool = Empty,
        mcp.protocol_version = Empty,
        subject = Empty,
        tenant = Empty,
        client_id = Empty,
        client_ip = Empty,
        outcome = Empty,
        reject_reason = Empty,
        latency_ms = Empty,
    );
    let resp = next.run(req).instrument(span.clone()).await;
    let status = resp.status();
    let latency = start.elapsed().as_millis() as u64;
    let d = obs.0.lock().map(|mut d| std::mem::take(&mut *d)).unwrap_or_default();
    let outcome = d.outcome.unwrap_or(if status.is_success() {
        "ok"
    } else if status.is_client_error() {
        "bad_request"
    } else {
        "error"
    });
    span.record("http.status", status.as_u16());
    span.record("outcome", outcome);
    span.record("latency_ms", latency);
    if let Some(v) = &protocol_version {
        span.record("mcp.protocol_version", v.as_str());
    }
    if let Some(ip) = meta.client_ip {
        span.record("client_ip", tracing::field::display(ip));
    }
    for (k, v) in [
        ("mcp.method", &d.method),
        ("mcp.tool", &d.tool),
        ("subject", &d.subject),
        ("tenant", &d.tenant),
        ("client_id", &d.client_id),
    ] {
        if let Some(v) = v {
            span.record(k, v.as_str());
        }
    }
    if let Some(r) = d.reject_reason {
        span.record("reject_reason", r);
    }
    span.in_scope(|| {
        tracing::info!(
            target: "mcpward::request",
            http_status = status.as_u16(),
            mcp_method = d.method.as_deref().unwrap_or(""),
            mcp_tool = d.tool.as_deref().unwrap_or(""),
            subject = d.subject.as_deref().unwrap_or(""),
            client_id = d.client_id.as_deref().unwrap_or(""),
            outcome,
            reject_reason = d.reject_reason.unwrap_or(""),
            latency_ms = latency,
            "mcp request"
        );
    });
    resp
}

/// `x-request-id` values: ULIDs.
#[derive(Clone, Copy, Default)]
pub(crate) struct UlidRequestId;

impl tower_http::request_id::MakeRequestId for UlidRequestId {
    fn make_request_id<B>(&mut self, _req: &http::Request<B>) -> Option<tower_http::request_id::RequestId> {
        http::HeaderValue::from_str(&ulid::Ulid::new().to_string()).ok().map(tower_http::request_id::RequestId::new)
    }
}
