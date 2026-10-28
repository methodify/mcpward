//! The whole chain in one process: MCP token from one test issuer, On-Behalf-Of at the mock
//! token endpoint, which returns a JWT from a second issuer that the downstream API trusts.

use std::sync::{Arc, Mutex};

use axum::{
    Json as AxumJson, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mcpward::{
    auth::{JwtValidator, Oidc, TokenValidator},
    exchange::{Downstream, ExchangeError},
};
use mcpward_testing::{EntraError, TestClient, TestIssuer, TestTokenEndpoint, conformance::Conformance};
use serde_json::{Value, json};

use super::*;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const API: &str = "00000000-0000-0000-0000-000000000002";
const ORDERS_SCOPE: &str = "api://00000000-0000-0000-0000-000000000003/access_as_user";
const URL: &str = "http://localhost/mcp";

/// `(subject, x-request-id)` per downstream call.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

#[derive(Clone)]
struct OrdersApi {
    validator: Arc<JwtValidator>,
    seen: Seen,
}

async fn authed(s: &OrdersApi, h: &HeaderMap) -> Result<String, StatusCode> {
    let token =
        h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    let p = s.validator.validate(token).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    let rid = h.get("x-request-id").and_then(|v| v.to_str().ok()).map(str::to_owned);
    s.seen.lock().unwrap().push((p.subject.key().to_owned(), rid));
    Ok(p.subject.key().to_owned())
}

async fn list(
    State(s): State<OrdersApi>,
    h: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let user = match authed(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    if q.get("email").map(String::as_str) == Some("forbidden@example.com") {
        let body = json!({"type": "about:blank", "title": "Forbidden", "status": 403, "detail": "Requires the Orders Viewer role in the orders API"});
        return (StatusCode::FORBIDDEN, AxumJson(body)).into_response();
    }
    AxumJson(json!({"orders": [{"id": "ord_1", "email": q.get("email"), "for": user}]})).into_response()
}

async fn draft(State(s): State<OrdersApi>, h: HeaderMap, AxumJson(b): AxumJson<Value>) -> Response {
    if let Err(r) = authed(&s, &h).await {
        return r.into_response();
    }
    AxumJson(json!({"id": format!("drf_{}", b["sku"].as_str().unwrap_or(""))})).into_response()
}

struct Chain {
    mcp_issuer: TestIssuer,
    _orders_issuer: TestIssuer,
    ep: TestTokenEndpoint,
    seen: Seen,
    client: TestClient,
}

async fn chain() -> Chain {
    let mcp_issuer = TestIssuer::entra(TENANT, API).start().await;
    let orders_issuer = TestIssuer::start().await;
    let ep = TestTokenEndpoint::start().await;
    // The OBO token is a JWT from the orders API's issuer, for the same user.
    let minter = orders_issuer.token();
    ep.mint_with(move |req| minter.clone().sub(req.assertion_claims["oid"].as_str().unwrap_or("")).mint());

    let cfg = Oidc::new(orders_issuer.issuer())
        .audience(mcpward_testing::TEST_AUDIENCE)
        .issuer_config(&reqwest_client())
        .await
        .unwrap();
    let validator = Arc::new(
        JwtValidator::builder()
            .issuer(cfg)
            .required_scopes(["access_as_user"])
            .allow_any_client()
            .build()
            .await
            .unwrap(),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/orders/v1/orders", get(list))
        .route("/orders/v1/orders/drafts", post(draft))
        .with_state(OrdersApi { validator, seen: seen.clone() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/orders", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let obo = ep.obo_builder(TENANT, API, ep.obo_credential()).build().unwrap();
    let api = Arc::new(
        Downstream::builder("orders-api", base.parse().unwrap())
            .exchanger(Arc::new(obo))
            .scopes([ORDERS_SCOPE])
            .propagate_request_id(true)
            .build()
            .unwrap(),
    );
    let s = build(&mcp_issuer, api).await;
    Chain { mcp_issuer, _orders_issuer: orders_issuer, ep, seen, client: TestClient::new(s) }
}

fn reqwest_client() -> mcpward::reqwest::Client {
    mcpward::reqwest::Client::new()
}

async fn build(issuer: &TestIssuer, api: Arc<Downstream>) -> McpServer {
    server(api).resource_url(URL).unwrap().auth(issuer.auth_for(URL)).build().await.unwrap()
}

async fn build_for_conformance(issuer: &TestIssuer) -> McpServer {
    // Conformance needs no downstream calls; the exchanger is never reached.
    let ep = TestTokenEndpoint::start().await;
    let obo = ep.obo_builder(TENANT, API, ep.obo_credential()).build().unwrap();
    let api = Arc::new(
        Downstream::builder("orders-api", "http://127.0.0.1:9/orders".parse().unwrap())
            .exchanger(Arc::new(obo))
            .scopes([ORDERS_SCOPE])
            .build()
            .unwrap(),
    );
    build(issuer, api).await
}

// The connector-style setup: role denial as 403 insufficient_scope is covered in the probe
// tests; this example keeps the default in-band denial.
mcpward_testing::conformance! {
    issuer = TestIssuer::entra(TENANT, API).start(),
    server = build_for_conformance,
    config = Conformance::new(URL, "whoami").caller_roles(&["Orders.Reader"]).role_tool("draft_order", "Orders.Writer"),
}

#[tokio::test]
async fn reader_cannot_draft() {
    let c = chain().await;
    let token = c.mcp_issuer.token().roles(&["Orders.Reader"]).mint();
    let tools = c.client.list_tools(&token).await;
    assert!(tools.names().contains(&"find_orders"));
    assert!(!tools.names().contains(&"draft_order"));
    let res = c.client.call_tool(&token, "draft_order", json!({"sku": "A1", "quantity": 1})).await;
    assert_eq!(res.status, 200);
    assert!(res.is_tool_error());
    assert_eq!(c.ep.request_count(), 0, "denied before any exchange");
}

#[tokio::test]
async fn whole_chain_find_and_draft() {
    let c = chain().await;
    let token = c.mcp_issuer.token().roles(&["Orders.Writer"]).mint();
    let r = c.client.call_tool(&token, "find_orders", json!({"email": "pat@example.com"})).await;
    assert!(!r.is_tool_error(), "{}", r.text());
    let orders = &r.structured().unwrap()["orders"];
    assert_eq!(orders[0]["email"], "pat@example.com");
    // The downstream API saw the same user, through a token from its own issuer.
    assert_eq!(orders[0]["for"], mcpward_testing::TEST_OID);
    let r = c.client.call_tool(&token, "draft_order", json!({"sku": "A1", "quantity": 2})).await;
    assert_eq!(r.structured().unwrap()["id"], "drf_A1", "{}", r.text());
    assert_eq!(c.ep.request_count(), 1, "the OBO token is cached across calls");
    let req = &c.ep.requests()[0];
    assert_eq!(req.scope, ORDERS_SCOPE);
    assert_eq!(req.requested_token_use, "on_behalf_of");
}

#[tokio::test]
async fn request_id_propagates_without_overwrite() {
    let c = chain().await;
    let token = c.mcp_issuer.token().roles(&["Orders.Reader"]).mint();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "find_orders", "arguments": {"email": "a@example.com"}}});
    let r = c
        .client
        .post_raw(Some(&token), body, &[("mcp-protocol-version", "2025-11-25"), ("x-request-id", "req-from-client")])
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(c.seen.lock().unwrap().last().unwrap().1.as_deref(), Some("req-from-client"));
}

#[tokio::test]
async fn downstream_403_is_a_tool_error_with_detail() {
    let c = chain().await;
    let token = c.mcp_issuer.token().roles(&["Orders.Reader"]).mint();
    let r = c.client.call_tool(&token, "find_orders", json!({"email": "forbidden@example.com"})).await;
    assert_eq!(r.status, 200, "never an HTTP error from the MCP server");
    assert!(r.is_tool_error());
    assert!(r.structured().is_none());
    let v: Value = serde_json::from_str(r.tool_text().unwrap()).unwrap();
    assert_eq!(v["error"], "forbidden");
    assert_eq!(v["status"], 403);
    assert_eq!(v["message"], "Requires the Orders Viewer role in the orders API");
    assert_eq!(v["detail"]["title"], "Forbidden");
}

#[tokio::test]
async fn consent_failure_is_actionable() {
    let c = chain().await;
    c.ep.fail_next(EntraError::codes(&[65001]));
    let token = c.mcp_issuer.token().roles(&["Orders.Reader"]).mint();
    let r = c.client.call_tool(&token, "find_orders", json!({"email": "a@example.com"})).await;
    assert!(r.is_tool_error());
    let v: Value = serde_json::from_str(r.tool_text().unwrap()).unwrap();
    assert_eq!(v["error"], "consent_required");
    assert_eq!(v["message"], ExchangeError::ConsentRequired { codes: vec![] }.user_message());
}
