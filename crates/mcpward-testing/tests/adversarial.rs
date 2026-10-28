//! Adversarial tests: attempts to get past the auth and policy layers with request shapes the
//! policy layer and rmcp might read differently.

mod common;

use axum::body::Body;
use common::*;
use http::{Request, header};
use mcpward_testing::{TestClient, TestIssuer, TestResponse};
use serde_json::json;

async fn client() -> (TestIssuer, TestClient) {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let c = TestClient::new(server(&issuer).await);
    (issuer, c)
}

async fn raw(c: &TestClient, token: &str, body: &[u8], extra: &[(&str, &str)]) -> TestResponse {
    let mut b = Request::post(c.mcp_path())
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    c.send(b.body(Body::from(body.to_vec())).unwrap()).await
}

/// `write` needs the Writer role; the default token has none. A success result echoes the
/// text in structuredContent, so seeing it means the policy layer was bypassed.
fn bypassed(r: &TestResponse) -> bool {
    r.text().contains("PWNED") && !r.is_tool_error()
}

#[tokio::test]
async fn baseline_write_is_denied() {
    let (issuer, c) = client().await;
    let t = issuer.token().mint();
    let r = c.call_tool(&t, "write", json!({"text": "PWNED"})).await;
    assert!(!bypassed(&r), "{}", r.text());
    assert!(r.is_tool_error());
}

#[tokio::test]
async fn bypass_attempts_by_body_shape() {
    let (issuer, c) = client().await;
    let t = issuer.token().mint();
    let deep_open = "[".repeat(120);
    let deep_close = "]".repeat(120);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "duplicate name, allowed last",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","name":"whoami","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "duplicate name, allowed first",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "duplicate method, harmless last",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping","params":{"name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "duplicate params",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}},"params":{"name":"whoami"}}"#.to_vec(),
        ),
        (
            "lone surrogate in an ignored field",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}},"x":"\ud800"}"#.to_vec(),
        ),
        (
            "lone surrogate in _meta",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"},"_meta":{"x":"\ud800"}}}"#.to_vec(),
        ),
        (
            "utf-8 bom",
            [&[0xEF, 0xBB, 0xBF][..], br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}}"#].concat(),
        ),
        (
            "deep nesting in an ignored field",
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"write","arguments":{{"text":"PWNED"}}}},"x":{deep_open}{deep_close}}}"#
            )
            .into_bytes(),
        ),
        (
            "trailing garbage",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}} xx"#.to_vec(),
        ),
        (
            "escaped name",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "notification-shaped call",
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "batch",
            br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}}]"#.to_vec(),
        ),
        (
            "string id with numeric look",
            br#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
        (
            "huge float id",
            br#"{"jsonrpc":"2.0","id":1e2,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"}}}"#.to_vec(),
        ),
    ];
    let mut failures = Vec::new();
    for (label, body) in &cases {
        let r = raw(&c, &t, body, &[]).await;
        eprintln!("{label}: {} {}", r.status, r.text().chars().take(200).collect::<String>());
        if bypassed(&r) {
            failures.push(*label);
        }
        // Bodies the policy layer can't read exactly one way stop there, with 400.
        let fail_closed = label.starts_with("duplicate")
            || label.starts_with("lone surrogate")
            || ["utf-8 bom", "trailing garbage", "batch"].contains(label);
        if fail_closed && r.status != 400 {
            failures.push(*label);
        }
    }
    assert!(failures.is_empty(), "policy bypassed or not refused by: {failures:?}");
}

#[tokio::test]
async fn bypass_attempts_by_headers() {
    let (issuer, c) = client().await;
    let t = issuer.token().mint();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"PWNED"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"1"}}}}"#;
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("mcp-name says whoami", vec![("mcp-method", "tools/call"), ("mcp-name", "whoami")]),
        ("mcp-method says ping", vec![("mcp-method", "ping"), ("mcp-name", "write")]),
        ("content-type text/plain", vec![("content-type", "text/plain")]),
        ("content-encoding gzip", vec![("content-encoding", "gzip")]),
    ];
    let mut failures = Vec::new();
    for (label, hs) in &cases {
        let mut b = Request::post(c.mcp_path())
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header(header::AUTHORIZATION, format!("Bearer {t}"));
        if !hs.iter().any(|(k, _)| *k == "content-type") {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in hs {
            b = b.header(*k, *v);
        }
        let r = c.send(b.body(Body::from(body.to_vec())).unwrap()).await;
        eprintln!("{label}: {} {}", r.status, r.text().chars().take(200).collect::<String>());
        if bypassed(&r) {
            failures.push(*label);
        }
    }
    assert!(failures.is_empty(), "policy bypassed by: {failures:?}");
}

#[tokio::test]
async fn token_transport_rules() {
    let (issuer, c) = client().await;
    let t = issuer.token().mint();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}"#;
    let post = || {
        Request::post(c.mcp_path())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25")
    };
    // Two Authorization headers: 400 invalid_request.
    let r = c
        .send(
            post()
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .header(header::AUTHORIZATION, "Bearer x")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    // Lowercase scheme is accepted (RFC 7235 schemes are case-insensitive).
    let r = c
        .send(post().header(header::AUTHORIZATION, format!("bearer {t}")).body(Body::from(body.to_vec())).unwrap())
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    // Token in the query string, even alongside a valid header: 400.
    let r = c
        .send(
            Request::post(format!("{}?access_token={t}", c.mcp_path()))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    // Form body: 400.
    let r = c
        .send(
            Request::post(c.mcp_path())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={t}")))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    // No token: exactly the documented 401 challenge.
    let r = c.send(post().body(Body::from(body.to_vec())).unwrap()).await;
    assert_eq!(r.status, 401);
    assert_eq!(
        r.www_authenticate().unwrap(),
        format!(
            r#"Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp", scope="api://{API}/access_as_user""#
        )
    );
    // Expired: 401 invalid_token with the same parameters first.
    let r = c.call_tool(&issuer.token().expired().mint(), "whoami", json!({})).await;
    assert_eq!(r.status, 401);
    assert!(r.www_authenticate().unwrap().contains(r#"error="invalid_token""#));
    // Every HTTP method on the MCP path goes through auth.
    for m in [http::Method::GET, http::Method::DELETE, http::Method::PUT, http::Method::PATCH] {
        let r = c.send(Request::builder().method(m.clone()).uri(c.mcp_path()).body(Body::empty()).unwrap()).await;
        assert_eq!(r.status, 401, "{m}");
    }
}

#[tokio::test]
async fn nesting_depth_boundary_is_consistent() {
    let (issuer, c) = client().await;
    let t = issuer.token().mint();
    let mut failures = Vec::new();
    for depth in 100..140 {
        for place in ["top", "args", "meta"] {
            let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
            let body = match place {
                "top" => format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"write","arguments":{{"text":"PWNED"}}}},"x":{deep}}}"#
                ),
                "args" => format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"write","arguments":{{"text":"PWNED","x":{deep}}}}}}}"#
                ),
                _ => format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"write","arguments":{{"text":"PWNED"}},"_meta":{{"x":{deep}}}}}}}"#
                ),
            };
            let r = raw(&c, &t, body.as_bytes(), &[]).await;
            if bypassed(&r) {
                failures.push(format!("{place}@{depth}"));
            }
        }
    }
    assert!(failures.is_empty(), "policy bypassed at: {failures:?}");
}

/// Dev mode checks the socket it is finally served on, not only the configured bind address.
#[tokio::test]
async fn dev_mode_guard_checks_the_served_socket() {
    use mcpward::{Auth, DevIdentity, ServeError};
    let server = builder()
        .resource_url("http://localhost:8080/mcp")
        .unwrap()
        .bind("127.0.0.1:8080".parse().unwrap())
        .auth(Auth::dev(DevIdentity::default()))
        .build()
        .await
        .expect("dev build on a loopback bind");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server.serve_listener(listener, std::future::pending()),
    )
    .await
    .expect("serve_listener refuses immediately");
    assert!(matches!(r, Err(ServeError::DevNonLoopback(_))), "{r:?}");
}
