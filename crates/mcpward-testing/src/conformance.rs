//! The conformance suite. Generate it against your server with [`conformance!`](crate::conformance!).
//!
//! Each function here is one test. They check the resource-server contract: the exact `401`
//! challenge, Protected Resource Metadata, token rejection for every kind of bad token,
//! per-tool role and scope enforcement, list filtering, JWKS refetch limits, statelessness,
//! and that logs carry the subject and client but never the token.

use std::sync::Arc;

use http::Method;
use mcpward::{McpServer, RoleDenial, auth::ResourceUrl};
use serde_json::{Value, json};

use crate::{Era, LogCapture, TEST_CLIENT_ID, TEST_OID, TEST_SUBJECT, TestClient, TestIssuer};

/// What the suite needs to know about your server.
#[derive(Clone, Debug)]
pub struct Conformance {
    /// The resource URL the server was built with.
    pub resource_url: String,
    /// A tool a default token (base scope, no roles) may call successfully.
    pub open_tool: String,
    /// Valid arguments for `open_tool`.
    pub open_tool_args: Value,
    /// A tool that needs a role, and the role.
    pub role_tool: Option<(String, String)>,
    /// A tool that needs a delegated scope beyond the base scopes, and the scope (claim form).
    pub scope_tool: Option<(String, String)>,
    /// The server's role-denial mode.
    pub role_denial: RoleDenial,
    /// Roles every test token carries (for servers where even read tools need a role).
    pub caller_roles: Vec<String>,
}

impl Conformance {
    /// The resource URL and a tool open to every authenticated caller.
    pub fn new(resource_url: &str, open_tool: &str) -> Self {
        Conformance {
            resource_url: resource_url.to_owned(),
            open_tool: open_tool.to_owned(),
            open_tool_args: json!({}),
            role_tool: None,
            scope_tool: None,
            role_denial: RoleDenial::InBand,
            caller_roles: Vec::new(),
        }
    }
    /// Roles every test token carries. They must not include `role_tool`'s role.
    pub fn caller_roles(mut self, roles: &[&str]) -> Self {
        self.caller_roles = roles.iter().map(|r| r.to_string()).collect();
        self
    }
    /// Arguments for the open tool.
    pub fn open_tool_args(mut self, v: Value) -> Self {
        self.open_tool_args = v;
        self
    }
    /// A role-gated tool.
    pub fn role_tool(mut self, tool: &str, role: &str) -> Self {
        self.role_tool = Some((tool.to_owned(), role.to_owned()));
        self
    }
    /// A scope-gated tool.
    pub fn scope_tool(mut self, tool: &str, scope: &str) -> Self {
        self.scope_tool = Some((tool.to_owned(), scope.to_owned()));
        self
    }
    /// The role-denial mode.
    pub fn role_denial(mut self, m: RoleDenial) -> Self {
        self.role_denial = m;
        self
    }

    fn resource(&self) -> ResourceUrl {
        ResourceUrl::parse(&self.resource_url, true).expect("conformance resource_url")
    }
}

fn base(issuer: &TestIssuer, cfg: &Conformance) -> crate::TokenBuilder {
    let roles: Vec<&str> = cfg.caller_roles.iter().map(String::as_str).collect();
    if roles.is_empty() { issuer.token() } else { issuer.token().roles(&roles) }
}

async fn prm(c: &TestClient, cfg: &Conformance) -> Value {
    let r = c.get(&cfg.resource().prm_path()).await;
    assert_eq!(r.status, 200, "PRM should be served at the path-inserted URL");
    r.json.expect("PRM is JSON")
}

fn assert_rejected_401(r: &crate::TestResponse, what: &str) {
    assert_eq!(r.status, 401, "{what}: expected 401, got {} {}", r.status, r.text());
    let h = r.www_authenticate().unwrap_or_else(|| panic!("{what}: 401 without WWW-Authenticate"));
    assert!(h.starts_with("Bearer resource_metadata=\""), "{what}: {h}");
    assert!(h.contains("error=\"invalid_token\""), "{what}: {h}");
}

async fn list_with(server: McpServer, token: &str) -> crate::TestResponse {
    TestClient::new(server).list_tools(token).await
}

/// `POST` with no token returns 401 with exactly `Bearer resource_metadata="..", scope=".."`.
pub async fn no_token_401_exact_challenge(_: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let doc = prm(&c, cfg).await;
    let scopes: Vec<&str> =
        doc["scopes_supported"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let mut expected = format!("Bearer resource_metadata=\"{}\"", cfg.resource().resource_metadata_url());
    if !scopes.is_empty() {
        expected.push_str(&format!(", scope=\"{}\"", scopes.join(" ")));
    }
    let r = c.rpc(None, "tools/list", json!({})).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.www_authenticate(), Some(expected.as_str()));
}

/// PRM is served at the RFC 9728 path-inserted URL, publicly cacheable, with CORS.
pub async fn prm_path_inserted(_: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let r = c.get(&cfg.resource().prm_path()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert!(r.header("cache-control").is_some_and(|v| v.contains("public")));
}

/// PRM `resource` is byte-identical to the resource URL.
pub async fn prm_resource_exact(_: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let doc = prm(&TestClient::new(server), cfg).await;
    assert_eq!(doc["resource"].as_str(), Some(cfg.resource_url.as_str()));
}

/// PRM lists exactly one authorization server.
pub async fn prm_single_authorization_server(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let doc = prm(&TestClient::new(server), cfg).await;
    let a = doc["authorization_servers"].as_array().expect("authorization_servers");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].as_str(), Some(issuer.issuer()));
}

/// PRM never advertises `offline_access`.
pub async fn prm_no_offline_access(_: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let doc = prm(&TestClient::new(server), cfg).await;
    assert!(!doc["scopes_supported"].to_string().contains("offline_access"));
    assert_eq!(doc["bearer_methods_supported"], json!(["header"]));
}

/// The MCP URL never redirects.
pub async fn no_redirect_on_mcp_url(_: &TestIssuer, server: McpServer, _: &Conformance) {
    let c = TestClient::new(server);
    for m in [Method::POST, Method::GET, Method::DELETE] {
        let r = c.request(m.clone(), c.mcp_path(), None, None).await;
        assert!(!(300..400).contains(&r.status), "{m} returned {}", r.status);
    }
}

/// A trailing slash is 404, not a redirect.
pub async fn trailing_slash_is_404_not_redirect(_: &TestIssuer, server: McpServer, _: &Conformance) {
    let c = TestClient::new(server);
    if c.mcp_path() == "/" {
        return;
    }
    let r = c.request(Method::POST, &format!("{}/", c.mcp_path()), None, Some(json!({}))).await;
    assert_eq!(r.status, 404);
}

/// Wrong `iss` is rejected.
pub async fn wrong_iss_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let t = base(issuer, cfg).iss("https://untrusted.example.com/").mint();
    assert_rejected_401(&list_with(server, &t).await, "wrong iss");
}

/// Wrong `aud` is rejected with the "another resource" description.
pub async fn wrong_aud_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let t = base(issuer, cfg).aud("api://some-other-api").mint();
    let r = list_with(server, &t).await;
    assert_rejected_401(&r, "wrong aud");
    assert!(r.www_authenticate().unwrap_or("").contains("issued for another resource"));
}

/// Wrong `tid` is rejected (Entra-shaped issuers).
pub async fn wrong_tid_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    if !issuer.is_entra() {
        return;
    }
    let t = base(issuer, cfg).tid("00000000-0000-0000-0000-0000000000ff").mint();
    assert_rejected_401(&list_with(server, &t).await, "wrong tid");
}

/// An expired token is rejected with "The access token expired".
pub async fn expired_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = list_with(server, &base(issuer, cfg).expired().mint()).await;
    assert_rejected_401(&r, "expired");
    assert!(r.www_authenticate().unwrap_or("").contains("The access token expired"));
}

/// A token without the base scope gets 403 `insufficient_scope`.
pub async fn missing_scope_403(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = list_with(server, &base(issuer, cfg).scopes(&[]).mint()).await;
    assert_eq!(r.status, 403);
    assert!(r.www_authenticate().unwrap_or("").contains("error=\"insufficient_scope\""));
}

/// A client not in the allowlist gets a terminal 403 with no challenge.
pub async fn unlisted_azp_403_terminal(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = list_with(server, &base(issuer, cfg).azp("some-other-client").mint()).await;
    assert_eq!(r.status, 403);
    assert!(r.www_authenticate().is_none(), "unlisted azp must not get a challenge");
    assert_eq!(r.json.as_ref().and_then(|j| j["error"].as_str()), Some("client_not_allowed"));
}

/// A bad signature is rejected.
pub async fn bad_signature_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    assert_rejected_401(&list_with(server, &base(issuer, cfg).signed_by_untrusted_key().mint()).await, "bad signature");
}

/// `alg: none` is rejected.
pub async fn alg_none_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    assert_rejected_401(&list_with(server, &base(issuer, cfg).alg_none().mint()).await, "alg none");
}

/// HS256 signed with the public key is rejected.
pub async fn hs256_key_confusion(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    assert_rejected_401(&list_with(server, &base(issuer, cfg).hs256_with_public_key().mint()).await, "hs256 confusion");
}

/// `nbf` in the future (beyond leeway) is rejected.
pub async fn nbf_in_future(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = list_with(server, &base(issuer, cfg).not_before_in(std::time::Duration::from_secs(3600)).mint()).await;
    assert_rejected_401(&r, "nbf");
}

/// A token without `kid` is rejected.
pub async fn missing_kid(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    assert_rejected_401(&list_with(server, &base(issuer, cfg).without_kid().mint()).await, "missing kid");
}

/// Entra v1 tokens are rejected.
pub async fn v1_token_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    if !issuer.is_entra() {
        return;
    }
    assert_rejected_401(&list_with(server, &base(issuer, cfg).claim("ver", "1.0").mint()).await, "v1 token");
}

/// App-only tokens are refused.
pub async fn app_only_token_rejected(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = list_with(server, &base(issuer, cfg).app_only().mint()).await;
    assert!(r.status == 401 || r.status == 403, "app-only token got {}", r.status);
}

/// A token in the query string is a 400.
pub async fn token_in_query_400(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let t = base(issuer, cfg).mint();
    let r = c.request(Method::POST, &format!("{}?access_token={t}", c.mcp_path()), None, Some(json!({}))).await;
    assert_eq!(r.status, 400);
}

/// A tool needing a role is hidden from a caller without it, and listed for one with it.
pub async fn missing_role_hidden_from_list(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let Some((tool, role)) = &cfg.role_tool else { return };
    let c = TestClient::new(server);
    let without = c.list_tools(&base(issuer, cfg).mint()).await;
    assert_eq!(without.status, 200, "{}", without.text());
    assert!(!without.names().contains(&tool.as_str()), "{tool} listed without {role}");
    assert!(without.names().contains(&cfg.open_tool.as_str()));
    let mut roles: Vec<&str> = cfg.caller_roles.iter().map(String::as_str).collect();
    roles.push(role);
    let with = c.list_tools(&issuer.token().roles(&roles).mint()).await;
    assert!(with.names().contains(&tool.as_str()), "{tool} not listed with {role}");
}

/// In `InBand` mode, calling a role-gated tool without the role is an `isError` result.
pub async fn missing_role_call_is_tool_error(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let Some((tool, _)) = &cfg.role_tool else { return };
    if cfg.role_denial != RoleDenial::InBand {
        return;
    }
    let r = TestClient::new(server).call_tool(&base(issuer, cfg).mint(), tool, json!({})).await;
    assert_eq!(r.status, 200);
    assert!(r.is_tool_error(), "{}", r.text());
    assert!(r.structured().is_none());
}

/// In `HttpInsufficientScope` mode, calling a role-gated tool without the role is a 403.
pub async fn missing_role_403_insufficient_scope(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let Some((tool, _)) = &cfg.role_tool else { return };
    if cfg.role_denial != RoleDenial::HttpInsufficientScope {
        return;
    }
    let r = TestClient::new(server).call_tool(&base(issuer, cfg).mint(), tool, json!({})).await;
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.www_authenticate().unwrap_or("").contains("error=\"insufficient_scope\""));
}

/// A call needing a delegated scope the token lacks is a 403 listing every needed scope.
pub async fn missing_tool_scope_403_insufficient_scope_with_all_scopes(
    issuer: &TestIssuer,
    server: McpServer,
    cfg: &Conformance,
) {
    let Some((tool, scope)) = &cfg.scope_tool else { return };
    let c = TestClient::new(server);
    let doc = prm(&c, cfg).await;
    let r = c.call_tool(&base(issuer, cfg).mint(), tool, json!({})).await;
    assert_eq!(r.status, 403, "{}", r.text());
    let h = r.www_authenticate().unwrap_or("");
    assert!(h.contains("error=\"insufficient_scope\""), "{h}");
    assert!(h.contains(scope.as_str()), "{h}");
    for base in doc["scopes_supported"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        assert!(h.contains(base), "base scope {base} missing from {h}");
    }
}

/// A tool name with no policy is denied.
pub async fn unpoliced_tool_call_denied(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = TestClient::new(server)
        .call_tool(&base(issuer, cfg).mint(), "mcpward-conformance-no-such-tool", json!({}))
        .await;
    assert!(r.is_tool_error() || r.rpc_error().is_some() || r.status >= 400, "unpoliced call succeeded: {}", r.text());
}

/// 100 concurrent requests with unknown `kid`s cause exactly one JWKS refetch.
pub async fn unknown_kid_single_refetch(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = Arc::new(TestClient::new(server));
    let before = issuer.jwks_fetches();
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let c = c.clone();
        let t = base(issuer, cfg).unknown_kid().mint();
        tasks.push(tokio::spawn(async move { c.list_tools(&t).await.status }));
    }
    for t in tasks {
        assert_eq!(t.await.expect("task"), 401);
    }
    assert_eq!(issuer.jwks_fetches(), before + 1);
}

/// A second unknown `kid` right after the first causes no fetch.
pub async fn unknown_kid_rate_limited(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let before = issuer.jwks_fetches();
    assert_eq!(c.list_tools(&base(issuer, cfg).unknown_kid().mint()).await.status, 401);
    assert_eq!(c.list_tools(&base(issuer, cfg).unknown_kid().mint()).await.status, 401);
    assert_eq!(issuer.jwks_fetches(), before + 1);
}

/// After the issuer rotates keys, new tokens validate after one refetch.
pub async fn rotation_picked_up(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let before = issuer.jwks_fetches();
    issuer.rotate();
    let r = c.list_tools(&base(issuer, cfg).mint()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(issuer.jwks_fetches(), before + 1);
    issuer.rotate();
}

/// Logs carry the subject and client ID, and never the token or any of its segments.
pub async fn logs_have_subject_and_client_no_token(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let token = base(issuer, cfg).mint();
    let bad = base(issuer, cfg).aud("api://other").mint();
    let (cap, guard) = LogCapture::start();
    let r = c.call_tool(&token, &cfg.open_tool, cfg.open_tool_args.clone()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let _ = c.list_tools(&bad).await;
    drop(guard);
    let logs = cap.contents();
    let id = if issuer.is_entra() { TEST_OID } else { TEST_SUBJECT };
    assert!(logs.contains(id), "logs lack the subject");
    assert!(logs.contains(TEST_CLIENT_ID), "logs lack the client ID");
    for t in [&token, &bad] {
        assert!(!logs.contains(t.as_str()), "a token was logged");
        for seg in t.split('.').filter(|s| s.len() > 8) {
            assert!(!logs.contains(seg), "a token segment was logged");
        }
    }
}

/// No `Mcp-Session-Id` is ever issued.
pub async fn no_session_header_issued(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = TestClient::new(server).initialize(&base(issuer, cfg).mint()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.header("mcp-session-id").is_none());
}

/// `GET` on the MCP URL is 405 (no SSE stream).
pub async fn get_returns_405(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server);
    let r = c.request(Method::GET, c.mcp_path(), Some(&base(issuer, cfg).mint()), None).await;
    assert_eq!(r.status, 405);
}

/// 2026-07-28 requests work without any handshake.
pub async fn works_without_initialize_2026(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server).era(Era::V2026_07_28);
    let t = base(issuer, cfg).mint();
    let r = c.list_tools(&t).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.names().contains(&cfg.open_tool.as_str()));
    let r = c.call_tool(&t, &cfg.open_tool, cfg.open_tool_args.clone()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(!r.is_tool_error(), "{}", r.text());
}

/// Legacy `initialize`, then a tool call, each its own request.
pub async fn legacy_initialize_then_call(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let c = TestClient::new(server).era(Era::Legacy2025_11_25);
    let t = base(issuer, cfg).mint();
    assert_eq!(c.initialize(&t).await.status, 200);
    let r = c.call_tool(&t, &cfg.open_tool, cfg.open_tool_args.clone()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(!r.is_tool_error(), "{}", r.text());
}

/// List results are marked private when roles are in play.
pub async fn tools_list_private_cache_scope_when_roles(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    if cfg.role_tool.is_none() {
        return;
    }
    let r = TestClient::new(server).era(Era::V2026_07_28).list_tools(&base(issuer, cfg).mint()).await;
    assert_eq!(r.result().and_then(|r| r.get("cacheScope")), Some(&json!("private")));
}

/// In-band errors carry text only, never `structuredContent`.
pub async fn tool_error_has_no_structured_content(issuer: &TestIssuer, server: McpServer, cfg: &Conformance) {
    let r = TestClient::new(server)
        .call_tool(&base(issuer, cfg).mint(), "mcpward-conformance-no-such-tool", json!({}))
        .await;
    if r.is_tool_error() {
        assert!(r.structured().is_none());
        assert!(r.tool_text().is_some());
    }
}

/// Generates the conformance suite as `#[tokio::test]`s in a module named
/// `mcpward_conformance`.
///
/// ```ignore
/// mcpward_testing::conformance! {
///     issuer = mcpward_testing::TestIssuer::entra(TENANT, API).start(),
///     server = |issuer: &mcpward_testing::TestIssuer| build_server(issuer.auth_for("http://localhost/mcp")),
///     config = mcpward_testing::conformance::Conformance::new("http://localhost/mcp", "whoami")
///         .role_tool("add_note", "Notes.Writer"),
/// }
/// ```
///
/// `issuer` is a future that yields a [`TestIssuer`]; `server` is called with it and returns a
/// future that yields the built `McpServer`. Your crate needs `tokio` (with `macros` and `rt`)
/// as a dev-dependency.
#[macro_export]
macro_rules! conformance {
    (issuer = $issuer:expr, server = $make:expr, config = $cfg:expr $(,)?) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod mcpward_conformance {
            #[allow(unused_imports)]
            use super::*;
            $crate::__conformance_tests!($issuer, $make, $cfg;
                no_token_401_exact_challenge, prm_path_inserted, prm_resource_exact,
                prm_single_authorization_server, prm_no_offline_access, no_redirect_on_mcp_url,
                trailing_slash_is_404_not_redirect, wrong_iss_rejected, wrong_aud_rejected,
                wrong_tid_rejected, expired_rejected, missing_scope_403, unlisted_azp_403_terminal,
                bad_signature_rejected, alg_none_rejected, hs256_key_confusion, nbf_in_future,
                missing_kid, v1_token_rejected, app_only_token_rejected, token_in_query_400,
                missing_role_hidden_from_list, missing_role_call_is_tool_error,
                missing_role_403_insufficient_scope,
                missing_tool_scope_403_insufficient_scope_with_all_scopes,
                unpoliced_tool_call_denied, unknown_kid_single_refetch, unknown_kid_rate_limited,
                rotation_picked_up, logs_have_subject_and_client_no_token, no_session_header_issued,
                get_returns_405, works_without_initialize_2026, legacy_initialize_then_call,
                tools_list_private_cache_scope_when_roles, tool_error_has_no_structured_content
            );
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_tests {
    ($issuer:expr, $make:expr, $cfg:expr; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let issuer: $crate::TestIssuer = $issuer.await;
                let cfg: $crate::conformance::Conformance = $cfg;
                let server = ($make)(&issuer).await;
                $crate::conformance::$name(&issuer, server, &cfg).await;
            }
        )*
    };
}
