use axum::{Router, body::Body};
use http::{HeaderMap, Method, Request, header};
use http_body_util::BodyExt;
use mcpward::McpServer;
use serde_json::{Value, json};
use tower::ServiceExt;

/// Which protocol era requests use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Era {
    /// `2025-11-25`: `MCP-Protocol-Version` header, no per-request `_meta`, `initialize`.
    #[default]
    Legacy2025_11_25,
    /// `2026-07-28`: `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and per-request
    /// `_meta`; `server/discover` instead of `initialize`.
    V2026_07_28,
}

impl Era {
    /// The protocol version string.
    pub fn version(&self) -> &'static str {
        match self {
            Era::Legacy2025_11_25 => "2025-11-25",
            Era::V2026_07_28 => "2026-07-28",
        }
    }
}

/// Drives an [`McpServer`] in-process with `tower::ServiceExt::oneshot`.
#[derive(Clone)]
pub struct TestClient {
    router: Router,
    host: String,
    path: String,
    era: Era,
}

/// A response, with the body parsed as JSON when it is JSON.
#[derive(Clone, Debug)]
pub struct TestResponse {
    /// HTTP status.
    pub status: u16,
    /// Headers.
    pub headers: HeaderMap,
    /// Raw body.
    pub body: Vec<u8>,
    /// The body as JSON, if it parses.
    pub json: Option<Value>,
}

impl TestResponse {
    /// A header as a string.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// `WWW-Authenticate`.
    pub fn www_authenticate(&self) -> Option<&str> {
        self.header("www-authenticate")
    }

    /// The JSON-RPC `result`.
    pub fn result(&self) -> Option<&Value> {
        self.json.as_ref().and_then(|j| j.get("result"))
    }

    /// The JSON-RPC `error`.
    pub fn rpc_error(&self) -> Option<&Value> {
        self.json.as_ref().and_then(|j| j.get("error"))
    }

    /// Names in a `tools/list` or `prompts/list` result.
    pub fn names(&self) -> Vec<&str> {
        let r = self.result();
        ["tools", "prompts"]
            .iter()
            .filter_map(|k| r.and_then(|r| r.get(*k)).and_then(Value::as_array))
            .flatten()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect()
    }

    /// Whether this is a tool result with `isError: true`.
    pub fn is_tool_error(&self) -> bool {
        self.result().and_then(|r| r.get("isError")) == Some(&Value::Bool(true))
    }

    /// The first text content of a tool result.
    pub fn tool_text(&self) -> Option<&str> {
        self.result()?.get("content")?.get(0)?.get("text")?.as_str()
    }

    /// A tool result's `structuredContent`.
    pub fn structured(&self) -> Option<&Value> {
        self.result()?.get("structuredContent")
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl TestClient {
    /// Wraps a built server. Requests use the resource URL's host and path.
    pub fn new(server: McpServer) -> Self {
        let url: url::Url = server.resource_url().parse().expect("resource url");
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("localhost")),
            None => url.host_str().unwrap_or("localhost").to_owned(),
        };
        let path = server.mcp_path().to_owned();
        TestClient { router: server.router(), host, path, era: Era::default() }
    }

    /// Uses `era` for later requests.
    pub fn era(mut self, era: Era) -> Self {
        self.era = era;
        self
    }

    /// The current era.
    pub fn current_era(&self) -> Era {
        self.era
    }

    /// The MCP path.
    pub fn mcp_path(&self) -> &str {
        &self.path
    }

    /// Sends any request. A `Host` header is added if missing.
    pub async fn send(&self, mut req: Request<Body>) -> TestResponse {
        if !req.headers().contains_key(header::HOST) {
            req.headers_mut().insert(header::HOST, self.host.parse().expect("host"));
        }
        let resp = self.router.clone().oneshot(req).await.expect("infallible");
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
        let json = serde_json::from_slice(&body).ok();
        TestResponse { status, headers, body, json }
    }

    /// `GET path` with no token.
    pub async fn get(&self, path: &str) -> TestResponse {
        self.send(Request::get(path).body(Body::empty()).expect("request")).await
    }

    /// Any method on any path, with an optional token.
    pub async fn request(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> TestResponse {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if body.is_some() {
            b = b
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream");
        }
        let body = body.map(|v| Body::from(v.to_string())).unwrap_or_else(Body::empty);
        self.send(b.body(body).expect("request")).await
    }

    /// POSTs a raw JSON body to the MCP path with the given headers.
    pub async fn post_raw(&self, token: Option<&str>, body: Value, headers: &[(&str, &str)]) -> TestResponse {
        let mut b = Request::post(&self.path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::from(body.to_string())).expect("request")).await
    }

    /// A JSON-RPC request in the current era.
    pub async fn rpc(&self, token: Option<&str>, method: &str, mut params: Value) -> TestResponse {
        let id = 1;
        let version = self.era.version();
        let mut headers: Vec<(&str, String)> = vec![("mcp-protocol-version", version.to_owned())];
        if self.era == Era::V2026_07_28 {
            if !params.is_object() {
                params = json!({});
            }
            params["_meta"] = json!({
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "mcpward-testing", "version": env!("CARGO_PKG_VERSION")},
            });
            headers.push(("mcp-method", method.to_owned()));
            let name = match method {
                "tools/call" | "prompts/get" => params.get("name").and_then(Value::as_str),
                "resources/read" => params.get("uri").and_then(Value::as_str),
                _ => None,
            };
            if let Some(n) = name {
                headers.push(("mcp-name", n.to_owned()));
            }
        }
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.post_raw(token, body, &hs).await
    }

    /// `initialize` (legacy) or `server/discover` (2026-07-28).
    pub async fn initialize(&self, token: &str) -> TestResponse {
        match self.era {
            Era::Legacy2025_11_25 => {
                let params = json!({
                    "protocolVersion": self.era.version(),
                    "capabilities": {},
                    "clientInfo": {"name": "mcpward-testing", "version": env!("CARGO_PKG_VERSION")},
                });
                self.rpc(Some(token), "initialize", params).await
            }
            Era::V2026_07_28 => self.rpc(Some(token), "server/discover", json!({})).await,
        }
    }

    /// `tools/list`.
    pub async fn list_tools(&self, token: &str) -> TestResponse {
        self.rpc(Some(token), "tools/list", json!({})).await
    }

    /// `tools/call`.
    pub async fn call_tool(&self, token: &str, name: &str, args: Value) -> TestResponse {
        self.rpc(Some(token), "tools/call", json!({"name": name, "arguments": args})).await
    }
}
