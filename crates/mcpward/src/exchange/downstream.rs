use std::{fmt, sync::Arc, time::Duration};

use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

use super::{DownstreamToken, ExchangeError, ExchangeTarget, TokenExchanger};
use crate::{
    ConfigError, ToolFailure,
    auth::{Principal, SubjectToken},
    server::RequestMeta,
};

const MAX_ERROR_BODY: usize = 64 * 1024;

/// A downstream API the server calls as the user.
pub struct Downstream {
    name: &'static str,
    base_url: Url,
    target: ExchangeTarget,
    exchanger: Arc<dyn TokenExchanger>,
    http: reqwest::Client,
    headers: HeaderMap,
    propagate_request_id: bool,
}

impl fmt::Debug for Downstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Downstream")
            .field("name", &self.name)
            .field("base_url", &self.base_url.as_str())
            .field("scopes", &self.target.scopes)
            .field("exchanger", &self.exchanger.kind())
            .finish()
    }
}

/// Builds a [`Downstream`].
pub struct DownstreamBuilder {
    name: &'static str,
    base_url: Url,
    scopes: Vec<String>,
    exchanger: Option<Arc<dyn TokenExchanger>>,
    timeout: Duration,
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
    propagate_request_id: bool,
    http: Option<reqwest::Client>,
}

impl fmt::Debug for DownstreamBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownstreamBuilder")
            .field("name", &self.name)
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl DownstreamBuilder {
    /// The exchanger that mints tokens for this API.
    pub fn exchanger(mut self, e: Arc<dyn TokenExchanger>) -> Self {
        self.exchanger = Some(e);
        self
    }

    /// Scopes to request, for example `["api://<downstream>/access_as_user"]`.
    pub fn scopes<I, S>(mut self, s: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = s.into_iter().map(Into::into).collect();
        self
    }

    /// Shorthand for `scopes(["<audience>/.default"])`.
    pub fn audience(mut self, aud: &str) -> Self {
        self.scopes = vec![format!("{}/.default", aud.trim_end_matches('/'))];
        self
    }

    /// Request timeout. Default 30 s.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// `User-Agent`. Default `mcpward/<version>`.
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_owned());
        self
    }

    /// A header sent on every request.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Send the incoming `x-request-id` (and `traceparent`) downstream. Never overwrites one
    /// set on the request builder.
    pub fn propagate_request_id(mut self, on: bool) -> Self {
        self.propagate_request_id = on;
        self
    }

    /// A custom HTTP client. mcpward's default follows no redirects.
    pub fn http_client(mut self, c: reqwest::Client) -> Self {
        self.http = Some(c);
        self
    }

    /// Validates and builds.
    pub fn build(self) -> Result<Downstream, ConfigError> {
        let exchanger = self.exchanger.ok_or_else(|| ConfigError::invalid("downstream.exchanger", "required"))?;
        if exchanger.requires_user_token() && self.scopes.is_empty() {
            return Err(ConfigError::invalid("downstream.scopes", "at least one scope is required"));
        }
        if self.scopes.iter().any(|s| s == "offline_access") {
            return Err(ConfigError::invalid("downstream.scopes", "offline_access is never requested"));
        }
        crate::auth::check_https_or_loopback_pub(&self.base_url, "downstream.base_url")
            .or_else(|e| if exchanger.requires_user_token() { Err(e) } else { Ok(()) })?;
        let mut base = self.base_url;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let mut headers = HeaderMap::new();
        for (k, v) in self.headers {
            let name = HeaderName::try_from(k.as_str())
                .map_err(|_| ConfigError::invalid("downstream.header", format!("{k:?} is not a header name")))?;
            let value = HeaderValue::try_from(v.as_str())
                .map_err(|_| ConfigError::invalid("downstream.header", format!("bad value for {k}")))?;
            headers.append(name, value);
        }
        let http = match self.http {
            Some(h) => h,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(self.timeout)
                .user_agent(
                    self.user_agent.unwrap_or_else(|| concat!("mcpward/", env!("CARGO_PKG_VERSION")).to_owned()),
                )
                .build()
                .map_err(|e| ConfigError::invalid("downstream.http", e.to_string()))?,
        };
        Ok(Downstream {
            name: self.name,
            base_url: base,
            target: ExchangeTarget { name: self.name, scopes: self.scopes },
            exchanger,
            http,
            headers,
            propagate_request_id: self.propagate_request_id,
        })
    }
}

impl Downstream {
    /// Starts a builder. `name` is the logical name for logs and the cache key.
    pub fn builder(name: &'static str, base_url: Url) -> DownstreamBuilder {
        DownstreamBuilder {
            name,
            base_url,
            scopes: Vec::new(),
            exchanger: None,
            timeout: Duration::from_secs(30),
            user_agent: None,
            headers: Vec::new(),
            propagate_request_id: false,
            http: None,
        }
    }

    /// Reads `MCPWARD_<NAME>_BASE_URL` and `MCPWARD_<NAME>_SCOPES` (comma-separated).
    pub fn from_env(name: &'static str) -> Result<DownstreamBuilder, ConfigError> {
        Self::from_env_with("MCPWARD_", name, |k| std::env::var(k).ok())
    }

    /// Like [`Downstream::from_env`] with a custom prefix and lookup.
    pub fn from_env_with(
        prefix: &str,
        name: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<DownstreamBuilder, ConfigError> {
        let upper = name.to_ascii_uppercase().replace('-', "_");
        let mut problems = Vec::new();
        let url_var = format!("{prefix}{upper}_BASE_URL");
        let scopes_var = format!("{prefix}{upper}_SCOPES");
        let base = match lookup(&url_var).map(|v| v.parse::<Url>()) {
            Some(Ok(u)) => Some(u),
            Some(Err(_)) => {
                problems.push((url_var, "not a URL".to_owned()));
                None
            }
            None => {
                problems.push((url_var, "required".to_owned()));
                None
            }
        };
        let scopes: Vec<String> = lookup(&scopes_var)
            .map(|v| v.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        match base {
            Some(b) if problems.is_empty() => Ok(Downstream::builder(name, b).scopes(scopes)),
            _ => Err(ConfigError::Env(crate::EnvErrors { problems })),
        }
    }

    /// The logical name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The base URL (always ends with `/`).
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn requires_user_token(&self) -> bool {
        self.exchanger.requires_user_token()
    }

    pub(crate) fn describe(&self) -> String {
        format!("{} {} via {}", self.name, self.base_url, self.exchanger.kind())
    }

    pub(crate) async fn token_for(
        &self,
        principal: &Principal,
        subject: &SubjectToken,
    ) -> Result<DownstreamToken, ExchangeError> {
        self.exchanger.exchange(principal, subject, &self.target).await
    }

    pub(crate) fn authorized(&self, token: DownstreamToken, meta: Option<&RequestMeta>) -> AuthorizedClient<'_> {
        let (request_id, traceparent) = match (self.propagate_request_id, meta) {
            (true, Some(m)) => (Some(m.request_id.clone()).filter(|r| !r.is_empty()), m.traceparent.clone()),
            _ => (None, None),
        };
        AuthorizedClient { api: self, token, request_id, traceparent }
    }

    /// Resolves a relative path under the base URL; `None` if it would leave it.
    pub(crate) fn resolve(&self, path: &str) -> Option<Url> {
        if path.starts_with("//") || path.starts_with("\\") || path.contains("://") || Url::parse(path).is_ok() {
            return None;
        }
        let rel = path.trim_start_matches('/');
        let url = self.base_url.join(rel).ok()?;
        let same_origin = url.origin() == self.base_url.origin();
        (same_origin && url.path().starts_with(self.base_url.path())).then_some(url)
    }
}

/// An HTTP client bound to one downstream API and one user's token.
///
/// Paths must be relative to the base URL; anything else (absolute URLs, `//host`, paths that
/// resolve outside the base) panics in debug builds and produces a request that fails to send
/// in release builds, so the token only ever goes to the configured host.
pub struct AuthorizedClient<'a> {
    api: &'a Downstream,
    token: DownstreamToken,
    request_id: Option<String>,
    traceparent: Option<String>,
}

impl fmt::Debug for AuthorizedClient<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedClient").field("api", &self.api.name).field("token", &"[redacted]").finish()
    }
}

/// A downstream call failure.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum DownstreamError {
    /// A non-2xx response. `body` is the parsed JSON (or a string), capped at 64 KiB.
    #[error("downstream returned {status}")]
    Status {
        /// HTTP status.
        status: u16,
        /// Response body.
        body: Option<Value>,
    },
    /// Network failure or timeout.
    #[error("downstream request failed: {0}")]
    Transport(String),
    /// The success body didn't parse.
    #[error("downstream response did not parse: {0}")]
    Decode(String),
    /// The path would leave the base URL.
    #[error("path is not relative to the downstream base URL")]
    InvalidPath,
}

impl<'a> AuthorizedClient<'a> {
    /// `GET path`.
    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(Method::GET, path)
    }

    /// `POST path`.
    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(Method::POST, path)
    }

    /// `PUT path`.
    pub fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(Method::PUT, path)
    }

    /// `PATCH path`.
    pub fn patch(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(Method::PATCH, path)
    }

    /// `DELETE path`.
    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(Method::DELETE, path)
    }

    /// Any method.
    pub fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let Some(url) = self.api.resolve(path) else {
            debug_assert!(false, "mcpward: downstream path {path:?} is not relative to {}", self.api.base_url);
            // A relative URL fails to parse, so the builder carries an error and never sends.
            return self.api.http.request(method, "mcpward-rejected-path");
        };
        let mut rb = self.api.http.request(method, url).headers(self.api.headers.clone());
        let t = self.token.expose_secret();
        if !t.is_empty()
            && let Ok(mut v) = HeaderValue::try_from(format!("Bearer {t}"))
        {
            v.set_sensitive(true);
            rb = rb.header(header::AUTHORIZATION, v);
        }
        rb
    }

    /// Sends the request, adding `x-request-id` and `traceparent` when propagation is on and
    /// the request doesn't already have them.
    pub async fn send(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response, DownstreamError> {
        let mut req = rb.build().map_err(|e| {
            if e.is_builder() {
                DownstreamError::InvalidPath
            } else {
                DownstreamError::Transport(e.without_url().to_string())
            }
        })?;
        if req.url().origin() != self.api.base_url.origin() || !req.url().path().starts_with(self.api.base_url.path()) {
            return Err(DownstreamError::InvalidPath);
        }
        for (name, value) in [("x-request-id", &self.request_id), ("traceparent", &self.traceparent)] {
            if let Some(v) = value
                && !req.headers().contains_key(name)
                && let Ok(hv) = HeaderValue::try_from(v.as_str())
            {
                req.headers_mut().insert(name, hv);
            }
        }
        self.api.http.execute(req).await.map_err(|e| DownstreamError::Transport(e.without_url().to_string()))
    }

    /// Sends, maps non-2xx to [`DownstreamError::Status`], and parses JSON.
    pub async fn json<T: DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T, DownstreamError> {
        let resp = self.send(rb).await?;
        let status = resp.status();
        let bytes = read_capped(resp).await?;
        if !status.is_success() {
            let body = if bytes.is_empty() {
                None
            } else {
                Some(
                    serde_json::from_slice(&bytes)
                        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
                )
            };
            return Err(DownstreamError::Status { status: status.as_u16(), body });
        }
        let bytes = if bytes.is_empty() { b"null".to_vec() } else { bytes };
        serde_json::from_slice(&bytes).map_err(|e| DownstreamError::Decode(e.to_string()))
    }
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, DownstreamError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| DownstreamError::Transport(e.without_url().to_string()))? {
        buf.extend_from_slice(&chunk);
        if buf.len() > 32 * 1024 * 1024 {
            return Err(DownstreamError::Decode("response too large".into()));
        }
    }
    Ok(buf)
}

fn cap(v: Value) -> Value {
    let s = v.to_string();
    if s.len() <= MAX_ERROR_BODY { v } else { Value::String(s.chars().take(MAX_ERROR_BODY).collect()) }
}

impl From<DownstreamError> for ToolFailure {
    fn from(e: DownstreamError) -> Self {
        match e {
            DownstreamError::Status { status, body } => {
                let (code, message) = match status {
                    400 | 422 => ("invalid_request", "The downstream service rejected the request."),
                    401 => ("downstream_unauthorized", "The downstream service didn't accept your credentials."),
                    403 => ("forbidden", "You don't have permission to do this in the downstream service."),
                    404 => ("not_found", "The downstream service couldn't find that."),
                    409 => ("conflict", "The downstream service reported a conflict."),
                    429 => ("rate_limited", "The downstream service is rate limiting requests. Try again shortly."),
                    s if s >= 500 => ("downstream_unavailable", "The downstream service failed. Try again shortly."),
                    _ => ("downstream_error", "The downstream service returned an error."),
                };
                let message = body
                    .as_ref()
                    .and_then(|b| b.get("detail").or_else(|| b.get("title")).or_else(|| b.get("message")))
                    .and_then(Value::as_str)
                    .map(|s| s.chars().take(2000).collect::<String>())
                    .unwrap_or_else(|| message.to_owned());
                let mut f = ToolFailure::new(code, message).status(status);
                if let Some(b) = body {
                    f = f.detail(cap(b));
                }
                f
            }
            DownstreamError::Transport(_) => ToolFailure::new(
                "downstream_unavailable",
                "The downstream service couldn't be reached. Try again shortly.",
            ),
            DownstreamError::Decode(_) => ToolFailure::new(
                "downstream_error",
                "The downstream service returned a response this server couldn't read.",
            ),
            DownstreamError::InvalidPath => ToolFailure::new(
                "server_misconfigured",
                "The server isn't configured correctly. Contact its administrator.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::BoxFuture;
    use crate::exchange::TokenExchanger;

    struct Never;
    impl TokenExchanger for Never {
        fn exchange<'a>(
            &'a self,
            _: &'a Principal,
            _: &'a SubjectToken,
            _: &'a ExchangeTarget,
        ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
            Box::pin(async { Err(ExchangeError::Unavailable("x".into())) })
        }
    }

    fn api() -> Downstream {
        Downstream::builder("orders-api", "https://api.example.com/orders".parse().unwrap())
            .exchanger(Arc::new(Never))
            .scopes(["api://x/.default"])
            .build()
            .unwrap()
    }

    #[test]
    fn resolves_only_under_base() {
        let a = api();
        assert_eq!(a.resolve("/v1/things?x=1").unwrap().as_str(), "https://api.example.com/orders/v1/things?x=1");
        assert_eq!(a.resolve("v1/things").unwrap().as_str(), "https://api.example.com/orders/v1/things");
        for bad in
            ["https://evil.example.com/x", "//evil.example.com/x", "\\\\evil.example.com", "../../admin", "/../x"]
        {
            assert!(a.resolve(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn rejects_offline_access() {
        let r = Downstream::builder("x", "https://api.example.com".parse().unwrap())
            .exchanger(Arc::new(Never))
            .scopes(["offline_access"])
            .build();
        assert!(r.is_err());
    }

    #[test]
    fn status_to_failure() {
        let f: ToolFailure =
            DownstreamError::Status { status: 403, body: Some(serde_json::json!({"detail": "Requires Editor"})) }
                .into();
        assert_eq!(f.code(), "forbidden");
        assert_eq!(f.message(), "Requires Editor");
        assert_eq!(f.to_json()["status"], 403);
    }
}
