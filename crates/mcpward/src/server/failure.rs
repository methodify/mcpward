//! [`ToolFailure`]: tool errors as text-only `isError` results.

use std::fmt;

use rmcp::{
    handler::server::tool::IntoCallToolResult,
    model::{CallToolResponse, CallToolResult, ContentBlock},
};
use serde_json::{Map, Value, json};

use crate::auth::ToolDenied;

/// A tool error for the agent to read.
///
/// Becomes `isError: true` with one text block holding a compact JSON object:
/// `{"error": <code>, "message": <text>, "status"?: <u16>, "detail"?: <any>, "hint"?: <text>}`.
/// There is never `structuredContent`: a tool's output schema describes success results, and a
/// client that validates against it could reject an error-shaped object.
///
/// Handlers return `Result<Json<T>, ToolFailure>` and use `?` on [`ToolDenied`],
/// [`ExchangeError`](crate::exchange::ExchangeError), and
/// [`DownstreamError`](crate::exchange::DownstreamError).
#[derive(Clone, Debug, PartialEq)]
pub struct ToolFailure {
    code: String,
    message: String,
    status: Option<u16>,
    detail: Option<Value>,
    hint: Option<String>,
}

impl ToolFailure {
    /// A failure with a short snake_case code and a user-actionable message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        ToolFailure { code: code.into(), message: message.into(), status: None, detail: None, hint: None }
    }

    /// An HTTP-like status, for example a downstream API's.
    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Structured detail, for example a downstream problem document.
    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    /// A hint about what to do next.
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The JSON object written as the result's text.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("error".into(), json!(self.code));
        m.insert("message".into(), json!(self.message));
        if let Some(s) = self.status {
            m.insert("status".into(), json!(s));
        }
        if let Some(d) = &self.detail {
            m.insert("detail".into(), d.clone());
        }
        if let Some(h) = &self.hint {
            m.insert("hint".into(), json!(h));
        }
        Value::Object(m)
    }

    /// The `CallToolResult`.
    pub fn into_result(self) -> CallToolResult {
        CallToolResult::error(vec![ContentBlock::text(self.to_json().to_string())])
    }
}

impl fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ToolFailure {}

impl IntoCallToolResult for ToolFailure {
    fn into_call_tool_result(self) -> Result<CallToolResponse, rmcp::ErrorData> {
        Ok(self.into_result().into())
    }
}

impl From<ToolDenied> for ToolFailure {
    fn from(d: ToolDenied) -> Self {
        ToolFailure::new("forbidden", d.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_only() {
        let r = ToolFailure::new("conflict", "Already exists").status(409).hint("Use another name").into_result();
        assert_eq!(r.is_error, Some(true));
        assert!(r.structured_content.is_none());
        let v = serde_json::to_value(&r).unwrap();
        let text = v["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["error"], "conflict");
        assert_eq!(parsed["status"], 409);
    }
}
