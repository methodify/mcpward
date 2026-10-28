//! Handler extractors: [`Principal`], [`Caller`], and [`RequestMeta`].
//!
//! rmcp puts the request's `http::request::Parts` into the request context, and any handler
//! can read them with `Extension<Parts>`. So mcpward puts only safe values there: the
//! principal and request metadata. The raw token sits in [`SubjectSlot`], a crate-private
//! type that code outside mcpward can't name, and the `Authorization` header is removed
//! before rmcp sees the request.

use std::{fmt, net::IpAddr, sync::Arc};

use rmcp::{
    ErrorData,
    handler::server::common::{AsRequestContext, FromContextPart},
};

use crate::auth::{Principal, SubjectToken};

/// Crate-private holder for the caller's token. Only [`Caller`] reads it.
#[derive(Clone)]
pub(crate) struct SubjectSlot(pub(crate) SubjectToken);

/// Per-request metadata safe to show handlers and logs.
#[derive(Clone, Debug)]
pub struct RequestMeta {
    /// `x-request-id`, received or generated.
    pub request_id: String,
    /// `MCP-Protocol-Version`, if sent.
    pub protocol_version: Option<String>,
    /// Client IP from the socket, or from `X-Forwarded-For` when trusted.
    pub client_ip: Option<IpAddr>,
    /// W3C `traceparent`, if sent.
    pub traceparent: Option<String>,
}

fn parts<C: AsRequestContext>(ctx: &C) -> Result<&http::request::Parts, ErrorData> {
    ctx.as_request_context().extensions.get::<http::request::Parts>().ok_or_else(|| {
        ErrorData::internal_error("mcpward: request parts missing (is the handler served by McpServer?)", None)
    })
}

fn missing(what: &str) -> ErrorData {
    tracing::error!(target: "mcpward", "{what} missing from the request; the handler is not behind mcpward's auth layer");
    ErrorData::internal_error("server misconfiguration", None)
}

impl<C: AsRequestContext> FromContextPart<C> for Principal {
    fn from_context_part(ctx: &mut C) -> Result<Self, ErrorData> {
        parts(ctx)?.extensions.get::<Arc<Principal>>().map(|p| (**p).clone()).ok_or_else(|| missing("principal"))
    }
}

impl<C: AsRequestContext> FromContextPart<C> for RequestMeta {
    fn from_context_part(ctx: &mut C) -> Result<Self, ErrorData> {
        parts(ctx)?.extensions.get::<RequestMeta>().cloned().ok_or_else(|| missing("request metadata"))
    }
}

/// The caller, plus a handle for calling downstream APIs as them.
///
/// The token is held privately and only passed to a
/// [`TokenExchanger`](crate::exchange::TokenExchanger) by `Caller::client`. `Debug` prints
/// `[redacted]` for it.
#[derive(Clone)]
pub struct Caller {
    principal: Arc<Principal>,
    #[cfg_attr(not(feature = "exchange"), allow(dead_code))]
    subject: SubjectToken,
    #[cfg_attr(not(feature = "exchange"), allow(dead_code))]
    meta: Option<RequestMeta>,
}

impl Caller {
    /// The validated caller.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    #[cfg(feature = "exchange")]
    pub(crate) fn subject_token(&self) -> &SubjectToken {
        &self.subject
    }

    #[cfg(feature = "exchange")]
    pub(crate) fn meta(&self) -> Option<&RequestMeta> {
        self.meta.as_ref()
    }
}

impl std::ops::Deref for Caller {
    type Target = Principal;
    fn deref(&self) -> &Principal {
        &self.principal
    }
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller").field("principal", &self.principal).field("token", &"[redacted]").finish()
    }
}

impl<C: AsRequestContext> FromContextPart<C> for Caller {
    fn from_context_part(ctx: &mut C) -> Result<Self, ErrorData> {
        let p = parts(ctx)?;
        let principal = p.extensions.get::<Arc<Principal>>().cloned().ok_or_else(|| missing("principal"))?;
        let subject = p.extensions.get::<SubjectSlot>().map(|s| s.0.clone()).ok_or_else(|| missing("subject token"))?;
        Ok(Caller { principal, subject, meta: p.extensions.get::<RequestMeta>().cloned() })
    }
}
