//! The auth layer: bearer token extraction, validation, base scope check, and handing the
//! principal to the rest of the stack.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{StatusCode, header};
use serde_json::json;

use super::{AuthMode, ServerState, extract::SubjectSlot, obs::Obs};
use crate::auth::{AuthError, Challenge, Principal, RejectReason, SubjectToken};

fn token_in_query(req: &Request) -> bool {
    req.uri().query().is_some_and(|q| url::form_urlencoded::parse(q.as_bytes()).any(|(k, _)| k == "access_token"))
}

fn form_body(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded"))
}

enum Bearer<'a> {
    None,
    Token(&'a str),
    Malformed,
    Multiple,
}

fn bearer(req: &Request) -> Bearer<'_> {
    let mut values = req.headers().get_all(header::AUTHORIZATION).iter();
    let Some(first) = values.next() else { return Bearer::None };
    if values.next().is_some() {
        return Bearer::Multiple;
    }
    let Ok(v) = first.to_str() else { return Bearer::Malformed };
    let Some((scheme, rest)) = v.split_once(' ') else { return Bearer::None };
    if !scheme.eq_ignore_ascii_case("bearer") {
        // Another scheme: treated as no token, so the client gets the sign-in challenge.
        return Bearer::None;
    }
    if rest.is_empty() {
        return Bearer::None;
    }
    if rest.contains(' ') {
        return Bearer::Malformed;
    }
    Bearer::Token(rest)
}

pub(crate) async fn auth_mw(State(st): State<Arc<ServerState>>, mut req: Request, next: Next) -> Response {
    let obs = req.extensions().get::<Obs>().cloned().unwrap_or_default();
    if token_in_query(&req) || form_body(&req) {
        obs.outcome("bad_request");
        obs.reject(RejectReason::InvalidRequest.as_str());
        return st.challenge(&Challenge::InvalidRequest);
    }

    let validator = match &st.auth {
        #[cfg(feature = "dev-auth")]
        AuthMode::Dev(principal) => {
            // Any token sent is ignored, removed, and never logged.
            req.headers_mut().remove(header::AUTHORIZATION);
            obs.principal(principal.subject.key(), principal.subject.tenant(), principal.client_id.as_deref());
            req.extensions_mut().insert(principal.clone());
            req.extensions_mut().insert(SubjectSlot(SubjectToken::new("")));
            return next.run(req).await;
        }
        AuthMode::Token(v) => v.clone(),
    };

    let token = match bearer(&req) {
        Bearer::Token(t) => t.to_owned(),
        Bearer::None => {
            obs.outcome("unauthorized");
            obs.reject(RejectReason::MissingToken.as_str());
            return st.challenge(&Challenge::Unauthorized);
        }
        Bearer::Multiple => {
            obs.outcome("bad_request");
            obs.reject(RejectReason::InvalidRequest.as_str());
            return st.challenge(&Challenge::InvalidRequest);
        }
        Bearer::Malformed => {
            obs.outcome("invalid_token");
            obs.reject(RejectReason::Malformed.as_str());
            return st.challenge(&Challenge::InvalidToken(RejectReason::Malformed));
        }
    };

    let principal: Principal = match validator.validate(&token).await {
        Ok(p) => p,
        Err(AuthError::Rejected(r)) => {
            obs.reject(r.as_str());
            return match r {
                RejectReason::ClientNotAllowed => {
                    obs.outcome("client_not_allowed");
                    st.challenge(&Challenge::ClientNotAllowed)
                }
                RejectReason::InsufficientScope => {
                    obs.outcome("insufficient_scope");
                    st.challenge(&Challenge::InsufficientScope { scopes: st.base_scopes.clone() })
                }
                _ => {
                    obs.outcome("invalid_token");
                    st.challenge(&Challenge::InvalidToken(r))
                }
            };
        }
        Err(AuthError::Unavailable(reason)) => {
            obs.outcome("error");
            tracing::error!(target: "mcpward::auth", %reason, "token validation unavailable");
            let mut r = (StatusCode::SERVICE_UNAVAILABLE, json!({"error": "temporarily_unavailable"}).to_string())
                .into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
            r.headers_mut().insert(header::RETRY_AFTER, http::HeaderValue::from_static("5"));
            return r;
        }
    };
    obs.principal(principal.subject.key(), principal.subject.tenant(), principal.client_id.as_deref());

    // Custom validators may not check base scopes; check them here for every validator.
    if !st.base_scopes.iter().all(|s| principal.has_scope(s.claim())) {
        obs.outcome("insufficient_scope");
        obs.reject(RejectReason::InsufficientScope.as_str());
        return st.challenge(&Challenge::InsufficientScope { scopes: st.base_scopes.clone() });
    }

    // From here on the token is unreachable except through the crate-private slot.
    req.headers_mut().remove(header::AUTHORIZATION);
    req.extensions_mut().insert(Arc::new(principal));
    req.extensions_mut().insert(SubjectSlot(SubjectToken::new(&token)));
    drop(token);
    next.run(req).await
}
