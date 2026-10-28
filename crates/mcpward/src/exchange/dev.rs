use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};

use super::{DownstreamToken, ExchangeError, ExchangeTarget, TokenExchanger};
use crate::auth::{BoxFuture, Principal, SubjectToken};

/// Dev mode only: sends a fixed token or API key to the downstream API.
#[derive(Clone)]
pub struct StaticToken(SecretString);

impl StaticToken {
    /// The token to send as `Authorization: Bearer <token>`.
    pub fn new(token: impl Into<String>) -> Self {
        StaticToken(SecretString::from(token.into()))
    }
}

impl TokenExchanger for StaticToken {
    fn exchange<'a>(
        &'a self,
        _: &'a Principal,
        _: &'a SubjectToken,
        _: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
        Box::pin(async move {
            Ok(DownstreamToken::new(self.0.expose_secret(), SystemTime::now() + Duration::from_secs(3600)))
        })
    }
    fn requires_user_token(&self) -> bool {
        false
    }
    fn kind(&self) -> &'static str {
        "static-token"
    }
}

/// Dev mode only: no `Authorization` header (for a downstream API in its own dev mode).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAuth;

impl TokenExchanger for NoAuth {
    fn exchange<'a>(
        &'a self,
        _: &'a Principal,
        _: &'a SubjectToken,
        _: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
        Box::pin(async move { Ok(DownstreamToken::new("", SystemTime::now() + Duration::from_secs(3600))) })
    }
    fn requires_user_token(&self) -> bool {
        false
    }
    fn kind(&self) -> &'static str {
        "none"
    }
}
