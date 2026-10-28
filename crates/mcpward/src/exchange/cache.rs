use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use moka::{Expiry, future::Cache};

use super::{DownstreamToken, ExchangeError, ExchangeTarget, TokenExchanger};
use crate::{
    ConfigError,
    auth::{BoxFuture, Principal, SubjectToken},
};

/// The user and the scopes requested: two targets with one name but different scopes never
/// share a token.
type Key = (String, &'static str, String);

#[derive(Clone)]
struct Entry {
    token: DownstreamToken,
    ttl: Duration,
}

struct EntryExpiry;

impl Expiry<Key, Entry> for EntryExpiry {
    fn expire_after_create(&self, _: &Key, v: &Entry, _: Instant) -> Option<Duration> {
        Some(v.ttl)
    }
}

/// Caches any exchanger's tokens per user (`subject.key()`), target name, and requested scopes.
///
/// An entry expires at the earlier of the downstream token's expiry and the expiry of the
/// user token that minted it, minus a margin (default 3 min), so a cached token never outlives
/// the session that created it. Concurrent requests for one key share one exchange; errors
/// aren't cached. Memory only, bounded (default 10,000 entries).
pub struct CachedExchanger<E> {
    inner: Arc<E>,
    cache: Cache<Key, Entry>,
    margin: Duration,
}

impl<E: TokenExchanger> CachedExchanger<E> {
    /// Wraps `inner` with the default margin (3 min) and capacity (10,000).
    pub fn new(inner: E) -> Self {
        Self::with_settings(inner, Duration::from_secs(180), 10_000)
            .unwrap_or_else(|_| unreachable!("defaults are valid"))
    }

    /// Custom margin (1 to 10 min) and capacity.
    pub fn with_settings(inner: E, margin: Duration, capacity: u64) -> Result<Self, ConfigError> {
        if margin < Duration::from_secs(60) || margin > Duration::from_secs(600) {
            return Err(ConfigError::invalid("expiry_margin", "must be between 1 and 10 minutes"));
        }
        Ok(CachedExchanger {
            inner: Arc::new(inner),
            cache: Cache::builder().max_capacity(capacity).expire_after(EntryExpiry).build(),
            margin,
        })
    }

    /// The wrapped exchanger.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// The number of cached entries (approximate).
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

impl<E: TokenExchanger> TokenExchanger for CachedExchanger<E> {
    fn exchange<'a>(
        &'a self,
        principal: &'a Principal,
        subject: &'a SubjectToken,
        target: &'a ExchangeTarget,
    ) -> BoxFuture<'a, Result<DownstreamToken, ExchangeError>> {
        Box::pin(async move {
            let mut scopes = target.scopes.clone();
            scopes.sort();
            scopes.dedup();
            let key: Key = (principal.subject.key().to_owned(), target.name, scopes.join(" "));
            let miss = AtomicBool::new(false);
            let res = self
                .cache
                .try_get_with(key, async {
                    miss.store(true, Ordering::Relaxed);
                    let token = self.inner.exchange(principal, subject, target).await?;
                    let until = token.expires_at.min(principal.expires_at);
                    let ttl = until.duration_since(SystemTime::now()).unwrap_or_default().saturating_sub(self.margin);
                    Ok::<_, ExchangeError>(Entry { token, ttl })
                })
                .await;
            let cache = if miss.load(Ordering::Relaxed) { "miss" } else { "hit" };
            match res {
                Ok(e) => {
                    tracing::debug!(target: "mcpward::exchange", target = target.name, cache, "downstream token ready");
                    Ok(e.token)
                }
                Err(e) => Err((*e).clone()),
            }
        })
    }

    fn requires_user_token(&self) -> bool {
        self.inner.requires_user_token()
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
}
