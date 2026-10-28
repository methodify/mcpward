use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::BoxFuture;
use crate::ConfigError;

/// A JSON Web Key Set as fetched, before filtering. Each key is kept as raw JSON so one key
/// type mcpward doesn't know can't make the whole set fail to parse.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct JwkSet {
    /// The `keys` array.
    pub keys: Vec<Value>,
}

impl JwkSet {
    /// Parses a JWKS document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, JwksError> {
        serde_json::from_slice(bytes).map_err(|e| JwksError::Parse(e.to_string()))
    }
}

/// Why a JWKS fetch failed.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// Network or TLS failure.
    #[error("request failed: {0}")]
    Http(String),
    /// Non-2xx status (redirects are not followed).
    #[error("unexpected status {0}")]
    Status(u16),
    /// The response exceeded `max_response_bytes`.
    #[error("response larger than {0} bytes")]
    TooLarge(usize),
    /// The response isn't a JWKS.
    #[error("invalid JWKS: {0}")]
    Parse(String),
    /// The set has no usable key.
    #[error("no usable signing keys")]
    NoUsableKeys,
    /// The fetch took longer than `fetch_timeout`.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

impl JwksError {
    fn kind(&self) -> &'static str {
        match self {
            JwksError::Http(_) => "http",
            JwksError::Status(_) => "status",
            JwksError::TooLarge(_) => "too_large",
            JwksError::Parse(_) => "parse",
            JwksError::NoUsableKeys => "no_usable_keys",
            JwksError::Timeout(_) => "timeout",
        }
    }
}

/// Where signing keys come from.
pub trait KeySource: Send + Sync + 'static {
    /// Fetches the current key set.
    fn fetch(&self) -> BoxFuture<'_, Result<JwkSet, JwksError>>;
}

/// A fixed key set, for tests and air-gapped setups only. Logs a warning when used, because a
/// pinned key breaks when the provider rotates.
#[derive(Clone, Debug)]
pub struct StaticKeys(pub JwkSet);

impl KeySource for StaticKeys {
    fn fetch(&self) -> BoxFuture<'_, Result<JwkSet, JwksError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

/// When the first key load happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupPolicy {
    /// Load before the validator is returned; fail startup after `timeout`.
    WaitUntilLoaded {
        /// How long to wait.
        timeout: Duration,
    },
    /// Load in the background; requests get `503` until the first load succeeds.
    Lazy,
}

/// JWKS cache settings.
#[derive(Clone, Debug)]
pub struct JwksConfig {
    /// The JWKS URI. `https` only, or `http` on a loopback host.
    pub uri: Url,
    /// Scheduled refresh interval. Default 6 h, with ±10 % jitter.
    pub refresh_interval: Duration,
    /// Minimum time between refetches triggered by an unknown `kid`. Default 60 s,
    /// allowed 10 s to 10 min.
    pub min_refetch_interval: Duration,
    /// Per-fetch timeout. Default 10 s. It applies to every fetch, including one made with a
    /// consumer-supplied HTTP client or key source.
    pub fetch_timeout: Duration,
    /// Response size cap. Default 256 KiB.
    pub max_response_bytes: usize,
    /// First-load behavior. Default: wait up to 30 s.
    pub startup: StartupPolicy,
}

impl JwksConfig {
    /// Defaults for a JWKS URI.
    pub fn new(uri: Url) -> Self {
        JwksConfig {
            uri,
            refresh_interval: Duration::from_secs(6 * 3600),
            min_refetch_interval: Duration::from_secs(60),
            fetch_timeout: Duration::from_secs(10),
            max_response_bytes: 256 * 1024,
            startup: StartupPolicy::WaitUntilLoaded { timeout: Duration::from_secs(30) },
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        check_https_or_loopback(&self.uri, "jwks.uri")?;
        if self.min_refetch_interval < Duration::from_secs(10) || self.min_refetch_interval > Duration::from_secs(600) {
            return Err(ConfigError::invalid("jwks.min_refetch_interval", "must be between 10 s and 10 min"));
        }
        if self.refresh_interval < Duration::from_secs(60) {
            return Err(ConfigError::invalid("jwks.refresh_interval", "must be at least 60 s"));
        }
        Ok(())
    }
}

pub(crate) fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub(crate) fn check_https_or_loopback(url: &Url, field: &'static str) -> Result<(), ConfigError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        _ => Err(ConfigError::invalid(field, format!("{url} must use https (http is allowed only on loopback)"))),
    }
}

pub(crate) struct HttpKeySource {
    uri: Url,
    http: reqwest::Client,
    max_bytes: usize,
}

impl HttpKeySource {
    pub(crate) fn new(cfg: &JwksConfig, http: Option<reqwest::Client>) -> Result<Self, ConfigError> {
        let http = match http {
            Some(c) => c,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(cfg.fetch_timeout)
                .user_agent(concat!("mcpward/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| ConfigError::invalid("jwks", e.to_string()))?,
        };
        Ok(HttpKeySource { uri: cfg.uri.clone(), http, max_bytes: cfg.max_response_bytes })
    }
}

pub(crate) async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, JwksError> {
    if resp.content_length().is_some_and(|l| l as usize > max) {
        return Err(JwksError::TooLarge(max));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| JwksError::Http(e.to_string()))? {
        if buf.len() + chunk.len() > max {
            return Err(JwksError::TooLarge(max));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

impl KeySource for HttpKeySource {
    fn fetch(&self) -> BoxFuture<'_, Result<JwkSet, JwksError>> {
        Box::pin(async move {
            let resp = self
                .http
                .get(self.uri.clone())
                .header(http::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|e| JwksError::Http(e.without_url().to_string()))?;
            if !resp.status().is_success() {
                return Err(JwksError::Status(resp.status().as_u16()));
            }
            let body = read_capped(resp, self.max_bytes).await?;
            JwkSet::from_json(&body)
        })
    }
}

#[derive(Default)]
struct KeySet {
    keys: HashMap<String, Arc<DecodingKey>>,
}

/// The result of looking up a `kid`.
pub(crate) enum KeyLookup {
    Found(Arc<DecodingKey>),
    Unknown,
    Unavailable,
}

struct Inner {
    snapshot: ArcSwap<KeySet>,
    loaded: AtomicBool,
    fetch_lock: tokio::sync::Mutex<()>,
    last_on_demand: Mutex<Option<Instant>>,
    cfg: JwksConfig,
    source: Arc<dyn KeySource>,
    algorithms: Vec<Algorithm>,
}

/// A JWKS cache: lock-free snapshot reads, scheduled refresh, and rate-limited single-flight
/// refetch on an unknown `kid`.
pub struct JwksCache {
    inner: Arc<Inner>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwksCache")
            .field("uri", &self.inner.cfg.uri.as_str())
            .field("keys", &self.inner.snapshot.load().keys.len())
            .finish()
    }
}

impl Drop for JwksCache {
    fn drop(&mut self) {
        if let Some(t) = self.task.lock().ok().and_then(|mut t| t.take()) {
            t.abort();
        }
    }
}

#[derive(Clone, Copy)]
enum Trigger {
    Startup,
    Scheduled,
    UnknownKid,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Trigger::Startup => "startup",
            Trigger::Scheduled => "scheduled",
            Trigger::UnknownKid => "unknown_kid",
        }
    }
}

impl JwksCache {
    /// Creates an empty cache. Call [`JwksCache::start`] to load and begin refreshing.
    pub fn new(cfg: JwksConfig, source: Arc<dyn KeySource>, algorithms: Vec<Algorithm>) -> Self {
        JwksCache {
            inner: Arc::new(Inner {
                snapshot: ArcSwap::from_pointee(KeySet::default()),
                loaded: AtomicBool::new(false),
                fetch_lock: tokio::sync::Mutex::new(()),
                last_on_demand: Mutex::new(None),
                cfg,
                source,
                algorithms,
            }),
            task: Mutex::new(None),
        }
    }

    /// Performs the startup load per [`StartupPolicy`] and spawns the refresh task.
    pub async fn start(&self) -> Result<(), ConfigError> {
        match self.inner.cfg.startup {
            StartupPolicy::WaitUntilLoaded { timeout } => {
                let res = tokio::time::timeout(timeout, load(&self.inner, Trigger::Startup)).await;
                match res {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(ConfigError::JwksUnavailable {
                            uri: self.inner.cfg.uri.to_string(),
                            reason: e.to_string(),
                        });
                    }
                    Err(_) => {
                        return Err(ConfigError::JwksUnavailable {
                            uri: self.inner.cfg.uri.to_string(),
                            reason: format!("timed out after {timeout:?}"),
                        });
                    }
                }
            }
            StartupPolicy::Lazy => {
                let weak = Arc::downgrade(&self.inner);
                tokio::spawn(async move {
                    if let Some(inner) = weak.upgrade() {
                        let _ = load(&inner, Trigger::Startup).await;
                    }
                });
            }
        }
        let weak = Arc::downgrade(&self.inner);
        let handle = tokio::spawn(refresh_loop(weak));
        if let Ok(mut t) = self.task.lock() {
            *t = Some(handle);
        }
        Ok(())
    }

    /// Whether a key set has been loaded at least once.
    pub fn is_loaded(&self) -> bool {
        self.inner.loaded.load(Ordering::Acquire)
    }

    /// The number of keys in the current snapshot.
    pub fn key_count(&self) -> usize {
        self.inner.snapshot.load().keys.len()
    }

    /// The JWKS URI.
    pub fn uri(&self) -> &Url {
        &self.inner.cfg.uri
    }

    pub(crate) async fn key(&self, kid: &str) -> KeyLookup {
        let inner = &self.inner;
        if let Some(k) = inner.snapshot.load().keys.get(kid) {
            return KeyLookup::Found(k.clone());
        }
        // Waiting on the lock (instead of checking the interval first) lets requests that
        // arrive during an in-flight fetch see its result. The lock is uncontended otherwise.
        let _guard = inner.fetch_lock.lock().await;
        // Another task may have fetched while this one waited.
        if let Some(k) = inner.snapshot.load().keys.get(kid) {
            return KeyLookup::Found(k.clone());
        }
        if recently_refetched(inner) {
            return if inner.loaded.load(Ordering::Acquire) { KeyLookup::Unknown } else { KeyLookup::Unavailable };
        }
        if let Ok(mut last) = inner.last_on_demand.lock() {
            *last = Some(Instant::now());
        }
        let _ = fetch_and_swap(inner, Trigger::UnknownKid).await;
        if let Some(k) = inner.snapshot.load().keys.get(kid) {
            return KeyLookup::Found(k.clone());
        }
        if inner.loaded.load(Ordering::Acquire) { KeyLookup::Unknown } else { KeyLookup::Unavailable }
    }
}

fn recently_refetched(inner: &Inner) -> bool {
    inner.last_on_demand.lock().ok().and_then(|l| *l).is_some_and(|t| t.elapsed() < inner.cfg.min_refetch_interval)
}

async fn load(inner: &Inner, trigger: Trigger) -> Result<usize, JwksError> {
    let _guard = inner.fetch_lock.lock().await;
    fetch_and_swap(inner, trigger).await
}

/// Fetches and swaps. The caller holds `fetch_lock`.
async fn fetch_and_swap(inner: &Inner, trigger: Trigger) -> Result<usize, JwksError> {
    // The overall timeout applies whatever the source is: a consumer-supplied HTTP client may
    // have none, and a hung fetch would hold `fetch_lock` for every unknown-`kid` request.
    let timeout = inner.cfg.fetch_timeout;
    let fetched = match tokio::time::timeout(timeout, inner.source.fetch()).await {
        Ok(r) => r,
        Err(_) => Err(JwksError::Timeout(timeout)),
    };
    let result = fetched.and_then(|set| {
        let keys = accept_keys(&set, &inner.algorithms);
        if keys.is_empty() { Err(JwksError::NoUsableKeys) } else { Ok(keys) }
    });
    match result {
        Ok(keys) => {
            let n = keys.len();
            inner.snapshot.store(Arc::new(KeySet { keys }));
            inner.loaded.store(true, Ordering::Release);
            tracing::info!(target: "mcpward::jwks", event = "jwks.refresh", outcome = "ok", keys = n, trigger = trigger.as_str(), "signing keys loaded");
            Ok(n)
        }
        Err(e) => {
            tracing::warn!(target: "mcpward::jwks", event = "jwks.refresh", outcome = "error", error_kind = e.kind(), trigger = trigger.as_str(), uri = %inner.cfg.uri, "signing key refresh failed; keeping current keys");
            Err(e)
        }
    }
}

fn accept_keys(set: &JwkSet, algorithms: &[Algorithm]) -> HashMap<String, Arc<DecodingKey>> {
    let mut out = HashMap::new();
    let families: Vec<AlgorithmFamily> = algorithms.iter().map(|a| a.family()).collect();
    for key in &set.keys {
        let Some(obj) = key.as_object() else { continue };
        let s = |n: &str| obj.get(n).and_then(Value::as_str);
        let Some(kid) = s("kid").filter(|k| !k.is_empty()) else {
            tracing::debug!(target: "mcpward::jwks", "skipping key without kid");
            continue;
        };
        if let Some(u) = s("use")
            && u != "sig"
        {
            continue;
        }
        if let Some(alg) = s("alg")
            && !parse_alg(alg).is_some_and(|a| algorithms.contains(&a))
        {
            continue;
        }
        let decoding = match s("kty") {
            Some("RSA") if families.contains(&AlgorithmFamily::Rsa) => match (s("n"), s("e")) {
                (Some(n), Some(e)) => DecodingKey::from_rsa_components(n, e).ok(),
                _ => None,
            },
            Some("EC") if families.contains(&AlgorithmFamily::Ec) => match (s("x"), s("y")) {
                (Some(x), Some(y)) => DecodingKey::from_ec_components(x, y).ok(),
                _ => None,
            },
            Some("OKP") if families.contains(&AlgorithmFamily::Ed) => {
                s("x").and_then(|x| DecodingKey::from_ed_components(x).ok())
            }
            _ => None,
        };
        match decoding {
            Some(k) => {
                out.insert(kid.to_owned(), Arc::new(k));
            }
            None => tracing::debug!(target: "mcpward::jwks", kid = %truncate(kid), "skipping unusable key"),
        }
    }
    out
}

pub(crate) fn parse_alg(name: &str) -> Option<Algorithm> {
    name.parse::<Algorithm>().ok()
}

pub(crate) fn truncate(s: &str) -> String {
    s.chars().take(256).flat_map(char::escape_default).collect()
}

fn jitter(d: Duration) -> Duration {
    // ±10 % from the clock's sub-second noise; no RNG dependency needed for this.
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|t| t.subsec_nanos()).unwrap_or(0);
    let frac = (nanos % 2001) as f64 / 10_000.0 - 0.1; // -0.1 ..= 0.1
    d.mul_f64(1.0 + frac)
}

async fn refresh_loop(weak: Weak<Inner>) {
    let mut delay = match weak.upgrade() {
        Some(i) => jitter(i.cfg.refresh_interval),
        None => return,
    };
    let mut backoff = Duration::from_secs(30);
    // Until the first load succeeds (a `Lazy` start that failed), retry quickly instead of
    // waiting for the scheduled refresh: `/readyz` doesn't fetch, so a replica that gets no
    // traffic until it is ready would otherwise stay unready for hours.
    let mut unloaded_backoff = Duration::from_secs(1);
    loop {
        let unloaded = match weak.upgrade() {
            Some(i) => !i.loaded.load(Ordering::Acquire),
            None => return,
        };
        let wait = if unloaded {
            let w = unloaded_backoff.min(delay);
            unloaded_backoff = (unloaded_backoff * 2).min(Duration::from_secs(30));
            w
        } else {
            delay
        };
        tokio::time::sleep(wait).await;
        let Some(inner) = weak.upgrade() else { return };
        if unloaded && inner.loaded.load(Ordering::Acquire) {
            // Another path (the lazy start or an on-demand fetch) loaded the keys meanwhile.
            delay = jitter(inner.cfg.refresh_interval);
            continue;
        }
        match load(&inner, Trigger::Scheduled).await {
            Ok(_) => {
                backoff = Duration::from_secs(30);
                delay = jitter(inner.cfg.refresh_interval);
            }
            Err(_) => {
                delay = backoff.min(inner.cfg.refresh_interval);
                backoff = (backoff * 2).min(inner.cfg.refresh_interval);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // A real RSA public key (n, e) from the test-only key set.
    const N: &str = "3NBHC3J-cYet5EXSIr2xp8t0ftN0LjcDoon6Njc2s_wXim0Pp6APsGnQzK7uE5H2XGPJTwqaDm3c_ZGK73vCXqnqYgMD7nl5MpecjcSAB7V2njUHlAcRU3N7XOamkVMdxapBrLbzhQVFDjfW5r3yGvQJQ0iNBPJ4TEpME8hyXL7USaDIgPF5mHbk-WX6rhNx-IpPvOZR7RldDqyFwglHWzenED865qFOhtzLjCvkje52uRwgrMdvwp_bitG-kgHVBmlPYzFdrNdBrTUZ5GyLgMrab6UMSMMPKRVjYPYm1LeWKo2cmAyuapG9QfCk2JulAaaKFnY5c9usFrmmwLJQDQ";
    const E: &str = "AQAB";

    struct Counting {
        fetches: AtomicUsize,
        set: Mutex<JwkSet>,
        fail: AtomicBool,
    }

    impl KeySource for Counting {
        fn fetch(&self) -> BoxFuture<'_, Result<JwkSet, JwksError>> {
            Box::pin(async move {
                self.fetches.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                if self.fail.load(Ordering::SeqCst) {
                    return Err(JwksError::Status(500));
                }
                Ok(self.set.lock().unwrap().clone())
            })
        }
    }

    fn set(kids: &[&str]) -> JwkSet {
        JwkSet {
            keys: kids
                .iter()
                .map(|k| serde_json::json!({"kty": "RSA", "kid": k, "use": "sig", "n": N, "e": E}))
                .collect(),
        }
    }

    fn cache(src: Arc<Counting>) -> JwksCache {
        crate::auth::ensure_crypto_provider();
        let mut cfg = JwksConfig::new("http://127.0.0.1/jwks".parse().unwrap());
        cfg.min_refetch_interval = Duration::from_secs(10);
        JwksCache::new(cfg, src, vec![Algorithm::RS256])
    }

    fn src(kids: &[&str]) -> Arc<Counting> {
        Arc::new(Counting { fetches: AtomicUsize::new(0), set: Mutex::new(set(kids)), fail: AtomicBool::new(false) })
    }

    #[tokio::test]
    async fn startup_loads_and_filters() {
        let s = src(&["a"]);
        s.set.lock().unwrap().keys.push(serde_json::json!({"kty": "RSA", "kid": "enc", "use": "enc", "n": N, "e": E}));
        s.set.lock().unwrap().keys.push(serde_json::json!({"kty": "RSA", "kid": "hs", "alg": "HS256", "n": N, "e": E}));
        s.set.lock().unwrap().keys.push(serde_json::json!({"kty": "oct", "kid": "o", "k": "AAAA"}));
        s.set.lock().unwrap().keys.push(serde_json::json!({"kty": "RSA", "n": N, "e": E}));
        let c = cache(s.clone());
        c.start().await.unwrap();
        assert!(c.is_loaded());
        assert_eq!(c.key_count(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_single_flight_and_rate_limit() {
        let s = src(&["a"]);
        let c = Arc::new(cache(s.clone()));
        c.start().await.unwrap();
        assert_eq!(s.fetches.load(Ordering::SeqCst), 1);
        // The provider rotates; 100 concurrent requests with the new kid share one fetch.
        *s.set.lock().unwrap() = set(&["b"]);
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let c = c.clone();
            tasks.push(tokio::spawn(async move { matches!(c.key("b").await, KeyLookup::Found(_)) }));
        }
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(s.fetches.load(Ordering::SeqCst), 2);
        // A junk kid right after is rejected without a fetch.
        assert!(matches!(c.key("junk").await, KeyLookup::Unknown));
        assert_eq!(s.fetches.load(Ordering::SeqCst), 2);
        // The rotated-out key is gone: no pinning.
        assert!(matches!(c.key("a").await, KeyLookup::Unknown));
    }

    #[tokio::test]
    async fn failed_refresh_keeps_keys() {
        let s = src(&["a"]);
        let c = cache(s.clone());
        c.start().await.unwrap();
        s.fail.store(true, Ordering::SeqCst);
        assert!(load(&c.inner, Trigger::Scheduled).await.is_err());
        assert!(matches!(c.key("a").await, KeyLookup::Found(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_refresh_runs() {
        let s = src(&["a"]);
        let c = cache(s.clone());
        c.start().await.unwrap();
        *s.set.lock().unwrap() = set(&["b"]);
        tokio::time::sleep(Duration::from_secs(7 * 3600)).await;
        assert!(s.fetches.load(Ordering::SeqCst) >= 2);
        assert!(c.inner.snapshot.load().keys.contains_key("b"));
    }

    #[tokio::test]
    async fn startup_failure_is_config_error() {
        let s = src(&["a"]);
        s.fail.store(true, Ordering::SeqCst);
        let c = cache(s);
        let err = c.start().await.unwrap_err();
        assert!(err.to_string().contains("127.0.0.1/jwks"));
    }

    #[test]
    fn config_bounds() {
        let mut cfg = JwksConfig::new("https://login.example.com/keys".parse().unwrap());
        assert!(cfg.validate().is_ok());
        cfg.min_refetch_interval = Duration::from_secs(1);
        assert!(cfg.validate().is_err());
        let cfg = JwksConfig::new("http://login.example.com/keys".parse().unwrap());
        assert!(cfg.validate().is_err());
    }
}
