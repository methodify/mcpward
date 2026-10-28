//! Adversarial validator tests: claim shapes and configurations that should fail closed.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcpward::auth::{
    AuthError, Entra, JwtValidator, JwtValidatorBuilder, PrincipalKind, RejectReason, StartupPolicy, TokenValidator,
};
use mcpward_testing::{TEST_CLIENT_ID, TestIssuer};

const TENANT: &str = "00000000-0000-0000-0000-00000000000a";
const API: &str = "00000000-0000-0000-0000-00000000000b";
const URL: &str = "https://mcp.example.com/mcp";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn bare(issuer: &TestIssuer, tenant: &str, api: &str) -> JwtValidatorBuilder {
    let mut cfg = Entra::new(tenant, api).issuer_config(URL).unwrap();
    cfg.jwks.uri = issuer.jwks_uri();
    cfg.jwks.min_refetch_interval = Duration::from_secs(10);
    JwtValidator::builder().issuer(cfg)
}

async fn reason(v: &JwtValidator, token: &str) -> Result<PrincipalKind, RejectReason> {
    match v.validate(token).await {
        Ok(p) => Ok(p.kind),
        Err(AuthError::Rejected(r)) => Err(r),
        Err(e) => panic!("{e}"),
    }
}

/// An Entra app-only token (client credentials) carries neither `scp` nor, unless the API
/// configured the optional claim, `idtyp`. With no app roles assigned it has no `roles`
/// either. Such a token must never be treated as a user.
#[tokio::test]

async fn entra_app_only_token_without_idtyp_or_roles() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let token = issuer.token().without("scp").without("name").without("preferred_username").mint();
    // Default config: refused as app-only (before the base scope check).
    let v = bare(&issuer, TENANT, API)
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await
        .unwrap();
    assert_eq!(reason(&v, &token).await, Err(RejectReason::AppTokenNotAllowed));
    // With the scope opt-out it is still refused as app-only, never accepted as a user.
    let v = bare(&issuer, TENANT, API).no_required_scopes().allowed_clients([TEST_CLIENT_ID]).build().await.unwrap();
    let got = reason(&v, &token).await;
    eprintln!("app-only token without idtyp/roles, no_required_scopes: {got:?}");
    assert_eq!(got, Err(RejectReason::AppTokenNotAllowed), "app-only token accepted as {got:?}");
}

#[tokio::test]
async fn odd_claim_types() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = bare(&issuer, TENANT, API)
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await
        .unwrap();
    let far = (now() + 10 * 365 * 86400).to_string();
    // exp as a string must not be read as "no expiry".
    let r = reason(&v, &issuer.token().claim("exp", &far).mint()).await;
    eprintln!("exp as string: {r:?}");
    assert!(r.is_err());
    // tid as an array containing the tenant.
    let r = reason(&v, &issuer.token().claim("tid", [TENANT]).mint()).await;
    assert_eq!(r, Err(RejectReason::WrongTenant));
    // aud as an array with the right audience plus another: accepted (RFC 7519).
    assert!(reason(&v, &issuer.token().claim("aud", [API, "https://other.example.com"]).mint()).await.is_ok());
    // azp as an array: refused.
    let r = reason(&v, &issuer.token().claim("azp", [TEST_CLIENT_ID]).mint()).await;
    assert_eq!(r, Err(RejectReason::ClientNotAllowed));
    // scp with tab separators does not grant access_as_user.
    let r = reason(&v, &issuer.token().claim("scp", "x\taccess_as_user").mint()).await;
    assert_eq!(r, Err(RejectReason::InsufficientScope));
    // scp as an array is not read in the Entra preset.
    let r = reason(&v, &issuer.token().claim("scp", ["access_as_user"]).mint()).await;
    assert_eq!(r, Err(RejectReason::InsufficientScope));
}

/// A non-integer `iat` in the future skips the `iat` check (it is read with `as_u64`).
#[tokio::test]

async fn float_iat_in_the_future() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = bare(&issuer, TENANT, API)
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await
        .unwrap();
    let r = reason(&v, &issuer.token().claim("iat", (now() + 86400) as f64 + 0.5).mint()).await;
    assert_eq!(r, Err(RejectReason::NotYetValid));
}

/// Entra writes GUIDs in lowercase. A tenant or client ID configured in uppercase passes the
/// GUID check but then no token matches `iss`/`tid`/`aud`.
#[tokio::test]

async fn uppercase_guid_config() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = bare(&issuer, &TENANT.to_uppercase(), &API.to_uppercase())
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await;
    // Either normalize (the token validates) or refuse at build.
    if let Ok(v) = v {
        assert!(reason(&v, &issuer.token().mint()).await.is_ok(), "uppercase GUIDs build but reject every token");
    }
}

/// With `StartupPolicy::Lazy`, a failed first load is retried only on demand (a request with
/// a `kid`) or at the scheduled refresh (6 h by default). `/readyz` doesn't trigger a fetch, so
/// a replica gated on readiness gets no traffic and stays unready until the scheduled refresh.
#[tokio::test]

async fn lazy_startup_failure_is_not_retried() {
    use mcpward::auth::{BoxFuture, JwkSet, JwksError, KeySource};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct FailOnce {
        calls: AtomicUsize,
        good: JwkSet,
    }
    impl KeySource for FailOnce {
        fn fetch(&self) -> BoxFuture<'_, Result<JwkSet, JwksError>> {
            Box::pin(async move {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(JwksError::Status(503))
                } else {
                    Ok(self.good.clone())
                }
            })
        }
    }
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let good: JwkSet = reqwest::get(issuer.jwks_uri()).await.unwrap().json().await.unwrap();
    let src = Arc::new(FailOnce { calls: AtomicUsize::new(0), good });
    let mut cfg = Entra::new(TENANT, API).issuer_config(URL).unwrap();
    cfg.jwks.uri = issuer.jwks_uri();
    cfg.jwks.startup = StartupPolicy::Lazy;
    cfg.jwks.refresh_interval = Duration::from_secs(60);
    let v = JwtValidator::builder()
        .issuer(cfg)
        .key_source(src.clone())
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let ready_without_traffic = v.ready();
    let fetches_without_traffic = src.calls.load(Ordering::SeqCst);
    // One request with a kid triggers the on-demand fetch and recovers.
    let _ = v.validate(&issuer.token().mint()).await;
    eprintln!(
        "lazy: ready after 3 s with no traffic = {ready_without_traffic} ({fetches_without_traffic} fetches); after one request = {}",
        v.ready()
    );
    assert!(ready_without_traffic, "a healthy key source was not retried: readiness stays false until traffic arrives");
}
