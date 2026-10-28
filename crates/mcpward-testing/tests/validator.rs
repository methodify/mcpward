//! One test per row of the validation table, against `JwtValidator` directly.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcpward::ConfigError;
use mcpward::auth::{
    Algorithm, AuthError, ClaimEquals, Entra, JwtValidator, JwtValidatorBuilder, PrincipalKind, RejectReason,
    TokenValidator,
};
use mcpward_testing::{TEST_CLIENT_ID, TEST_OID, TestIssuer};

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const API: &str = "00000000-0000-0000-0000-000000000002";
const URL: &str = "https://mcp.example.com/mcp";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn bare(issuer: &TestIssuer, edit: impl FnOnce(&mut mcpward::auth::IssuerConfig)) -> JwtValidatorBuilder {
    let mut cfg = Entra::new(TENANT, API).issuer_config(URL).unwrap();
    cfg.jwks.uri = issuer.jwks_uri();
    cfg.jwks.min_refetch_interval = Duration::from_secs(10);
    edit(&mut cfg);
    JwtValidator::builder().issuer(cfg)
}

fn base(issuer: &TestIssuer, edit: impl FnOnce(&mut mcpward::auth::IssuerConfig)) -> JwtValidatorBuilder {
    bare(issuer, edit).required_scopes(["access_as_user"]).allowed_clients([TEST_CLIENT_ID])
}

async fn setup() -> (TestIssuer, JwtValidator) {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = base(&issuer, |_| {}).build().await.unwrap();
    (issuer, v)
}

async fn reason(v: &JwtValidator, token: &str) -> RejectReason {
    match v.validate(token).await {
        Err(AuthError::Rejected(r)) => r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn valid_token_maps_principal() {
    let (issuer, v) = setup().await;
    let p = v.validate(&issuer.token().roles(&["R"]).mint()).await.unwrap();
    assert_eq!(p.subject.key(), format!("{TENANT}:{TEST_OID}"));
    assert_eq!(p.subject.tenant(), Some(TENANT));
    assert_eq!(p.client_id.as_deref(), Some(TEST_CLIENT_ID));
    assert!(p.has_scope("access_as_user") && p.has_role("R"));
    assert_eq!(p.kind, PrincipalKind::User);
    assert_eq!(p.username.as_deref(), Some("test.user@example.com"));
    assert!(p.token_id.is_some());
    assert_eq!(p.claim::<String>("ver").as_deref(), Some("2.0"));
}

#[tokio::test]
async fn row01_transport_empty_and_oversized() {
    let (_, v) = setup().await;
    assert_eq!(reason(&v, "").await, RejectReason::MissingToken);
    assert_eq!(reason(&v, &"a".repeat(17 * 1024)).await, RejectReason::Malformed);
}

#[tokio::test]
async fn row02_shape() {
    let (_, v) = setup().await;
    assert_eq!(reason(&v, "abc.def").await, RejectReason::Malformed);
    assert_eq!(reason(&v, "a.b.c.d").await, RejectReason::Malformed);
    assert_eq!(reason(&v, "bm90LWpzb24.e30.sig").await, RejectReason::Malformed);
}

#[tokio::test]
async fn row03_alg_allowlist() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().alg_none().mint()).await, RejectReason::AlgorithmNotAllowed);
    assert_eq!(reason(&v, &issuer.token().hs256_with_public_key().mint()).await, RejectReason::AlgorithmNotAllowed);
    let err = base(&issuer, |_| {}).algorithms(&[Algorithm::HS256]).build().await.unwrap_err();
    assert!(err.to_string().contains("HMAC"), "{err}");
}

#[tokio::test]
async fn row04_typ() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = base(&issuer, |c| c.required_typ = Some("at+jwt".into())).build().await.unwrap();
    assert_eq!(reason(&v, &issuer.token().mint()).await, RejectReason::WrongType);
    assert!(v.validate(&issuer.token().typ(Some("AT+JWT")).mint()).await.is_ok());
}

#[tokio::test]
async fn row05_kid() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().without_kid().mint()).await, RejectReason::MissingKid);
    assert_eq!(reason(&v, &issuer.token().unknown_kid().mint()).await, RejectReason::UnknownKid);
}

#[tokio::test]
async fn row06_signature() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().signed_by_untrusted_key().mint()).await, RejectReason::BadSignature);
    let t = issuer.token().mint();
    let mut parts: Vec<&str> = t.split('.').collect();
    let other = issuer.token().oid("someone-else").mint();
    let other_payload = other.split('.').nth(1).unwrap().to_owned();
    parts[1] = &other_payload;
    assert_eq!(reason(&v, &parts.join(".")).await, RejectReason::BadSignature, "payload swap");
}

#[tokio::test]
async fn row07_iss() {
    let (issuer, v) = setup().await;
    assert_eq!(
        reason(&v, &issuer.token().iss("https://login.microsoftonline.com/other/v2.0").mint()).await,
        RejectReason::WrongIssuer
    );
    assert_eq!(reason(&v, &issuer.token().without("iss").mint()).await, RejectReason::MissingClaim);
}

#[tokio::test]
async fn row08_aud() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().aud("api://other").mint()).await, RejectReason::WrongAudience);
    for aud in [API.to_owned(), format!("api://{API}"), URL.to_owned()] {
        assert!(v.validate(&issuer.token().aud(&aud).mint()).await.is_ok(), "{aud}");
    }
    assert!(v.validate(&issuer.token().claim("aud", ["x", API]).mint()).await.is_ok());
    assert_eq!(reason(&v, &issuer.token().without("aud").mint()).await, RejectReason::MissingClaim);
}

#[tokio::test]
async fn row09_exp_with_leeway() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().expired().mint()).await, RejectReason::Expired);
    assert_eq!(reason(&v, &issuer.token().without("exp").mint()).await, RejectReason::MissingClaim);
    assert!(v.validate(&issuer.token().claim("exp", now() - 60).mint()).await.is_ok(), "inside the 120 s leeway");
    let err = base(&issuer, |_| {}).leeway(Duration::from_secs(301)).build().await.unwrap_err();
    assert!(err.to_string().contains("leeway"));
}

#[tokio::test]
async fn row10_nbf() {
    let (issuer, v) = setup().await;
    assert_eq!(
        reason(&v, &issuer.token().not_before_in(Duration::from_secs(600)).mint()).await,
        RejectReason::NotYetValid
    );
    assert_eq!(
        reason(&v, &issuer.token().without("nbf").mint()).await,
        RejectReason::MissingClaim,
        "Entra requires nbf"
    );
    assert!(v.validate(&issuer.token().not_before_in(Duration::from_secs(60)).mint()).await.is_ok());
}

#[tokio::test]
async fn row11_iat() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().claim("iat", now() + 600).mint()).await, RejectReason::NotYetValid);
}

#[tokio::test]
async fn row12_tenant() {
    let (issuer, v) = setup().await;
    assert_eq!(
        reason(&v, &issuer.token().tid("00000000-0000-0000-0000-0000000000ff").mint()).await,
        RejectReason::WrongTenant
    );
}

#[tokio::test]
async fn row13_version() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().claim("ver", "1.0").mint()).await, RejectReason::WrongTokenVersion);
}

#[tokio::test]
async fn row14_token_use() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = base(&issuer, |c| c.required_claims.push(ClaimEquals::new("token_use", "access"))).build().await.unwrap();
    assert_eq!(reason(&v, &issuer.token().mint()).await, RejectReason::WrongTokenUse);
    assert!(v.validate(&issuer.token().claim("token_use", "access").mint()).await.is_ok());
}

#[tokio::test]
async fn row15_subject_and_app_tokens() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().without("oid").mint()).await, RejectReason::MissingSubject);
    assert_eq!(reason(&v, &issuer.token().oid("").mint()).await, RejectReason::MissingSubject);
    assert_eq!(reason(&v, &issuer.token().app_only().mint()).await, RejectReason::AppTokenNotAllowed);
    assert_eq!(reason(&v, &issuer.token().without("scp").roles(&["X"]).mint()).await, RejectReason::AppTokenNotAllowed);
    let v = bare(&issuer, |_| {})
        .allowed_clients([TEST_CLIENT_ID])
        .allow_app_tokens(true)
        .no_required_scopes()
        .build()
        .await
        .unwrap();
    assert_eq!(v.validate(&issuer.token().app_only().mint()).await.unwrap().kind, PrincipalKind::Application);
}

#[tokio::test]
async fn row16_client_allowlist() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().azp("other").mint()).await, RejectReason::ClientNotAllowed);
    assert_eq!(reason(&v, &issuer.token().without("azp").mint()).await, RejectReason::ClientNotAllowed);
    let any = bare(&issuer, |_| {}).required_scopes(["access_as_user"]).allow_any_client().build().await.unwrap();
    assert!(any.validate(&issuer.token().azp("other").mint()).await.is_ok());
}

#[tokio::test]
async fn row17_base_scope() {
    let (issuer, v) = setup().await;
    assert_eq!(reason(&v, &issuer.token().scopes(&["other"]).mint()).await, RejectReason::InsufficientScope);
}

#[tokio::test]
async fn row18_custom_check() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let v = base(&issuer, |_| {})
        .claim_check(
            |p: &mcpward::Principal| if p.has_role("Banned") { Err(RejectReason::Custom("banned")) } else { Ok(()) },
        )
        .build()
        .await
        .unwrap();
    assert_eq!(reason(&v, &issuer.token().roles(&["Banned"]).mint()).await, RejectReason::Custom("banned"));
    assert!(v.validate(&issuer.token().mint()).await.is_ok());
}

#[tokio::test]
async fn builder_fails_closed() {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let mut cfg = Entra::new(TENANT, API).issuer_config(URL).unwrap();
    cfg.jwks.uri = issuer.jwks_uri();
    let err = JwtValidator::builder().issuer(cfg.clone()).allowed_clients(["c"]).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::NoRequiredScopes));
    let err = JwtValidator::builder().issuer(cfg.clone()).required_scopes(["s"]).build().await.unwrap_err();
    assert!(matches!(err, ConfigError::NoClientAllowlist));
    let err = JwtValidator::builder()
        .issuer(cfg)
        .required_scopes(["s"])
        .allowed_clients(Vec::<String>::new())
        .build()
        .await
        .unwrap_err();
    assert!(matches!(err, ConfigError::NoClientAllowlist), "an empty allowlist is not an opt-out");
}

#[tokio::test]
async fn generic_oidc_discovery_and_claims() {
    let issuer = TestIssuer::start().await;
    let http = reqwest::Client::new();
    let cfg = mcpward::Oidc::new(issuer.issuer())
        .audience(mcpward_testing::TEST_AUDIENCE)
        .roles_claim("realm_access.roles")
        .issuer_config(&http)
        .await
        .unwrap();
    assert_eq!(cfg.jwks.uri, issuer.jwks_uri());
    let v = JwtValidator::builder()
        .issuer(cfg)
        .required_scopes(["access_as_user"])
        .allowed_clients(["kc-client"])
        .build()
        .await
        .unwrap();
    // Keycloak-shaped token: nested roles, client in azp.
    let t = issuer.token().azp("kc-client").claim("realm_access", serde_json::json!({"roles": ["Admin"]})).mint();
    let p = v.validate(&t).await.unwrap();
    assert!(p.has_role("Admin"));
    assert_eq!(p.subject.key(), mcpward_testing::TEST_SUBJECT);
    // Okta-shaped: scp as an array, client in cid.
    let t = issuer
        .token()
        .without("azp")
        .without("scope")
        .claim("cid", "kc-client")
        .claim("scp", ["access_as_user"])
        .mint();
    assert!(v.validate(&t).await.is_ok());
    // A mismatched discovery issuer is refused.
    let wrong = mcpward::Oidc::new(format!("{}/", issuer.issuer())).audience("x").issuer_config(&http).await;
    assert!(wrong.is_err());
}

#[tokio::test]
async fn jwks_appid_uri_refused_for_entra() {
    let auth =
        mcpward::Auth::entra(Entra::new(TENANT, API)).required_scopes(["s"]).allowed_clients(["c"]).jwks(|mut j| {
            j.uri = "https://login.microsoftonline.com/x/discovery/v2.0/keys?appid=abc".parse().unwrap();
            j
        });
    let probe = mcpward::McpServer::builder(Noop)
        .tools(&mcpward::rmcp::handler::server::router::tool::ToolRouter::<Noop>::new());
    let err = probe.resource_url(URL).unwrap().auth(auth).build().await.unwrap_err();
    assert!(err.to_string().contains("appid"), "{err}");
}

#[derive(Clone)]
struct Noop;
impl mcpward::rmcp::ServerHandler for Noop {}
