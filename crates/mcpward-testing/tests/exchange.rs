//! Entra On-Behalf-Of against the mock token endpoint: request shape, credentials, error-code
//! mapping, caching, and single-flight.

use std::{sync::Arc, time::Duration};

use mcpward::{
    Principal,
    auth::{AuthError, Entra, JwtValidator, SubjectToken, TokenValidator},
    exchange::{ClientCredential, EntraObo, ExchangeError, ExchangeTarget, TokenExchanger},
};
use mcpward_testing::{EntraError, TEST_CLIENT_ID, TestIssuer, TestTokenEndpoint};

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const API: &str = "00000000-0000-0000-0000-000000000002";
const UAMI: &str = "00000000-0000-0000-0000-000000000004";

struct Fixture {
    issuer: TestIssuer,
    validator: JwtValidator,
    ep: TestTokenEndpoint,
}

async fn fixture() -> Fixture {
    let issuer = TestIssuer::entra(TENANT, API).start().await;
    let mut cfg = Entra::new(TENANT, API).issuer_config("https://mcp.example.com/mcp").unwrap();
    cfg.jwks.uri = issuer.jwks_uri();
    let validator = JwtValidator::builder()
        .issuer(cfg)
        .required_scopes(["access_as_user"])
        .allowed_clients([TEST_CLIENT_ID])
        .build()
        .await
        .unwrap();
    Fixture { issuer, validator, ep: TestTokenEndpoint::start().await }
}

impl Fixture {
    async fn user(&self, oid: &str) -> (Principal, SubjectToken) {
        self.user_with(oid, Duration::from_secs(3600)).await
    }
    async fn user_with(&self, oid: &str, life: Duration) -> (Principal, SubjectToken) {
        let t = self.issuer.token().oid(oid).expires_in(life).mint();
        let p: Result<Principal, AuthError> = self.validator.validate(&t).await;
        (p.unwrap(), SubjectToken::new(&t))
    }
    fn obo(&self) -> EntraObo {
        self.ep.obo_builder(TENANT, API, self.ep.obo_credential()).build().unwrap()
    }
}

fn target() -> ExchangeTarget {
    ExchangeTarget {
        name: "orders-api",
        scopes: vec!["api://00000000-0000-0000-0000-000000000003/access_as_user".into()],
    }
}

#[tokio::test]
async fn obo_request_shape_with_secret() {
    let f = fixture().await;
    let obo = f.obo();
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let t = obo.exchange(&p, &s, &target()).await.unwrap();
    assert!(t.expose_secret().starts_with("mock-obo-token-"));
    assert!(t.expires_at > std::time::SystemTime::now());
    let reqs = f.ep.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(r.tenant, TENANT);
    assert_eq!(r.grant_type, "urn:ietf:params:oauth:grant-type:jwt-bearer");
    assert_eq!(r.requested_token_use, "on_behalf_of");
    assert_eq!(r.client_id, API);
    assert_eq!(r.scope, target().scopes[0]);
    assert!(r.has_client_secret && !r.has_client_assertion);
    assert_eq!(r.assertion_claims["oid"], "00000000-0000-0000-0000-0000000000b1");
    assert!(!r.scope.contains("offline_access"));
}

#[tokio::test]
async fn cache_is_per_user_and_target() {
    let f = fixture().await;
    let obo = f.obo();
    let (a, sa) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let (b, sb) = f.user("00000000-0000-0000-0000-0000000000b2").await;
    let t1 = obo.exchange(&a, &sa, &target()).await.unwrap();
    let t2 = obo.exchange(&a, &sa, &target()).await.unwrap();
    assert_eq!(t1.expose_secret(), t2.expose_secret());
    assert_eq!(f.ep.request_count(), 1);
    let t3 = obo.exchange(&b, &sb, &target()).await.unwrap();
    assert_ne!(t1.expose_secret(), t3.expose_secret());
    let other = ExchangeTarget { name: "graph", scopes: vec!["https://graph.microsoft.com/User.Read".into()] };
    obo.exchange(&a, &sa, &other).await.unwrap();
    assert_eq!(f.ep.request_count(), 3);
}

#[tokio::test]
async fn single_flight() {
    let f = fixture().await;
    let obo = Arc::new(f.obo());
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let (obo, p, s) = (obo.clone(), p.clone(), s.clone());
        tasks.push(tokio::spawn(
            async move { obo.exchange(&p, &s, &target()).await.map(|t| t.expose_secret().to_owned()) },
        ));
    }
    let mut tokens = std::collections::BTreeSet::new();
    for t in tasks {
        tokens.insert(t.await.unwrap().unwrap());
    }
    assert_eq!(tokens.len(), 1);
    assert_eq!(f.ep.request_count(), 1);
}

#[tokio::test]
async fn entry_never_outlives_the_upstream_token() {
    let f = fixture().await;
    let obo = f.obo();
    // The user token expires inside the 3-minute margin, so the result isn't kept.
    let (p, s) = f.user_with("00000000-0000-0000-0000-0000000000b1", Duration::from_secs(100)).await;
    obo.exchange(&p, &s, &target()).await.unwrap();
    obo.exchange(&p, &s, &target()).await.unwrap();
    assert_eq!(f.ep.request_count(), 2);
}

#[tokio::test]
async fn error_codes_map_and_are_not_cached() {
    let f = fixture().await;
    let obo = f.obo();
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    f.ep.fail_next(EntraError::codes(&[65001]));
    let e = obo.exchange(&p, &s, &target()).await.unwrap_err();
    assert!(matches!(e, ExchangeError::ConsentRequired { ref codes } if codes == &[65001]), "{e:?}");
    assert!(e.user_message().contains("administrator needs to grant consent"));
    f.ep.fail_next(EntraError::codes(&[50173]));
    assert!(matches!(obo.exchange(&p, &s, &target()).await.unwrap_err(), ExchangeError::SessionRevoked { .. }));
    f.ep.fail_next(EntraError::codes(&[50076]).error("interaction_required"));
    assert!(matches!(obo.exchange(&p, &s, &target()).await.unwrap_err(), ExchangeError::InteractionRequired { .. }));
    f.ep.fail_next(EntraError::codes(&[700016]).error("unauthorized_client"));
    assert!(matches!(obo.exchange(&p, &s, &target()).await.unwrap_err(), ExchangeError::Misconfigured { .. }));
    f.ep.fail_next(EntraError::codes(&[99999]));
    let e = obo.exchange(&p, &s, &target()).await.unwrap_err();
    assert!(
        matches!(e, ExchangeError::Misconfigured { .. }),
        "unknown invalid_grant tells the user to contact an admin"
    );
    f.ep.fail_next(EntraError::unavailable());
    assert!(matches!(obo.exchange(&p, &s, &target()).await.unwrap_err(), ExchangeError::Unavailable(_)));
    let ok = obo.exchange(&p, &s, &target()).await;
    assert!(ok.is_ok(), "errors are not cached");
    let failure: mcpward::ToolFailure = ExchangeError::SessionRevoked { codes: vec![50173] }.into();
    assert_eq!(failure.to_json()["error"], "session_revoked");
}

#[tokio::test]
async fn managed_identity_credential() {
    let f = fixture().await;
    let obo = f.ep.managed_identity_obo(TENANT, API, UAMI).build().unwrap();
    let (a, sa) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let (b, sb) = f.user("00000000-0000-0000-0000-0000000000b2").await;
    obo.exchange(&a, &sa, &target()).await.unwrap();
    obo.exchange(&b, &sb, &target()).await.unwrap();
    let reqs = f.ep.requests();
    assert!(reqs.iter().all(|r| r.assertion_from_identity_endpoint && !r.has_client_secret));
    assert_eq!(
        reqs[0].client_assertion_type.as_deref(),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
    assert_eq!(f.ep.identity_requests(), 1, "the federated assertion is cached");
}

#[tokio::test]
async fn managed_identity_requires_client_id() {
    let f = fixture().await;
    assert!(f.ep.managed_identity_obo(TENANT, API, "").build().is_err());
}

#[tokio::test]
async fn assertion_file_credential() {
    let f = fixture().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "file-assertion\n").unwrap();
    let obo = f.ep.obo_builder(TENANT, API, ClientCredential::AssertionFile { path: path.clone() }).build().unwrap();
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    obo.exchange(&p, &s, &target()).await.unwrap();
    let r = &f.ep.requests()[0];
    assert!(r.has_client_assertion && !r.has_client_secret);
}

#[tokio::test]
async fn offline_access_is_never_requested() {
    let f = fixture().await;
    let obo = f.obo();
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let t = ExchangeTarget { name: "x", scopes: vec!["offline_access".into()] };
    assert!(obo.exchange(&p, &s, &t).await.is_err());
    assert_eq!(f.ep.request_count(), 0);
}

#[tokio::test]
async fn mint_with_returns_a_real_jwt() {
    let f = fixture().await;
    let downstream = TestIssuer::start().await;
    let iss = downstream.token();
    f.ep.mint_with(move |req| iss.clone().sub(req.assertion_claims["oid"].as_str().unwrap_or("")).mint());
    let obo = f.obo();
    let (p, s) = f.user("00000000-0000-0000-0000-0000000000b1").await;
    let t = obo.exchange(&p, &s, &target()).await.unwrap();
    assert_eq!(t.expose_secret().split('.').count(), 3);
}
