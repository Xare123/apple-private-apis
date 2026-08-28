#![cfg(feature = "remote-anisette-v3")]

//! Manual credential-free probe for the production remote Anisette v3 client.
//!
//! This uses generated, in-memory state only. It never accepts an Apple ID,
//! password, relay code, or persisted ADI value. The probe is ignored by
//! default because it sends generated provisioning material to SideStore's
//! public relay service and Apple's provisioning endpoints.

use std::time::Duration;

use omnisette::{
    remote_anisette_v3::{AnisetteClient, AnisetteState},
    AnisetteError, LoginClientInfo,
};
use tokio::time::timeout;

const ENDPOINTS: [&str; 2] = ["https://ani.sidestore.io", "https://ani.sidestore.app"];
const OVERALL_TIMEOUT: Duration = Duration::from_secs(150);

fn login_info() -> LoginClientInfo {
    LoginClientInfo {
        mme_client_info:
            "<iPhone7,2> <iPhone OS;12.5.5;16H62> <com.apple.akd/1.0 (com.apple.akd/1.0)>".into(),
        akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".into(),
        ..LoginClientInfo::default()
    }
}

fn error_kind(error: &AnisetteError) -> &'static str {
    match error {
        AnisetteError::InvalidArgument(_) => "invalid_argument",
        AnisetteError::AnisetteNotProvisioned => "not_provisioned",
        AnisetteError::ReqwestError(_) => "http_error",
        AnisetteError::WsError(_) => "websocket_error",
        AnisetteError::SerdeError(_) => "json_error",
        AnisetteError::ProvisioningServerError(_) => "server_error",
        AnisetteError::ProvisioningSocketClosed => "socket_closed",
        _ => "other_error",
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual credential-free probe; sends generated protocol material to public relays"]
async fn credential_free_v3_probe() {
    for endpoint in ENDPOINTS {
        let mut state = AnisetteState::new();
        let result = timeout(OVERALL_TIMEOUT, async {
            let client = AnisetteClient::new(endpoint.into(), login_info()).await?;
            client.provision(&mut state).await
        })
        .await;

        match result {
            Ok(Ok(())) => println!("endpoint={endpoint} outcome=provisioning_complete"),
            Ok(Err(error)) => println!(
                "endpoint={endpoint} outcome=failed result={}",
                error_kind(&error)
            ),
            Err(_) => println!("endpoint={endpoint} outcome=failed result=overall_timeout"),
        }
    }
}
