//! Explicit public transport observation using the unchanged production client.
//! Never authenticates, loads a saved profile, or requests Anisette/OTP data.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct DeniedProvider(Arc<AtomicUsize>);

impl AnisetteProvider for DeniedProvider {
    async fn get_anisette_headers(
        &mut self,
    ) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(omnisette::AnisetteError::AnisetteNotProvisioned)
    }
}

#[tokio::test]
#[ignore = "one explicit credential-free HTTPS GET; not a login or service-health test"]
async fn manual_public_gsa_transport() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Mutex::new(AnisetteClient::new(DeniedProvider(
        calls.clone(),
    ))));
    let account = AppleAccount::new_with_anisette(LoginClientInfo::default(), provider).unwrap();
    assert!(account.username.is_none() && account.spd.is_none());
    assert!(account.tokens.is_empty() && account.hashed_password.is_none());

    let started = std::time::Instant::now();
    let result = account
        .client
        .get(GSA_ENDPOINT)
        .timeout(Duration::from_secs(6))
        .send()
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut response = match result {
        Ok(response) => response,
        Err(error) => {
            println!(
                "{}",
                json!({
                    "probe": "public-gsa-production-client", "http_status": 0,
                    "strict_https": false, "failure": format!("{error:?}"),
                    "provider_calls": 0, "credentials_loaded": false,
                    "authentication_tested": false,
                    "milliseconds": started.elapsed().as_millis(),
                })
            );
            panic!("public transport failed before an HTTP response; no login attempted");
        }
    };
    let same_origin =
        response.url().origin() == reqwest::Url::parse(GSA_ENDPOINT).unwrap().origin();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let complete = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = 4096 - body.len();
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if body.len() == 4096 {
                        return false;
                    }
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    let digest = format!("{:x}", Sha256::digest(&body));
    println!(
        "{}",
        json!({
            "probe": "public-gsa-production-client", "http_status": status,
            "strict_https": same_origin, "final_origin": safe_response_origin(response.url().as_str()),
            "body_complete": complete, "observed_bytes": body.len(),
            "body_sha256_prefix": if complete { Some(&digest[..16]) } else { None },
            "body_is_html": looks_like_html(&String::from_utf8_lossy(&body)),
            "provider_calls": calls.load(Ordering::SeqCst), "credentials_loaded": false,
            "authentication_tested": false, "milliseconds": started.elapsed().as_millis(),
        })
    );
    assert!(
        same_origin,
        "unexpected redirect; not same-origin transport proof"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
