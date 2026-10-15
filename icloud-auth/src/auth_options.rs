use super::{looks_like_html, AuthenticationExtras, Error, LoginState, PhoneNumber, VerifyBody};
use log::{debug, info, warn};
use reqwest::{header::CONTENT_TYPE, Response};
use std::time::Duration;

const AUTH_OPTIONS_DIAGNOSTIC_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum DiagnosticRead {
    Complete,
    Limited,
    ReadError,
    Timeout,
}

fn auth_options_failure_summary(
    status: u16,
    content_type: &str,
    body: &[u8],
    read: DiagnosticRead,
) -> String {
    // Only fixed classifications and numbers may escape. Never log response
    // text, arbitrary header values, URLs, phone numbers, codes or tokens.
    let media = match content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "application/json" => "json",
        "text/html" => "html",
        "text/xml" | "application/xml" | "text/x-xml-plist" => "xml",
        "" => "absent",
        _ => "other",
    };
    let body = &body[..body.len().min(AUTH_OPTIONS_DIAGNOSTIC_LIMIT)];
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let kind = if body.is_empty() {
        "empty"
    } else if looks_like_html(text) {
        "html"
    } else if text.starts_with("<xmlui") || (text.starts_with("<?xml") && text.contains("<xmlui")) {
        "xmlui"
    } else if text.starts_with("<?xml") || text.starts_with("<plist") {
        "xml"
    } else if serde_json::from_slice::<serde_json::Value>(body).is_ok() {
        "json"
    } else {
        "other"
    };
    // Observed text markers, not a diagnosis or instruction to retry.
    let marker = if text.contains("access to this apple developer service was denied") {
        "developer-service-denied"
    } else if text.contains("could not connect to icloud") {
        "icloud-connect-error"
    } else if text.contains("access denied") {
        "access-denied"
    } else {
        "unclassified"
    };
    let read = match read {
        DiagnosticRead::Complete => "complete",
        DiagnosticRead::Limited => "limited",
        DiagnosticRead::ReadError => "read-error",
        DiagnosticRead::Timeout => "timeout",
    };
    format!("stage=trusted-phone-options; status={status}; media={media}; body_kind={kind}; marker={marker}; body_read={read}; observed_bytes={}", body.len())
}

async fn rejected_auth_options_summary(mut response: Response) -> String {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut body = Vec::new();
    // Error diagnostics must not become an unbounded read or replace the
    // original HTTP rejection with a secondary body-read failure.
    let read = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = AUTH_OPTIONS_DIAGNOSTIC_LIMIT - body.len();
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if body.len() == AUTH_OPTIONS_DIAGNOSTIC_LIMIT {
                        return DiagnosticRead::Limited;
                    }
                }
                Ok(None) => return DiagnosticRead::Complete,
                Err(_) => return DiagnosticRead::ReadError,
            }
        }
    })
    .await
    .unwrap_or(DiagnosticRead::Timeout);
    auth_options_failure_summary(status, &content_type, &body, read)
}

pub(super) async fn parse_auth_options_response(
    response: Response,
) -> Result<AuthenticationExtras, Error> {
    let status = response.status().as_u16();
    debug!(target: "icloud_auth::client", "Apple authentication HTTP: stage=trusted-phone-options; status={status}");
    if !response.status().is_success() {
        let summary = rejected_auth_options_summary(response).await;
        warn!(target: "icloud_auth::client", "Apple authentication HTTP: {summary}");
        return Err(Error::FailedGetting2FAConfig);
    }
    let resp = response.bytes().await?;
    let mut new_state: AuthenticationExtras = serde_json::from_slice(&resp)?;
    info!(
        "Parsed GSA authentication extras (trusted_phone_count={}, has_new_state={})",
        new_state.trusted_phone_numbers.len(),
        new_state.new_state.is_some()
    );
    if new_state.trusted_phone_numbers.is_empty() {
        return Err(Error::HardwareKeyError);
    }
    if status == 201 {
        new_state.new_state = Some(LoginState::NeedsSMS2FAVerification(VerifyBody {
            phone_number: PhoneNumber {
                id: new_state.trusted_phone_numbers[0].id,
            },
            mode: "sms".to_string(),
            security_code: None,
        }));
    }
    Ok(new_state)
}

#[cfg(test)]
#[path = "auth_options_tests.rs"]
mod tests;
