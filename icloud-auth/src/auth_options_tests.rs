use super::{
    auth_options_failure_summary, parse_auth_options_response, rejected_auth_options_summary,
    DiagnosticRead, Error, LoginState, AUTH_OPTIONS_DIAGNOSTIC_LIMIT,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

const PHONES: &str = r#"{"trustedPhoneNumbers":[{"numberWithDialCode":"+1 *** **00","lastTwoDigits":"00","pushMode":"sms","id":7}]}"#;

// One synthetic loopback request, no accounts or external endpoints.
async fn response(
    status: u16,
    body: &[u8],
    hold_open: bool,
) -> (reqwest::Response, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
            assert!(request.len() < 8192);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(request.starts_with(b"GET /auth HTTP/1.1\r\n"));
        let length = body.len() + usize::from(hold_open);
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
        if hold_open {
            thread::sleep(Duration::from_millis(1300));
        }
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{address}/auth"))
        .send()
        .await
        .unwrap();
    (response, server)
}

#[test]
fn options_summary_never_emits_private_body_or_header_values() {
    let body = br#"<html><title>user@example.test 123456</title><body>Access to this Apple Developer Service was denied. token=synthetic-private-value</body></html>"#;
    let summary = auth_options_failure_summary(
        403,
        "text/html; token=synthetic-header",
        body,
        DiagnosticRead::Complete,
    );
    assert!(summary.contains("status=403; media=html; body_kind=html; marker=developer-service-denied; body_read=complete;"));
    for private in [
        "user@example.test",
        "123456",
        "synthetic-private-value",
        "synthetic-header",
        "<html>",
    ] {
        assert!(!summary.contains(private));
    }
    let summary = auth_options_failure_summary(
        403,
        "synthetic-private-header",
        br#"<?xml version="1.0"?><xmlui><alert message="Could not connect to iCloud"/></xmlui>"#,
        DiagnosticRead::ReadError,
    );
    assert!(summary.contains(
        "media=other; body_kind=xmlui; marker=icloud-connect-error; body_read=read-error;"
    ));
    assert!(!summary.contains("synthetic-private-header"));
}

#[test]
fn options_summary_classifies_json_empty_and_oversize_without_logging_them() {
    let json = auth_options_failure_summary(
        429,
        "application/json",
        br#"{"serviceErrors":[{"message":"user@example.test"}]}"#,
        DiagnosticRead::Complete,
    );
    assert!(json.contains("media=json; body_kind=json; marker=unclassified;"));
    assert!(!json.contains("user@example.test"));
    let empty = auth_options_failure_summary(503, "", b"", DiagnosticRead::Timeout);
    assert!(empty.contains(
        "media=absent; body_kind=empty; marker=unclassified; body_read=timeout; observed_bytes=0"
    ));
    let huge = auth_options_failure_summary(
        403,
        "text/plain",
        &vec![b'x'; AUTH_OPTIONS_DIAGNOSTIC_LIMIT + 50],
        DiagnosticRead::Limited,
    );
    assert!(huge.ends_with("observed_bytes=16384"));
}

#[tokio::test]
async fn options_http_failures_cannot_become_accepted_phone_lists() {
    for status in [403, 429, 503] {
        let (response, server) = response(status, PHONES.as_bytes(), false).await;
        assert!(matches!(
            parse_auth_options_response(response).await,
            Err(Error::FailedGetting2FAConfig)
        ));
        server.join().unwrap();
    }
    let message = Error::FailedGetting2FAConfig.to_string();
    assert!(message.contains("could not request an SMS"));
    assert!(!message.contains("trusted-device"));
}

#[tokio::test]
async fn options_success_preserves_phone_selection_and_already_sent_sms() {
    for status in [200, 201] {
        let (response, server) = response(status, PHONES.as_bytes(), false).await;
        let options = parse_auth_options_response(response).await.unwrap();
        assert_eq!(options.trusted_phone_numbers[0].id, 7);
        if status == 201 {
            let Some(LoginState::NeedsSMS2FAVerification(body)) = options.new_state else {
                panic!("expected already sent SMS");
            };
            assert_eq!(body.phone_number.id, 7);
            assert_eq!(body.mode, "sms");
        } else {
            assert!(options.new_state.is_none());
        }
        server.join().unwrap();
    }
}

#[tokio::test]
async fn options_diagnostic_body_is_size_limited() {
    let (response, server) =
        response(403, &vec![b'x'; AUTH_OPTIONS_DIAGNOSTIC_LIMIT + 1], false).await;
    let summary = rejected_auth_options_summary(response).await;
    assert!(summary.contains("body_read=limited; observed_bytes=16384"));
    server.join().unwrap();
}

#[tokio::test]
async fn options_stalled_error_body_times_out_without_changing_failure() {
    let (response, server) = response(403, b"", true).await;
    let summary = rejected_auth_options_summary(response).await;
    assert!(summary.contains("status=403;"));
    assert!(summary.contains("body_read=timeout; observed_bytes=0"));
    server.join().unwrap();
}
