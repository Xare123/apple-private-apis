//! Synthetic HTTP responses only. No Apple, account, or device access.
use super::{parse_response, AppleAccount, AuthResponseStage, Error};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

const SUCCESS: &[u8] = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>"#;
const REJECTED: &[u8] = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>-80045</integer></dict></dict></dict></plist>"#;

struct Server {
    release: mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

async fn response(status: u16, body: &[u8], hold_open: bool) -> (reqwest::Response, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let (release, stop) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        let length = body.len() + usize::from(hold_open);
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: text/html\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
        if hold_open {
            let _ = stop.recv_timeout(Duration::from_secs(5));
        }
    });
    let server = Server {
        release,
        handle: Some(handle),
    };
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{address}/synthetic-auth"))
        .send()
        .await
        .unwrap();
    (response, server)
}

/// Chunked HTTP/500 with NO Content-Length: one oversized first chunk, then a
/// stalled remainder. Proves the incremental cap triggers on the first chunk
/// without buffering the full body or waiting for the stall/deadline.
async fn chunked_stalled_response(status: u16, first_chunk: &[u8]) -> (reqwest::Response, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let first_chunk = first_chunk.to_vec();
    let (release, stop) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
        write!(stream, "{:X}\r\n", first_chunk.len()).unwrap();
        stream.write_all(&first_chunk).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();
        // Stall the remainder: no terminating chunk is ever sent.
        let _ = stop.recv_timeout(Duration::from_secs(5));
    });
    let server = Server {
        release,
        handle: Some(handle),
    };
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{address}/synthetic-auth"))
        .send()
        .await
        .unwrap();
    (response, server)
}

#[tokio::test]
async fn server_error_precedes_html_or_plist_parsing() {
    // HTTP 500 is the single bounded exception (structured -80045 preserved
    // elsewhere); 502/503/504 stay immediate and generic here.
    for status in [502, 503, 504] {
        for body in [
            b"<html>synthetic-user@example.test 123456</html>".as_slice(),
            SUCCESS,
            b"",
        ] {
            let (response, _server) = response(status, body, false).await;
            assert!(matches!(parse_response("srp-init", Ok(response)).await,
                Err(Error::AuthenticationServiceUnavailable(code)) if code == status));
        }
    }
}

#[tokio::test]
async fn server_error_does_not_wait_for_error_body() {
    let (response, _server) = response(503, b"", true).await;
    let result = tokio::time::timeout(
        Duration::from_millis(300),
        parse_response("srp-complete", Ok(response)),
    )
    .await;
    assert!(matches!(
        result,
        Ok(Err(Error::AuthenticationServiceUnavailable(503)))
    ));
}

#[tokio::test]
async fn rate_limit_is_not_a_success_or_bad_password() {
    let (response, _server) = response(429, SUCCESS, false).await;
    assert!(matches!(
        parse_response("srp-init", Ok(response)).await,
        Err(Error::AuthenticationRateLimited)
    ));
}

#[tokio::test]
async fn normal_plist_and_account_rejection_are_preserved() {
    for (status, body, expected) in [(200, SUCCESS, 0), (401, REJECTED, -80045)] {
        let (response, _server) = response(status, body, false).await;
        let dict = parse_response("srp-init", Ok(response)).await.unwrap();
        assert_eq!(
            dict["Status"].as_dictionary().unwrap()["ec"].as_signed_integer(),
            Some(expected)
        );
    }
}

#[tokio::test]
async fn non_service_html_keeps_the_existing_sanitized_diagnostic() {
    let (response, _server) = response(
        403,
        b"<html>synthetic-user@example.test 123456</html>",
        false,
    )
    .await;
    let Error::UnexpectedResponse(summary) =
        parse_response("srp-init", Ok(response)).await.unwrap_err()
    else {
        panic!("expected existing sanitized HTML error");
    };
    assert!(summary.contains("status=403"));
    assert!(!summary.contains("synthetic-user") && !summary.contains("123456"));
}

#[test]
fn service_error_copy_does_not_blame_password_or_claim_an_sms_was_sent() {
    let unavailable = Error::AuthenticationServiceUnavailable(503).to_string();
    assert!(unavailable.contains("HTTP 503") && unavailable.contains("try again later"));
    assert!(unavailable.contains("does not require resetting"));
    let limited = Error::AuthenticationRateLimited.to_string();
    assert!(limited.contains("HTTP 429") && limited.contains("wait before trying again"));
    for message in [unavailable, limited] {
        assert!(
            !message.contains("password") && !message.contains("SMS") && !message.contains("<html")
        );
    }
}

#[tokio::test]
async fn http500_structured_rejection_is_preserved_for_existing_stage_check() {
    // Fails before the bounded-500 correction (old code returned generic 500
    // without reading the body); passes after.
    let (response, _server) = response(500, REJECTED, false).await;
    let dict = parse_response("srp-init", Ok(response)).await.unwrap();
    assert_eq!(
        dict["Status"].as_dictionary().unwrap()["ec"].as_signed_integer(),
        Some(-80045)
    );
    type Provider = omnisette::DefaultAnisetteProvider;
    match AppleAccount::<Provider>::check_error_at_stage(AuthResponseStage::SrpInit, &dict) {
        Err(Error::AuthSrpWithMessage(code, _)) => assert_eq!(code, -80045),
        other => panic!("expected preserved -80045 rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn http500_success_or_malformed_body_stays_unavailable() {
    let truncated = &REJECTED[..REJECTED.len() / 2];
    let missing_ec: &[u8] = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Response</key><dict><key>Status</key><dict><key>em</key><string>no-ec</string></dict></dict></dict></plist>"#;
    for body in [
        SUCCESS,
        b"".as_slice(),
        b"<html>synthetic-user@example.test 123456</html>".as_slice(),
        truncated,
        b"not a plist".as_slice(),
        missing_ec,
    ] {
        let (response, _server) = response(500, body, false).await;
        let err = parse_response("srp-init", Ok(response)).await.unwrap_err();
        assert!(
            matches!(err, Error::AuthenticationServiceUnavailable(500)),
            "500 body should stay generic unavailable, got {err:?}"
        );
        assert!(
            !err.to_string().contains("synthetic-user") && !err.to_string().contains("123456"),
            "generic 500 must not echo body contents"
        );
    }
}

#[tokio::test]
async fn http500_oversized_body_stays_unavailable() {
    let oversized = vec![b'A'; 20 * 1024];
    let (response, _server) = response(500, &oversized, false).await;
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        parse_response("srp-init", Ok(response)),
    )
    .await
    .expect("oversized 500 should finish quickly, not hang");
    assert!(matches!(
        result,
        Err(Error::AuthenticationServiceUnavailable(500))
    ));
}

#[tokio::test]
async fn http500_chunked_oversized_first_chunk_rejected_without_stall_wait() {
    // No Content-Length: 20 KiB arrive as the first chunk, then the remainder
    // stalls forever. The incremental cap must reject on that first chunk
    // (well under the 1s body budget), not buffer the body or wait out the
    // stall/deadline. Old whole-body buffering would sit in the stall until
    // the outer timeout below elapses and fail this test.
    let oversized = vec![b'B'; 20 * 1024];
    let (response, _server) = chunked_stalled_response(500, &oversized).await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(300),
        parse_response("srp-init", Ok(response)),
    )
    .await
    .expect("oversized first chunk must trigger the cap without stalling");
    assert!(matches!(
        result,
        Err(Error::AuthenticationServiceUnavailable(500))
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "cap must trigger before the 1s body budget, not at/after it"
    );
}

#[tokio::test]
async fn http500_slow_body_stays_within_bound() {
    let (response, _server) = response(500, b"", true).await;
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        parse_response("srp-init", Ok(response)),
    )
    .await
    .expect("bounded 500 body wait should finish within 3s");
    assert!(matches!(
        result,
        Err(Error::AuthenticationServiceUnavailable(500))
    ));
}

#[tokio::test]
async fn rate_limit_and_other_service_errors_do_not_wait_for_body() {
    for status in [502u16, 504, 429] {
        let (response, _server) = response(status, b"", true).await;
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            parse_response("srp-complete", Ok(response)),
        )
        .await;
        match status {
            429 => assert!(
                matches!(result, Ok(Err(Error::AuthenticationRateLimited))),
                "429 should stay immediate rate-limited"
            ),
            _ => assert!(
                matches!(
                    result,
                    Ok(Err(Error::AuthenticationServiceUnavailable(code))) if code == status
                ),
                "{status} should stay immediate generic"
            ),
        }
    }
}
