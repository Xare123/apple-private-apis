//! Loopback only. The production lookup client and bounded reader are exercised
//! with synthetic bags; no Apple, provider, account or persistent state access.
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
};

struct Fixture {
    url: String,
    request: mpsc::Receiver<String>,
    release: mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(handle) = self.handle.take() {
            let result = handle.join();
            if !thread::panicking() { result.unwrap(); }
        }
    }
}

fn fixture(status: u16, headers: &str, body: Vec<u8>, stall: bool) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/lookup", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let (release, stop) = mpsc::channel();
    let (sent, request) = mpsc::channel();
    let headers = headers.to_owned();
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream: TcpStream = loop {
            if stop.try_recv().is_ok() || std::time::Instant::now() >= deadline {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("loopback accept: {e}"),
            }
        };
        // Accepted sockets inherit nonblocking mode on Windows.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).unwrap_or(0) != 1 {
                return;
            }
            bytes.push(byte[0]);
            assert!(bytes.len() < 8192);
        }
        sent.send(String::from_utf8(bytes).unwrap()).unwrap();
        let _ = write!(
            stream,
            "HTTP/1.1 {status} Fixture\r\n{headers}Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        if stall {
            let _ = stop.recv_timeout(Duration::from_secs(5));
        }
    });
    Fixture {
        url,
        request,
        release,
        handle: Some(handle),
    }
}

fn info() -> LoginClientInfo {
    LoginClientInfo {
        mme_client_info_akd: "synthetic-provider".into(),
        akd_user_agent: "synthetic-agent".into(),
        ..Default::default()
    }
}

async fn fetch(server: &Fixture, budget: Duration) -> Result<AuthRoutes, Error> {
    let client = lookup_client_builder().unwrap().no_proxy().build().unwrap();
    lookup_with_client(&client, &server.url, &info(), budget).await
}

#[tokio::test]
async fn public_lookup_requests_only_public_metadata_and_reads_selected_services() {
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &super::tests::bag("https://gsd.apple.com")).unwrap();
    let headers = format!(
        "Content-Type: text/x-xml-plist\r\nContent-Length: {}\r\n",
        xml.len()
    );
    let server = fixture(200, &headers, xml, false);
    let routes = fetch(&server, Duration::from_secs(2)).await.unwrap();
    assert_eq!(routes.srp, "https://gsd.apple.com/grandslam/GsService2");
    assert_eq!(
        routes.validate_code,
        "https://gsa.apple.com/grandslam/GsService2/validate"
    );
    let request = server
        .request
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .to_ascii_lowercase();
    assert!(request.starts_with("get /lookup http/1.1\r\n"));
    assert!(request.contains("x-mme-client-info: synthetic-provider\r\n"));
    assert!(request.contains("user-agent: synthetic-agent\r\n"));
    for private in [
        "cookie:",
        "authorization:",
        "x-apple-identity-token:",
        "x-apple-i-md:",
    ] {
        assert!(!request.contains(private));
    }
}

#[tokio::test]
async fn redirects_are_not_followed_even_to_a_loopback_target() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let server = fixture(
        302,
        &format!(
            "Location: http://{}/must-not-receive\r\nContent-Length: 0\r\n",
            target.local_addr().unwrap()
        ),
        vec![],
        false,
    );
    assert!(matches!(fetch(&server, Duration::from_secs(1)).await,
        Err(Error::UnexpectedResponse(reason)) if reason == "auth-service-lookup-rejected"));
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn lookup_rate_limits_and_service_failures_do_not_read_stalled_bodies() {
    for status in [429, 500, 503] {
        let server = fixture(status, "Content-Length: 10\r\n", vec![], true);
        let result = tokio::time::timeout(
            Duration::from_millis(400),
            fetch(&server, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert!(match result {
            Err(Error::AuthenticationRateLimited) => status == 429,
            Err(Error::AuthenticationServiceUnavailable(code)) => code == status,
            _ => false,
        });
    }
}

#[tokio::test]
async fn declared_and_chunked_size_limits_precede_stalled_remainders() {
    let oversized = MAX_BAG_BYTES + 1;
    let chunk = format!("{oversized:X}\r\n{}\r\n", "x".repeat(oversized)).into_bytes();
    for (headers, body) in [
        (format!("Content-Length: {oversized}\r\n"), vec![]),
        ("Transfer-Encoding: chunked\r\n".to_string(), chunk),
    ] {
        let server = fixture(200, &headers, body, true);
        let result = tokio::time::timeout(
            Duration::from_millis(400),
            fetch(&server, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert!(
            matches!(result, Err(Error::UnexpectedResponse(reason)) if reason == "auth-service-lookup-too-large")
        );
    }
}

#[tokio::test]
async fn stalled_and_malformed_bags_fail_without_fallback_or_body_disclosure() {
    let stalled = fixture(200, "Content-Length: 10\r\n", vec![], true);
    assert!(matches!(fetch(&stalled, Duration::from_millis(100)).await,
        Err(Error::UnexpectedResponse(reason)) if reason == "auth-service-lookup-timeout"));
    let body = b"<html>synthetic-private-marker</html>".to_vec();
    let malformed = fixture(
        200,
        &format!("Content-Length: {}\r\n", body.len()),
        body,
        false,
    );
    let error = fetch(&malformed, Duration::from_secs(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("malformed-auth-service-lookup"));
    assert!(!error.contains("synthetic-private-marker"));
}
