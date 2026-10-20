//! Complete synthetic SRP and subsequent request-routing checks using the real
//! AppleAccount methods. The only server is loopback and all identities are fake.
//! The cfg(test) route fixture does not alter production HTTPS/lookup rules.
use super::*;
use cbc::cipher::BlockEncryptMut;
use omnisette::{AnisetteClientInfo, AnisetteError};
use srp::server::{SrpServer, SrpServerVerifier};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex as SyncMutex,
    },
    thread,
};

const USER: &str = "route-fixture@example.invalid";
const PASSWORD: &[u8] = b"synthetic-routing-fixture-not-a-real-password";

struct Provider {
    info: AnisetteClientInfo,
    calls: Arc<AtomicUsize>,
}

impl AnisetteProvider for Provider {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HashMap::from([(
            "X-Apple-I-MD".into(),
            "synthetic-proof".into(),
        )]))
    }
    fn auth_client_info(&self) -> Option<&AnisetteClientInfo> {
        Some(&self.info)
    }
}

fn account() -> AppleAccount<Provider> {
    let provider = Provider {
        info: AnisetteClientInfo {
            client_info: "effective-provider".into(),
            user_agent: "effective-agent".into(),
        },
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let original = LoginClientInfo {
        mme_client_info_akd: "activation-hardware".into(),
        mme_client_info: "activation-hardware".into(),
        akd_user_agent: "activation-agent".into(),
        browser_user_agent: "synthetic-browser".into(),
        ..Default::default()
    };
    let mut account = AppleAccount::new_with_anisette(
        original,
        Arc::new(Mutex::new(AnisetteClient::new(provider))),
    )
    .unwrap();
    account.client = ClientBuilder::new()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    account
}

#[derive(Clone)]
struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Request {
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
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        bytes.push(byte[0]);
        assert!(bytes.len() < 16384);
    }
    let head = String::from_utf8(bytes).unwrap();
    let mut lines = head.lines();
    let mut start = lines.next().unwrap().split_whitespace();
    let method = start.next().unwrap().to_string();
    let path = start.next().unwrap().to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers
        .get("content-length")
        .map(|n| n.parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length < 65536);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Request {
        method,
        path,
        headers,
        body,
    }
}

struct Server {
    routes: AuthRoutes,
    requests: Arc<SyncMutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let result = handle.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn plist_bytes(value: &Dictionary) -> Vec<u8> {
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, value).unwrap();
    bytes
}

fn status(code: i64, hsc: i64) -> Value {
    Value::Dictionary(Dictionary::from_iter([
        ("ec", Value::Integer(code.into())),
        ("hsc", Value::Integer(hsc.into())),
    ]))
}

fn server(bad_proof: bool) -> Server {
    server_with_verification(bad_proof, None)
}

fn server_with_verification(bad_proof: bool, verification: Option<(u16, i64, bool)>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    // Test-process-only static route fixture; no account data is retained.
    let url = |path: &str| -> &'static str {
        Box::leak(format!("http://{address}{path}").into_boxed_str())
    };
    let routes = AuthRoutes {
        srp: url("/selected-srp"),
        secondary: url("/selected-secondary"),
        trusted_device: url("/selected-trusted"),
        validate_code: url("/independent-validate"),
    };
    let requests = Arc::new(SyncMutex::new(Vec::new()));
    let recorded = requests.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = thread::spawn(move || {
        let salt = b"synthetic-salt";
        let mut derived_password = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(&Sha256::digest(PASSWORD), salt, 1, &mut derived_password);
        let verifier =
            SrpClient::<Sha256>::new(&G_2048).compute_verifier(b"", &derived_password, salt);
        let srp = SrpServer::<Sha256>::new(&G_2048);
        let b = [0x45; 32];
        let mut session: Option<SrpServerVerifier<Sha256>> = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !stop_thread.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(e) => panic!("loopback accept: {e}"),
            };
            let request = read_request(&mut stream);
            recorded.lock().unwrap().push(request.clone());
            let (http_status, body) = if request.path == "/selected-srp" {
                assert_eq!(request.method, "POST");
                assert_eq!(request.headers["x-mme-client-info"], "effective-provider");
                assert_eq!(request.headers["user-agent"], "effective-agent");
                let packet: Dictionary = plist::from_bytes(&request.body).unwrap();
                let input = packet["Request"].as_dictionary().unwrap();
                assert_eq!(input["u"].as_string().unwrap(), USER);
                let response = if input["o"].as_string() == Some("init") {
                    assert!(session.is_none());
                    session = Some(
                        srp.process_reply(
                            &b,
                            &verifier,
                            input["A2k"].as_data().unwrap(),
                            USER.as_bytes(),
                            salt,
                        )
                        .unwrap(),
                    );
                    Dictionary::from_iter([
                        ("Status", status(0, 200)),
                        ("s", Value::Data(salt.to_vec())),
                        (
                            "B",
                            Value::Data(srp.compute_public_ephemeral(&b, &verifier)),
                        ),
                        ("i", Value::Integer(1.into())),
                        ("c", Value::String("fixture-challenge".into())),
                        ("sp", Value::String("s2k".into())),
                    ])
                } else {
                    assert_eq!(input["o"].as_string(), Some("complete"));
                    let session = session.as_ref().unwrap();
                    session
                        .verify_client(input["M1"].as_data().unwrap())
                        .unwrap();
                    let secret = Dictionary::from_iter([
                        ("acname", Value::String(USER.into())),
                        ("adsid", Value::String("synthetic-account".into())),
                        (
                            "GsIdmsToken",
                            Value::String("synthetic-identity-token".into()),
                        ),
                    ]);
                    let derive = |name: &[u8]| {
                        Hmac::<Sha256>::new_from_slice(session.key())
                            .unwrap()
                            .chain_update(name)
                            .finalize()
                            .into_bytes()
                    };
                    let key = derive(b"extra data key:");
                    let iv = derive(b"extra data iv:");
                    let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv[..16])
                        .unwrap()
                        .encrypt_padded_vec_mut::<Pkcs7>(&plist_bytes(&secret));
                    let mut proof = session.proof().to_vec();
                    if bad_proof {
                        proof[0] ^= 1;
                    }
                    Dictionary::from_iter([
                        ("Status", status(0, 409)),
                        ("M2", Value::Data(proof)),
                        ("spd", Value::Data(encrypted)),
                    ])
                };
                (
                    200,
                    plist_bytes(&Dictionary::from_iter([(
                        "Response",
                        Value::Dictionary(response),
                    )])),
                )
            } else {
                assert_eq!(
                    request.headers["x-apple-identity-token"],
                    base64::encode("synthetic-account:synthetic-identity-token")
                );
                match request.path.as_str() {
                    "/selected-secondary" => (403, vec![]),
                    "/selected-secondary/verify/phone" | "/selected-trusted" => (200, vec![]),
                    "/selected-secondary/verify/phone/securitycode" => (401, vec![]),
                    "/independent-validate" if verification.is_some() => {
                        let (status, code, _) = verification.unwrap();
                        (status, plist_bytes(&Dictionary::from_iter([("ec", Value::Integer(code.into()))])))
                    },
                    "/independent-validate" => (
                        200,
                        plist_bytes(&Dictionary::from_iter([(
                            "ec",
                            Value::Integer((-21669).into()),
                        )])),
                    ),
                    _ => panic!("unexpected synthetic route"),
                }
            };
            let token_header = if request.path == "/independent-validate"
                && verification.is_some_and(|(_, _, include_pet)| include_pet) {
                format!("X-Apple-PE-Token: {}\r\n", base64::encode("synthetic-account:fresh-verified-pet:300"))
            } else { String::new() };
            write!(stream, "HTTP/1.1 {http_status} Fixture\r\nContent-Type: text/x-xml-plist\r\nContent-Length: {}\r\n{token_header}Connection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    Server {
        routes,
        requests,
        stop,
        handle: Some(handle),
    }
}

#[tokio::test]
async fn trusted_device_http_errors_never_accept_success_shaped_tokens() {
    for status in [401, 429, 503] {
        let server = server_with_verification(false, Some((status, 0, true)));
        let mut account = account();
        account.auth_routes_override = Some(server.routes);
        account.login_email_pass(USER, &Sha256::digest(PASSWORD)).await.unwrap();
        account.tokens.insert("com.apple.gs.idms.pet".into(), FetchedToken {
            token: "pre-verification-token".into(), expiration: SystemTime::now() + Duration::from_secs(300),
        });
        assert!(account.verify_2fa("123456".into()).await.is_err());
        assert_eq!(account.get_pet().as_deref(), Some("pre-verification-token"));
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn trusted_device_rejection_never_accepts_a_token_header() {
    let server = server_with_verification(false, Some((200, -21669, true)));
    let mut account = account();
    account.auth_routes_override = Some(server.routes);
    account.login_email_pass(USER, &Sha256::digest(PASSWORD)).await.unwrap();
    assert!(account.verify_2fa("123456".into()).await.is_err());
    assert_ne!(account.get_pet().as_deref(), Some("fresh-verified-pet"));
}

#[tokio::test]
async fn trusted_device_success_requires_this_response_to_supply_the_pet() {
    for include_pet in [false, true] {
        let server = server_with_verification(false, Some((200, 0, include_pet)));
        let mut account = account();
        account.auth_routes_override = Some(server.routes);
        account.login_email_pass(USER, &Sha256::digest(PASSWORD)).await.unwrap();
        account.tokens.insert("com.apple.gs.idms.pet".into(), FetchedToken {
            token: "pre-verification-token".into(), expiration: SystemTime::now() + Duration::from_secs(300),
        });
        let state = account.verify_2fa("123456".into()).await.unwrap();
        if include_pet {
            assert!(matches!(state, LoginState::LoggedIn));
            assert_eq!(account.get_pet().as_deref(), Some("fresh-verified-pet"));
            assert!(account.pet_remaining_lifetime().unwrap() > Duration::from_secs(290));
        } else {
            assert!(matches!(state, LoginState::NeedsLogin));
            assert!(account.get_pet().is_none());
        }
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn verified_srp_binds_all_later_requests_and_preserves_independent_validation() {
    let server = server(false);
    let mut account = account();
    account.auth_routes_override = Some(server.routes);
    assert!(matches!(
        account
            .login_email_pass(USER, &Sha256::digest(PASSWORD))
            .await
            .unwrap(),
        LoginState::Needs2FAVerification
    ));
    assert_eq!(account.session_auth_routes().unwrap(), server.routes);
    // Effective auth metadata is bound without rewriting activation hardware.
    assert_eq!(
        account.client_info.mme_client_info_akd,
        "activation-hardware"
    );
    assert!(account
        .auth_routes
        .as_ref()
        .unwrap()
        .matches(&account.get_anisette().await.unwrap().client_info));
    assert!(account.get_auth_extras().await.is_err());
    let sms = account.send_sms_2fa_to_devices(7).await.unwrap();
    let LoginState::NeedsSMS2FAVerification(body) = sms else {
        panic!("SMS request not accepted");
    };
    assert!(account.verify_sms_2fa("123456".into(), body).await.is_err());
    assert!(matches!(
        account.send_2fa_to_devices().await.unwrap(),
        LoginState::Needs2FAVerification
    ));
    assert!(account.verify_2fa("123456".into()).await.is_err());
    let observed: Vec<_> = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| (r.method.clone(), r.path.clone()))
        .collect();
    assert_eq!(
        observed,
        [
            ("POST", "/selected-srp"),
            ("POST", "/selected-srp"),
            ("GET", "/selected-secondary"),
            ("PUT", "/selected-secondary/verify/phone"),
            ("POST", "/selected-secondary/verify/phone/securitycode"),
            ("GET", "/selected-trusted"),
            ("GET", "/independent-validate"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string()))
    );
    let saved_spd = account.spd.clone();
    account.anisette.lock().await.provider.info.user_agent = "changed-provider".into();
    assert!(matches!(account.send_sms_2fa_to_devices(7).await,
        Err(Error::UnexpectedResponse(reason)) if reason == "authentication-client-changed"));
    assert_eq!(server.requests.lock().unwrap().len(), 7);
    assert_eq!(account.spd, saved_spd);
    assert_eq!(account.session_auth_routes().unwrap(), server.routes);
}

#[tokio::test]
async fn rejected_server_proof_never_binds_or_dispatches_secondary_authentication() {
    let server = server(true);
    let mut account = account();
    account.auth_routes_override = Some(server.routes);
    assert!(matches!(
        account
            .login_email_pass(USER, &Sha256::digest(PASSWORD))
            .await,
        Err(Error::SrpFailure("verify-server"))
    ));
    assert!(account.spd.is_none());
    assert!(account.auth_routes.is_none());
    assert!(matches!(
        account.get_auth_extras().await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_relogin_cannot_reuse_previous_verification_binding() {
    let previous = server(false);
    let mut account = account();
    account.auth_routes_override = Some(previous.routes);
    account
        .login_email_pass(USER, &Sha256::digest(PASSWORD))
        .await
        .unwrap();
    let saved_spd = account.spd.clone();
    let rejected = server(true);
    account.auth_routes_override = Some(rejected.routes);
    assert!(matches!(
        account
            .login_email_pass(USER, &Sha256::digest(PASSWORD))
            .await,
        Err(Error::SrpFailure("verify-server"))
    ));
    assert!(
        account.auth_routes.is_none(),
        "failed retry retained an old verification session"
    );
    let calls = account
        .anisette
        .lock()
        .await
        .provider
        .calls
        .load(Ordering::SeqCst);
    assert!(matches!(
        account.get_auth_extras().await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert!(matches!(
        account.send_sms_2fa_to_devices(7).await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert_eq!(
        account
            .anisette
            .lock()
            .await
            .provider
            .calls
            .load(Ordering::SeqCst),
        calls
    );
    assert_eq!(
        account.spd, saved_spd,
        "failed retry must not erase retained account data"
    );
    assert_eq!(previous.requests.lock().unwrap().len(), 2);
    assert_eq!(rejected.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn cancelled_relogin_cannot_reuse_previous_verification_binding() {
    let previous = server(false);
    let mut account = account();
    account.auth_routes_override = Some(previous.routes);
    account
        .login_email_pass(USER, &Sha256::digest(PASSWORD))
        .await
        .unwrap();
    let saved_spd = account.spd.clone();
    // Hold the real provider mutex so the retry is cancelled at its first
    // asynchronous boundary, independently of the proof cache's lifetime.
    let shared_provider = account.anisette.clone();
    let provider_guard = shared_provider.lock().await;
    assert!(tokio::time::timeout(
        Duration::from_millis(25),
        account.login_email_pass(USER, &Sha256::digest(PASSWORD)),
    )
    .await
    .is_err());
    assert!(
        account.auth_routes.is_none(),
        "cancelled retry retained an old verification session"
    );
    drop(provider_guard);
    let calls = account
        .anisette
        .lock()
        .await
        .provider
        .calls
        .load(Ordering::SeqCst);
    assert!(matches!(
        account.send_2fa_to_devices().await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert!(matches!(
        account.verify_2fa("123456".into()).await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert_eq!(
        account
            .anisette
            .lock()
            .await
            .provider
            .calls
            .load(Ordering::SeqCst),
        calls
    );
    assert_eq!(
        account.spd, saved_spd,
        "cancelled retry must not erase retained account data"
    );
    assert_eq!(previous.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn unbound_restored_state_does_not_fetch_proof_or_guess_verification_route() {
    let mut account = account();
    account.spd = Some(Dictionary::from_iter([
        ("adsid", Value::String("synthetic-account".into())),
        ("GsIdmsToken", Value::String("synthetic-token".into())),
    ]));
    let saved_spd = account.spd.clone();
    assert!(matches!(
        account.get_auth_extras().await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert!(matches!(
        account.send_sms_2fa_to_devices(7).await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert!(matches!(
        account.send_2fa_to_devices().await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert!(matches!(
        account.verify_2fa("123456".into()).await,
        Err(Error::TwoFactorSessionMissing)
    ));
    assert_eq!(account.spd, saved_spd);
    assert_eq!(
        account
            .anisette
            .lock()
            .await
            .provider
            .calls
            .load(Ordering::SeqCst),
        0
    );
}
