//! Explicit, ignored authentication discriminators using the production path.
//! SRP-init is credential-free. The separate password/SMS check requires the
//! private sealing wrapper. Neither test registers IDS or accesses CloudKit.
use super::*;
use std::io::{self, BufRead, Read, Write};
use omnisette::remote_anisette_v3::{AnisetteClient as RemoteClient, AnisetteState};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    username: String,
    endpoint: String,
    state_plist: String,
    client_info: ProbeClientInfo,
    #[serde(default)]
    native_windows: Option<NativeWindowsInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeWindowsInput {
    executable: std::path::PathBuf,
    library: std::path::PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeClientInfo {
    ak_context_type: String,
    client_app_name: String,
    client_bundle_id: String,
    mme_client_info: String,
    mme_client_info_akd: String,
    akd_user_agent: String,
    browser_user_agent: String,
    hardware_headers: HashMap<String, String>,
    push_token: Option<String>,
    update_account_bundle_id: String,
}

impl From<ProbeClientInfo> for LoginClientInfo {
    fn from(v: ProbeClientInfo) -> Self {
        Self {
            ak_context_type: v.ak_context_type,
            client_app_name: v.client_app_name,
            client_bundle_id: v.client_bundle_id,
            mme_client_info: v.mme_client_info,
            mme_client_info_akd: v.mme_client_info_akd,
            akd_user_agent: v.akd_user_agent,
            browser_user_agent: v.browser_user_agent,
            hardware_headers: v.hardware_headers,
            push_token: v.push_token,
            update_account_bundle_id: v.update_account_bundle_id,
        }
    }
}

struct PreservedProvider {
    client: RemoteClient,
    state: AnisetteState,
}

enum ProbeProvider {
    Remote(PreservedProvider),
    Windows(NativeWindowsInput),
}

impl AnisetteProvider for ProbeProvider {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
        match self {
            Self::Remote(provider) => provider.get_anisette_headers().await,
            Self::Windows(input) => native_windows_headers(input).await,
        }
    }
}

fn parse_native_headers(bytes: &[u8]) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
    use omnisette::AnisetteError::Misc;
    if bytes.len() > 8192 { return Err(Misc); }
    let headers: HashMap<String, String> = serde_json::from_slice(bytes).map_err(|_| Misc)?;
    let keys = ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO",
        "X-Mme-Device-Id", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"];
    if headers.len() != keys.len() || keys.iter().any(|key| !headers.contains_key(*key)) {
        return Err(Misc);
    }
    for value in headers.values() {
        if value.is_empty() || value.len() > 2048 || reqwest::header::HeaderValue::from_str(value).is_err() {
            return Err(Misc);
        }
    }
    for key in ["X-Apple-I-MD", "X-Apple-I-MD-M"] {
        let value = base64::decode(&headers[key]).map_err(|_| Misc)?;
        if value.is_empty() || value.len() > 1024 { return Err(Misc); }
    }
    headers["X-Apple-I-MD-RINFO"].parse::<u64>().map_err(|_| Misc)?;
    let device_parts: Vec<_> = headers["X-Mme-Device-Id"].split('.').collect();
    if device_parts.len() != 7 || device_parts.iter().any(|v|
        v.len() != 8 || !v.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(Misc);
    }
    if headers["X-Apple-I-TimeZone"] != "UTC" || headers["X-Apple-Locale"] != "en_US" {
        return Err(Misc);
    }
    Ok(headers)
}

#[cfg(windows)]
async fn native_windows_headers(input: &NativeWindowsInput) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
    use std::{os::windows::process::CommandExt, process::{Child, Command, Stdio}};
    use omnisette::AnisetteError::Misc;
    // Test-only private helper. The controller verifies both selected file hashes.
    // No account data is passed to this process, and stderr is never forwarded.
    if !input.executable.is_absolute() || !input.executable.is_file()
        || !input.library.is_absolute() || !input.library.is_file() { return Err(Misc); }
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut child = OwnedChild(Command::new(&input.executable).arg(&input.library)
        .creation_flags(0x08000000).stdin(Stdio::piped()).stdout(Stdio::piped())
        .stderr(Stdio::null()).spawn().map_err(|_| Misc)?);
    {
        let mut stdin = child.0.stdin.take().ok_or(Misc)?;
        stdin.write_all(b"ob-existing-machine-private-pipe-v1\n").map_err(|_| Misc)?;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().map_err(|_| Misc)? {
            if !status.success() { return Err(Misc); }
            break;
        }
        if std::time::Instant::now() >= deadline { return Err(Misc); }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut bytes = Vec::new();
    child.0.stdout.take().ok_or(Misc)?.take(8193).read_to_end(&mut bytes).map_err(|_| Misc)?;
    parse_native_headers(&bytes)
}

#[cfg(not(windows))]
async fn native_windows_headers(_: &NativeWindowsInput) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
    Err(omnisette::AnisetteError::UnsupportedDevice)
}

impl AnisetteProvider for PreservedProvider {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, omnisette::AnisetteError> {
        // One request only. Never provision, reset, retry or write saved state.
        Ok(self.client.get_headers(&self.state).await?.get_headers())
    }
}

struct NumericStatusLogger;
impl log::Log for NumericStatusLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target() == "icloud_auth::client"
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) { return; }
        let text = record.args().to_string();
        if text.starts_with("Apple authentication status: stage=") || text.starts_with("Apple authentication HTTP: stage=") {
            println!("{text}");
            let _ = io::stdout().flush();
        }
    }
    fn flush(&self) {}
}
static LOGGER: NumericStatusLogger = NumericStatusLogger;

async fn run_probe(input: ProbeInput) -> Result<bool, Error> {
    let username = input.username.clone();
    let account = prepared_account(input).await?;
    let anisette = account.get_anisette().await?;
    let srp = SrpClient::<Sha256>::new(&G_2048);
    let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let (response, _) = account.request_srp_init(
        GSA_ENDPOINT, &username, srp.compute_public_ephemeral(&a), &anisette,
        &Uuid::new_v4().to_string().to_uppercase(),
    ).await?;
    // Validate only the shape. Do not display challenge/salt or calculate proof.
    srp_init_params(&response)?;
    Ok(true)
}

async fn prepared_account(input: ProbeInput) -> Result<AppleAccount<ProbeProvider>, Error> {
    let info: LoginClientInfo = input.client_info.into();
    if let Some(native) = input.native_windows {
        if !input.endpoint.is_empty() || !input.state_plist.is_empty()
            || !info.hardware_headers.is_empty() || info.push_token.is_some()
            || !info.mme_client_info_akd.starts_with("<PC> <Windows;") {
            return Err(Error::Parse);
        }
        let provider = Arc::new(Mutex::new(AnisetteClient::new(ProbeProvider::Windows(native))));
        return AppleAccount::new_with_anisette(info, provider);
    }
    let state_bytes = base64::decode(input.state_plist).map_err(|_| Error::Parse)?;
    let state: AnisetteState = plist::from_bytes(&state_bytes)?;
    if !state.is_provisioned() { return Err(Error::Parse); }
    let client = RemoteClient::new(input.endpoint, info.clone()).await?;
    let provider = Arc::new(Mutex::new(AnisetteClient::new(ProbeProvider::Remote(PreservedProvider { client, state }))));
    AppleAccount::new_with_anisette(info, provider)
}

fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::ErrorGettingAnisette(_) => "provider",
        Error::ReqwestError(_) => "transport",
        Error::UnexpectedResponse(_) => "unexpected-response",
        Error::PlistError(_) => "plist",
        Error::Parse => "parse",
        Error::AuthSrpWithMessage(_, _) => "apple-status-rejected",
        Error::AuthSrp => "auth-rejected",
        Error::FailedGetting2FAConfig => "two-factor-config-unavailable",
        Error::HardwareKeyError => "no-supported-trusted-phone",
        Error::Bad2faCode => "verification-rejected",
        _ => "other",
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual private-input check; contacts the existing provider and Apple SRP-init only"]
async fn retained_profile_srp_init_only() {
    let mut raw = Vec::new();
    io::stdin().take(65537).read_to_end(&mut raw).expect("private stdin read failed");
    assert!(raw.len() <= 65536, "private input exceeds bound");
    let input: ProbeInput = serde_json::from_slice(&raw).expect("private input schema invalid");
    assert!(!input.username.is_empty(), "account selection required");
    log::set_logger(&LOGGER).expect("isolated logger required");
    log::set_max_level(log::LevelFilter::Debug);
    let result = tokio::time::timeout(Duration::from_secs(45), run_probe(input)).await;
    let outcome = match result {
        Ok(Ok(true)) => "init-accepted-proof-not-submitted",
        Ok(Err(Error::AuthSrpWithMessage(_, _))) => "apple-init-rejected",
        Ok(Err(error)) => {
            let kind = error_kind(&error);
            println!("probe_error_kind={kind}");
            "transport-provider-or-response-error"
        },
        _ => "bounded-timeout",
    };
    println!("probe_outcome={outcome}; password_submissions=0; sms_requests=0; persistence_writes=0");
    // A server rejection is a measured outcome, not a passing login assertion.
    assert!(!matches!(outcome, "bounded-timeout" | "transport-provider-or-response-error"), "probe did not reach a classifiable Apple response");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataComparisonInput {
    context: ProbeInput,
    implementation: String,
    advertised: omnisette::AnisetteClientInfo,
}

fn comparison_metadata(implementation: &str, advertised: &omnisette::AnisetteClientInfo)
    -> Result<omnisette::AnisetteClientInfo, Error>
{
    // Exactly the current production v2.2.2 compatibility predicate. Refuse a
    // changed provider instead of silently testing a different configuration.
    if implementation != "anisette-v3-server v2.2.2"
        || advertised.client_info != "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        || advertised.user_agent != "akd/1.0 CFNetwork/808.1.4" {
        return Err(Error::Parse);
    }
    Ok(omnisette::AnisetteClientInfo {
        client_info: "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
        user_agent: advertised.user_agent.clone(),
    })
}

fn metadata_variant(original: &AnisetteData, metadata: &omnisette::AnisetteClientInfo) -> AnisetteData {
    let mut client_info = original.client_info.clone();
    client_info.use_anisette_client_info(metadata);
    AnisetteData { base_headers: original.base_headers.clone(), client_info }
}

fn init_comparison_outcome(result: &Result<(Dictionary, HeaderMap), Error>) -> (&'static str, u16) {
    match result {
        Ok((response, _)) if srp_init_params(response).is_ok() => ("init-accepted", 0),
        Ok(_) => ("invalid-challenge", 0),
        Err(Error::AuthenticationServiceUnavailable(status)) => ("service-unavailable", *status),
        Err(Error::AuthenticationRateLimited) => ("rate-limited", 429),
        Err(Error::AuthSrpWithMessage(_, _)) | Err(Error::AuthSrp) => ("apple-rejected", 0),
        Err(_) => ("transport-or-response-error", 0),
    }
}

async fn run_metadata_comparison(input: MetadataComparisonInput) -> Result<(), Error> {
    if input.context.native_windows.is_some() || input.context.username.is_empty() {
        return Err(Error::Parse);
    }
    let metadata = comparison_metadata(&input.implementation, &input.advertised)?;
    let username = input.context.username.clone();
    let original_account = prepared_account(input.context).await?;
    // One provider fetch; never provision, reset, or persist provider state.
    let original = original_account.get_anisette().await?;
    let current = metadata_variant(&original, &metadata);
    if original.get_cpd_data("comparison") != current.get_cpd_data("comparison") {
        return Err(Error::Parse);
    }
    // Separate cookie jars prevent the first server response from changing the
    // second request. Both use the production constructor, endpoint and TLS.
    let current_account = AppleAccount::new_with_anisette(
        current.client_info.clone(), original_account.anisette.clone())?;
    let mut submissions = 0;
    for (label, account, data) in [
        ("original-hardware", &original_account, &original),
        ("current-provider", &current_account, &current),
    ] {
        println!("comparison_variant={label}");
        io::stdout().flush().ok();
        let srp = SrpClient::<Sha256>::new(&G_2048);
        let secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let request_id = Uuid::new_v4().to_string().to_uppercase();
        submissions += 1;
        let result = tokio::time::timeout(Duration::from_secs(15), account.request_srp_init(
            GSA_ENDPOINT, &username, srp.compute_public_ephemeral(&secret), data, &request_id,
        )).await;
        let (outcome, status) = match &result {
            Ok(result) => init_comparison_outcome(result),
            Err(_) => ("bounded-timeout", 0),
        };
        println!("comparison_result: variant={label}; outcome={outcome}; http={status}");
        // Stop on throttling or an unclassified transport/shape failure. A
        // classifiable 5xx remains a measured result, not an automatic retry.
        if matches!(outcome, "rate-limited" | "bounded-timeout" | "transport-or-response-error" | "invalid-challenge") {
            break;
        }
    }
    println!("comparison_complete: init_requests={submissions}; provider_fetches=1; password_submissions=0; sms_requests=0; persistence_writes=0");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual private comparison; at most two SRP-init requests, no password or SMS"]
async fn retained_profile_client_metadata_comparison() {
    let mut raw = Vec::new();
    io::stdin().take(65537).read_to_end(&mut raw).expect("private stdin read failed");
    assert!(raw.len() <= 65536, "private input exceeds bound");
    let input: MetadataComparisonInput = serde_json::from_slice(&raw).expect("private schema invalid");
    log::set_logger(&LOGGER).expect("isolated logger required");
    log::set_max_level(log::LevelFilter::Debug);
    match tokio::time::timeout(Duration::from_secs(50), run_metadata_comparison(input)).await {
        Ok(Ok(())) => {},
        Ok(Err(_)) => panic!("comparison preparation failed; private details withheld"),
        Err(_) => panic!("comparison exceeded overall deadline"),
    }
}

#[test]
fn metadata_comparison_changes_only_client_description_headers() {
    let original = AnisetteData { base_headers: HashMap::from([
        ("X-Apple-I-MD".into(), "synthetic-proof".into()),
        ("X-Mme-Device-Id".into(), "synthetic-provider-id".into()),
    ]), client_info: LoginClientInfo {
        mme_client_info: "synthetic-hardware".into(), mme_client_info_akd: "synthetic-hardware-akd".into(),
        akd_user_agent: "synthetic-hardware-agent".into(),
        hardware_headers: HashMap::from([("X-Apple-I-SRL-NO".into(), "synthetic-serial".into())]),
        push_token: Some("synthetic-push".into()), ..Default::default()
    }};
    let changed = metadata_variant(&original, &omnisette::AnisetteClientInfo {
        client_info: "synthetic-provider".into(), user_agent: "synthetic-provider-agent".into(),
    });
    assert_eq!(original.base_headers, changed.base_headers);
    assert_eq!(original.get_cpd_data("same-request"), changed.get_cpd_data("same-request"));
    let left = original.get_gsservice_headers();
    let right = changed.get_gsservice_headers();
    let mut differences: Vec<_> = left.iter().filter(|(key, value)| right.get(*key) != Some(*value))
        .map(|(key, _)| key.as_str()).collect();
    differences.sort_unstable();
    assert_eq!(left.len(), right.len());
    assert_eq!(differences, ["User-Agent", "X-MMe-Client-Info"]);
}

#[test]
fn metadata_comparison_rejects_changed_provider_and_hides_error_text() {
    let mut advertised = omnisette::AnisetteClientInfo {
        client_info: "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
        user_agent: "akd/1.0 CFNetwork/808.1.4".into(),
    };
    assert!(comparison_metadata("anisette-v3-server v2.2.2", &advertised).is_ok());
    assert!(comparison_metadata("different-provider", &advertised).is_err());
    advertised.user_agent = "changed".into();
    assert!(comparison_metadata("anisette-v3-server v2.2.2", &advertised).is_err());
    assert_eq!(init_comparison_outcome(&Err(Error::AuthSrpWithMessage(-80045, "private account text".into()))), ("apple-rejected", 0));
    assert_eq!(init_comparison_outcome(&Err(Error::AuthenticationServiceUnavailable(503))), ("service-unavailable", 503));
    assert_eq!(init_comparison_outcome(&Err(Error::AuthenticationRateLimited)), ("rate-limited", 429));
}

fn srp_endpoint_from_bag(bag: &Dictionary) -> Result<&'static str, Error> {
    let endpoint = bag.get("urls").and_then(Value::as_dictionary)
        .and_then(|urls| urls.get("gsService")).and_then(Value::as_string);
    match endpoint {
        Some(GSA_ENDPOINT) => Ok(GSA_ENDPOINT),
        Some("https://gsd.apple.com/grandslam/GsService2") =>
            Ok("https://gsd.apple.com/grandslam/GsService2"),
        _ => Err(Error::UnexpectedResponse("unsupported-srp-service".into())),
    }
}

async fn run_server_selected_init(input: MetadataComparisonInput) -> Result<(), Error> {
    if input.context.native_windows.is_some() || input.context.username.is_empty() {
        return Err(Error::Parse);
    }
    let metadata = comparison_metadata(&input.implementation, &input.advertised)?;
    let username = input.context.username.clone();
    let lookup_account = prepared_account(input.context).await?;
    let original = lookup_account.get_anisette().await?;
    let current = metadata_variant(&original, &metadata);
    // Lookup carries only public client descriptors. No proof, hardware or
    // account headers. Keep its cookie jar separate from the SRP request.
    let lookup_url = format!("{GSA_ENDPOINT}/lookup");
    let mut response = lookup_account.client.get(&lookup_url)
        .header("X-MMe-Client-Info", &current.client_info.mme_client_info_akd)
        .header("User-Agent", &current.client_info.akd_user_agent)
        .header("Accept", "text/x-xml-plist")
        .send().await?.error_for_status()?;
    if response.url().as_str() != lookup_url { return Err(Error::Parse); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > 65536 - bytes.len() { return Err(Error::Parse); }
        bytes.extend_from_slice(&chunk);
    }
    let bag: Dictionary = plist::from_bytes(&bytes)?;
    let endpoint = srp_endpoint_from_bag(&bag)?;
    // An unchanged route does not justify repeating the failed request.
    if endpoint == GSA_ENDPOINT {
        return Err(Error::UnexpectedResponse("srp-route-unchanged".into()));
    }
    println!("route_probe_service=gsd; lookup_status=200");
    let account = AppleAccount::new_with_anisette(
        current.client_info.clone(), lookup_account.anisette.clone())?;
    let srp = SrpClient::<Sha256>::new(&G_2048);
    let secret: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let result = tokio::time::timeout(Duration::from_secs(15), account.request_srp_init(
        endpoint, &username, srp.compute_public_ephemeral(&secret), &current,
        &Uuid::new_v4().to_string().to_uppercase(),
    )).await;
    let (outcome, status) = match &result {
        Ok(result) => init_comparison_outcome(result),
        Err(_) => ("bounded-timeout", 0),
    };
    println!("route_probe_result: outcome={outcome}; http={status}");
    println!("route_probe_complete: init_requests=1; provider_fetches=1; password_submissions=0; sms_requests=0; persistence_writes=0");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual private SRP-init check using only the exact Apple-selected service"]
async fn retained_profile_server_selected_init() {
    let mut raw = Vec::new();
    io::stdin().take(65537).read_to_end(&mut raw).expect("private stdin read failed");
    assert!(raw.len() <= 65536, "private input exceeds bound");
    let input: MetadataComparisonInput = serde_json::from_slice(&raw).expect("private schema invalid");
    log::set_logger(&LOGGER).expect("isolated logger required");
    log::set_max_level(log::LevelFilter::Debug);
    match tokio::time::timeout(Duration::from_secs(50), run_server_selected_init(input)).await {
        Ok(Ok(())) => {},
        Ok(Err(_)) => panic!("route preparation failed; private details withheld"),
        Err(_) => panic!("route probe exceeded overall deadline"),
    }
}

#[test]
fn srp_route_accepts_only_exact_official_services() {
    for url in [GSA_ENDPOINT, "https://gsd.apple.com/grandslam/GsService2"] {
        let bag = Dictionary::from_iter([("urls", Value::Dictionary(
            Dictionary::from_iter([("gsService", Value::String(url.into()))]))) ]);
        assert_eq!(srp_endpoint_from_bag(&bag).unwrap(), url);
    }
}

#[test]
fn srp_route_rejects_missing_untrusted_and_non_srp_paths() {
    assert!(srp_endpoint_from_bag(&Dictionary::new()).is_err());
    for url in ["http://gsd.apple.com/grandslam/GsService2",
        "https://gsd.apple.com.evil.test/grandslam/GsService2",
        "https://gsd.apple.com/grandslam/GsService2?redirect=1",
        "https://gsd.apple.com/auth", "https://gsa.apple.com/grandslam/GsService2/"] {
        let bag = Dictionary::from_iter([("urls", Value::Dictionary(
            Dictionary::from_iter([("gsService", Value::String(url.into()))]))) ]);
        assert!(srp_endpoint_from_bag(&bag).is_err());
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProbeVerificationChannel {
    #[default]
    Sms,
    ManualDeviceCode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordProbeInput {
    context: ProbeInput,
    password_sha256: String,
    output_protocol: String,
    #[serde(default)]
    server_selected_sms: bool,
    #[serde(default)]
    server_selected_auth: bool,
    #[serde(default)]
    sms_bootstrap_only: bool,
    #[serde(default)]
    sms_session_replay: bool,
    #[serde(default)]
    verification_channel: ProbeVerificationChannel,
}

pub(super) fn report_session_headers(stage: &str, headers: &HeaderMap) {
    if !matches!(stage, "srp-init" | "srp-complete" | "sms-bootstrap") { return; }
    // Presence only. Do not print or persist continuation/session credentials.
    println!("probe_session_headers: stage={stage}; scnt={}; session_id={}; two_factor_app={}",
        headers.contains_key("scnt"), headers.contains_key("x-apple-id-session-id"),
        headers.contains_key("x-apple-2fa-app"));
}

fn bootstrap_headers(mut headers: HeaderMap) -> HeaderMap {
    // Apple's current validateOnDemand2FAToken web module uses this HTML
    // bootstrap before its JSON SMS operations. Test-only, same native token,
    // provider, cookie jar and Apple-selected origin; no imported web session.
    headers.insert("Accept", HeaderValue::from_static("text/html"));
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers
}

fn bootstrap_summary(status: u16, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let marker = if text.contains("access to this apple developer service was denied") {
        "developer-service-denied"
    } else if text.contains("could not connect to icloud") {
        "icloud-connect-error"
    } else { "unclassified" };
    let page = if looks_like_html(&text) { classify_html_page(&text) } else { "not-html" };
    format!("probe_bootstrap: status={status}; page={page}; marker={marker}; observed_bytes={}", body.len())
}

pub(super) fn continuation_headers(headers: &HeaderMap) -> Result<HeaderMap, Error> {
    let mut continuation = HeaderMap::new();
    for name in ["scnt", "x-apple-id-session-id", "x-apple-auth-attributes", "x-apple-2fa-app"] {
        let values = headers.get_all(name).iter().collect::<Vec<_>>();
        if values.len() > 1 {
            return Err(Error::UnexpectedResponse("ambiguous-secondary-auth-session".into()));
        }
        if let Some(value) = values.first() {
            if value.is_empty() || value.as_bytes().len() > 4096 || value.to_str().is_err() {
                return Err(Error::UnexpectedResponse("invalid-secondary-auth-session".into()));
            }
            let mut value = (*value).clone();
            value.set_sensitive(true);
            continuation.insert(name, value);
        }
    }
    Ok(continuation)
}

async fn inspect_sms_bootstrap(account: &AppleAccount<ProbeProvider>) -> Result<HeaderMap, Error> {
    let mut response = account.client.get(account.secondary_auth_endpoint("")?)
        .headers(bootstrap_headers(account.build_2fa_headers(true).await?))
        .send().await?;
    if response.url().as_str() != account.secondary_auth_endpoint("")? {
        return Err(Error::UnexpectedResponse("secondary-auth-origin-changed".into()));
    }
    report_session_headers("sms-bootstrap", response.headers());
    let continuation = continuation_headers(response.headers())?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    // Retain neither HTML nor headers. Inspection is bounded even on errors.
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(chunk) = response.chunk().await? {
            let remaining = 16384 - body.len();
            body.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
            if body.len() == 16384 { break; }
        }
        Ok::<(), reqwest::Error>(())
    }).await.map_err(|_| Error::UnexpectedResponse("bootstrap-body-timeout".into()))??;
    println!("{}", bootstrap_summary(status, &body));
    Ok(continuation)
}

fn secondary_origin_from_bag(bag: &Dictionary) -> Result<&'static str, Error> {
    let endpoint = bag.get("urls").and_then(Value::as_dictionary)
        .and_then(|urls| urls.get("secondaryAuth")).and_then(Value::as_string);
    match endpoint {
        Some("https://gsa.apple.com/auth") => Ok("https://gsa.apple.com"),
        Some("https://gsd.apple.com/auth") => Ok("https://gsd.apple.com"),
        _ => Err(Error::UnexpectedResponse("unsupported-secondary-auth-service".to_string())),
    }
}

async fn select_server_sms_route(account: &mut AppleAccount<ProbeProvider>) -> Result<(), Error> {
    // Public Apple lookup, with the same declared client as SRP, before any
    // password submission. No anisette, hardware or account headers are sent.
    let response = account.client.get(format!("{GSA_ENDPOINT}/lookup"))
        .header("X-MMe-Client-Info", &account.client_info.mme_client_info_akd)
        .header("User-Agent", &account.client_info.akd_user_agent)
        .header("Accept", "text/x-xml-plist")
        .send().await?.error_for_status()?;
    let bytes = response.bytes().await?;
    if bytes.len() > 65536 { return Err(Error::Parse); }
    let bag: Dictionary = plist::from_bytes(&bytes)?;
    let secondary = secondary_origin_from_bag(&bag)?;
    // Historical SMS-only discriminator. Explicitly not the production route:
    // it keeps SRP on GSA while varying secondary auth, as recorded in evidence.
    account.auth_routes_override = Some(AuthRoutes {
        srp: GSA_ENDPOINT,
        secondary: if secondary == "https://gsd.apple.com" { "https://gsd.apple.com/auth" } else { "https://gsa.apple.com/auth" },
        trusted_device: "https://gsa.apple.com/auth/verify/trusteddevice",
        validate_code: "https://gsa.apple.com/grandslam/GsService2/validate",
    });
    println!("probe_secondary_auth_route={}",
        if secondary == "https://gsd.apple.com" { "gsd" } else { "gsa" });
    Ok(())
}

fn coherent_auth_routes(bag: &Dictionary) -> Result<(&'static str, &'static str), Error> {
    let srp = srp_endpoint_from_bag(bag)?;
    let secondary = secondary_origin_from_bag(bag)?;
    if !srp.starts_with(&format!("{secondary}/")) {
        return Err(Error::UnexpectedResponse("inconsistent-auth-services".into()));
    }
    Ok((srp, secondary))
}

#[test]
fn server_auth_routes_require_complete_coherent_official_pair() {
    let bag_for = |srp: &str, sms: &str| Dictionary::from_iter([("urls", Value::Dictionary(
        Dictionary::from_iter([("gsService", Value::String(srp.into())),
            ("secondaryAuth", Value::String(sms.into()))]))) ]);
    for origin in ["https://gsa.apple.com", "https://gsd.apple.com"] {
        let bag = bag_for(&format!("{origin}/grandslam/GsService2"), &format!("{origin}/auth"));
        assert_eq!(coherent_auth_routes(&bag).unwrap().1, origin);
    }
    assert!(coherent_auth_routes(&bag_for(GSA_ENDPOINT, "https://gsd.apple.com/auth")).is_err());
    assert!(coherent_auth_routes(&bag_for(GSA_ENDPOINT, "https://private.invalid/auth")).is_err());
    assert!(coherent_auth_routes(&Dictionary::new()).is_err());
}

#[test]
fn secondary_route_accepts_only_exact_official_auth_services() {
    for (url, expected) in [("https://gsa.apple.com/auth", "https://gsa.apple.com"),
                            ("https://gsd.apple.com/auth", "https://gsd.apple.com")] {
        let bag = Dictionary::from_iter([("urls".to_string(), Value::Dictionary(
            Dictionary::from_iter([("secondaryAuth".to_string(), Value::String(url.into()))]))) ]);
        assert_eq!(secondary_origin_from_bag(&bag).unwrap(), expected);
    }
}

#[test]
fn secondary_route_rejects_missing_or_untrusted_paths_without_fallback() {
    assert!(secondary_origin_from_bag(&Dictionary::new()).is_err());
    for url in ["http://gsd.apple.com/auth", "https://gsd.apple.com.evil.invalid/auth",
        "https://gsa.apple.com@evil.invalid/auth", "https://gsd.apple.com/auth?token=private",
        "https://gsd.apple.com/auth/other", "https://gsd.apple.com:444/auth", ""] {
        let bag = Dictionary::from_iter([("urls".to_string(), Value::Dictionary(
            Dictionary::from_iter([("secondaryAuth".to_string(), Value::String(url.into()))]))) ]);
        assert!(secondary_origin_from_bag(&bag).is_err());
    }
}

fn read_private_line(limit: u64) -> Vec<u8> {
    let mut raw = Vec::new();
    io::stdin().lock().take(limit + 1).read_until(b'\n', &mut raw).expect("private stdin read failed");
    assert!(raw.len() as u64 <= limit && raw.last() == Some(&b'\n'), "invalid private input framing");
    raw
}

fn print_state(state: &LoginState) {
    let label = match state {
        LoginState::LoggedIn => "logged-in",
        LoginState::NeedsDevice2FA => "needs-device-2fa",
        LoginState::NeedsSMS2FA => "needs-sms-2fa",
        LoginState::Needs2FAVerification => "needs-device-verification",
        LoginState::NeedsSMS2FAVerification(_) => "needs-sms-verification",
        LoginState::NeedsExtraStep(_) => "needs-extra-step",
        LoginState::NeedsLogin => "needs-login",
    };
    println!("probe_login_state={label}");
    let _ = io::stdout().flush();
}

enum SmsChallenge {
    AlreadyRequested(VerifyBody),
    Request(u32),
    SelectPhone,
}

fn sms_challenge(extras: Result<AuthenticationExtras, Error>) -> Result<SmsChallenge, Error> {
    // Transport/routing choices must never change the user's selected channel.
    // In particular, rejected SMS setup is not permission to ask for a push code.
    let extras = extras?;
    match extras.new_state {
        Some(LoginState::NeedsSMS2FAVerification(body)) => Ok(SmsChallenge::AlreadyRequested(body)),
        Some(_) => Err(Error::UnexpectedResponse("unsupported-sms-challenge".to_string())),
        None if extras.trusted_phone_numbers.len() == 1 =>
            Ok(SmsChallenge::Request(extras.trusted_phone_numbers[0].id)),
        None if extras.trusted_phone_numbers.is_empty() => Err(Error::HardwareKeyError),
        None => Ok(SmsChallenge::SelectPhone),
    }
}

fn manual_device_code_required(state: &LoginState) -> Result<bool, Error> {
    match state {
        LoginState::NeedsDevice2FA | LoginState::Needs2FAVerification => Ok(true),
        LoginState::LoggedIn => Ok(false),
        _ => Err(Error::UnexpectedResponse("manual-device-verification-not-offered".into())),
    }
}

async fn read_verification_code() -> Result<String, Error> {
    let raw = tokio::task::spawn_blocking(|| read_private_line(256)).await.map_err(|_| Error::Parse)?;
    let code: String = serde_json::from_slice(&raw)?;
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) { return Err(Error::Parse); }
    Ok(code)
}

async fn password_sms_probe(input: PasswordProbeInput) -> Result<(), Error> {
    if input.output_protocol != "private-pipe-sealed-v1" { return Err(Error::Parse); }
    if input.sms_bootstrap_only && input.sms_session_replay { return Err(Error::Parse); }
    let manual_device_code = input.verification_channel == ProbeVerificationChannel::ManualDeviceCode;
    if manual_device_code && (!input.server_selected_auth || input.server_selected_sms
        || input.sms_bootstrap_only || input.sms_session_replay) { return Err(Error::Parse); }
    let username = input.context.username.clone();
    let password = base64::decode(input.password_sha256).map_err(|_| Error::Parse)?;
    if password.len() != 32 { return Err(Error::Parse); }
    let mut account = bounded_auth(prepared_account(input.context)).await?;
    if input.server_selected_auth {
        if input.server_selected_sms { return Err(Error::Parse); }
        // The production login now resolves and binds its own routes. Do not
        // substitute a cfg(test) implementation for the claimed live path.
    } else if input.server_selected_sms {
        bounded_auth(select_server_sms_route(&mut account)).await?;
    }
    println!("probe_password_attempt=1");
    let state = bounded_auth(account.login_email_pass(&username, &password)).await?;
    if input.server_selected_auth {
        println!("probe_server_auth_routes={}", if account.session_auth_routes()?.secondary
            == "https://gsd.apple.com/auth" { "gsd" } else { "gsa" });
    }
    print_state(&state);
    if input.sms_bootstrap_only {
        if matches!(state, LoginState::NeedsDevice2FA | LoginState::NeedsSMS2FA | LoginState::Needs2FAVerification) {
            bounded_auth(inspect_sms_bootstrap(&account)).await?;
            println!("probe_outcome=bootstrap-inspected-no-sms");
        } else {
            println!("probe_outcome=authentication-not-complete");
        }
        // Never fall through to SMS/push dispatch, code input or snapshot export.
        return Ok(());
    }
    if input.sms_session_replay && matches!(state, LoginState::NeedsDevice2FA | LoginState::NeedsSMS2FA | LoginState::Needs2FAVerification) {
        // One changed comparison based on Apple's observed header replay.
        // A 403 is not success. Only a subsequent accepted native JSON response
        // with a real trusted phone can authorize the existing SMS request.
        let session = bounded_auth(inspect_sms_bootstrap(&account)).await?;
        if session.is_empty() {
            println!("probe_outcome=bootstrap-no-continuation");
            return Ok(());
        }
        println!("probe_session_replay=true");
        account.secondary_auth_session = Some(Mutex::new(session));
    }
    let state = if manual_device_code { state } else { match state {
        LoginState::NeedsDevice2FA | LoginState::NeedsSMS2FA | LoginState::Needs2FAVerification => {
            // Use the actual trusted-phone list. Never invent or change a number.
            match sms_challenge(bounded_auth(account.get_auth_extras()).await)? {
                SmsChallenge::AlreadyRequested(body) => LoginState::NeedsSMS2FAVerification(body),
                SmsChallenge::Request(phone_id) => {
                    println!("probe_sms_request=1");
                    bounded_auth(account.send_sms_2fa_to_devices(phone_id)).await?
                }
                SmsChallenge::SelectPhone => {
                    println!("probe_outcome=trusted-phone-selection-required");
                    return Ok(());
                }
            }
        }
        state => state,
    }};
    let manual_code_required = manual_device_code && manual_device_code_required(&state)?;
    let code_was_required = manual_code_required || matches!(state, LoginState::NeedsSMS2FAVerification(_));
    let state = if manual_code_required {
        // Explicit operator-selected channel, never a fallback from SMS.
        // The user generates the code on a real trusted Apple device. Do not
        // trigger a popup, guess a code, or dispatch SMS from this branch.
        println!("probe_manual_device_code_ready=true");
        let _ = io::stdout().flush();
        bounded_auth(account.verify_2fa(read_verification_code().await?)).await?
    } else if let LoginState::NeedsSMS2FAVerification(body) = state {
        println!("probe_sms_requested=true");
        let _ = io::stdout().flush();
        // Only the private controlling wrapper can provide this framed input.
        bounded_auth(account.verify_sms_2fa(read_verification_code().await?, body)).await?
    } else { state };
    print_state(&state);
    let state = if code_was_required {
        if !matches!(state, LoginState::LoggedIn | LoginState::NeedsLogin) {
            println!("probe_outcome=authentication-not-complete");
            return Ok(());
        }
        // Match the application's post-verification gate. Accepted verification
        // is not a substitute for the fresh SRP exchange and authenticated PET.
        println!("probe_post_verification_login=1");
        let state = bounded_auth(account.login_email_pass(&username, &password)).await?;
        print_state(&state);
        state
    } else { state };
    if !probe_authentication_is_complete(&state, account.get_pet().is_some()) {
        println!("probe_outcome=authentication-not-complete");
        return Ok(());
    }
    // Output only to the private pipe consumed and sealed by the wrapper. Never
    // invoke this test with --nocapture without that wrapper. No message/CloudKit
    // operations, token fetch, identity registration or auto-retry are performed.
    let tokens: serde_json::Value = account.tokens.iter().map(|(name, token)| {
        (name.clone(), json!({"token": token.token, "expiration_unix_millis": token.expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_millis()}))
    }).collect();
    println!("private_account_snapshot={}", json!({"username": account.username, "spd": account.spd,
        "tokens": tokens, "hashed_password": base64::encode(password)}));
    println!("probe_outcome=authenticated-no-cloudkit-or-registration");
    Ok(())
}

fn probe_authentication_is_complete(state: &LoginState, has_pet: bool) -> bool {
    matches!(state, LoginState::LoggedIn) && has_pet
}

fn synthetic_sms_extras(ids: &[u32], new_state: Option<LoginState>) -> AuthenticationExtras {
    AuthenticationExtras {
        trusted_phone_numbers: ids.iter().map(|id| TrustedPhoneNumber {
            id: *id, number_with_dial_code: "synthetic".into(),
            last_two_digits: "00".into(), push_mode: "sms".into(),
        }).collect(),
        new_state, recovery_url: None, cant_use_phone_number_url: None,
        dont_have_access_url: None, recovery_web_url: None,
        repair_phone_number_url: None, repair_phone_number_web_url: None,
    }
}

#[test]
fn sms_setup_failure_never_becomes_a_trusted_device_challenge() {
    assert!(matches!(sms_challenge(Err(Error::FailedGetting2FAConfig)), Err(Error::FailedGetting2FAConfig)));
    let extras = synthetic_sms_extras(&[7], Some(LoginState::Needs2FAVerification));
    assert!(matches!(sms_challenge(Ok(extras)), Err(Error::UnexpectedResponse(_))));
}

#[test]
fn manual_device_channel_requires_explicit_selection_and_matching_challenge() {
    assert!(matches!(ProbeVerificationChannel::default(), ProbeVerificationChannel::Sms));
    assert!(matches!(serde_json::from_str::<ProbeVerificationChannel>("\"manual_device_code\"").unwrap(),
        ProbeVerificationChannel::ManualDeviceCode));
    assert!(serde_json::from_str::<ProbeVerificationChannel>("\"auto\"").is_err());
    assert!(manual_device_code_required(&LoginState::NeedsDevice2FA).unwrap());
    assert!(manual_device_code_required(&LoginState::Needs2FAVerification).unwrap());
    assert!(!manual_device_code_required(&LoginState::LoggedIn).unwrap());
    for state in [LoginState::NeedsSMS2FA, LoginState::NeedsLogin, LoginState::NeedsExtraStep("fixture".into())] {
        assert!(manual_device_code_required(&state).is_err());
    }
}

#[test]
fn sms_request_uses_the_only_server_provided_phone_id() {
    assert!(matches!(sms_challenge(Ok(synthetic_sms_extras(&[7], None))), Ok(SmsChallenge::Request(7))));
}

#[test]
fn sms_already_requested_is_not_sent_twice() {
    let state = LoginState::NeedsSMS2FAVerification(VerifyBody {
        phone_number: PhoneNumber { id: 7 }, mode: "sms".into(), security_code: None,
    });
    let plan = sms_challenge(Ok(synthetic_sms_extras(&[7], Some(state)))).unwrap();
    assert!(matches!(plan, SmsChallenge::AlreadyRequested(body) if body.phone_number.id == 7));
}

#[test]
fn sms_requires_selection_without_guessing_or_replacing_a_phone() {
    assert!(matches!(sms_challenge(Ok(synthetic_sms_extras(&[7, 9], None))), Ok(SmsChallenge::SelectPhone)));
    assert!(matches!(sms_challenge(Ok(synthetic_sms_extras(&[], None))), Err(Error::HardwareKeyError)));
}

#[test]
fn probe_success_requires_authenticated_state_and_pet() {
    assert!(probe_authentication_is_complete(&LoginState::LoggedIn, true));
    assert!(!probe_authentication_is_complete(&LoginState::LoggedIn, false));
    for state in [LoginState::NeedsLogin, LoginState::Needs2FAVerification,
        LoginState::NeedsDevice2FA, LoginState::NeedsSMS2FA] {
        assert!(!probe_authentication_is_complete(&state, true));
        assert!(!probe_authentication_is_complete(&state, false));
    }
}

#[test]
fn native_header_contract_rejects_unknown_fields_and_invalid_buffers() {
    let valid = json!({"X-Apple-I-MD":"AQID", "X-Apple-I-MD-M":"BAUG",
        "X-Apple-I-MD-RINFO":"17106176", "X-Mme-Device-Id":"12345678.12345678.12345678.12345678.12345678.12345678.12345678",
        "X-Apple-I-Client-Time":"2026-10-14T00:00:00Z", "X-Apple-I-TimeZone":"UTC", "X-Apple-Locale":"en_US"});
    assert!(parse_native_headers(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for (key, value) in [("Authorization", "private"), ("X-Apple-I-MD", "!"),
        ("X-Apple-I-MD-RINFO", "-1"), ("X-Mme-Device-Id", "not-a-windows-id"),
        ("X-Apple-I-TimeZone", "UTC\r\nInjected: yes")] {
        let mut invalid = valid.clone();
        invalid[key] = value.into();
        assert!(parse_native_headers(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    assert!(parse_native_headers(&vec![b' '; 8193]).is_err());
}

#[test]
fn bootstrap_preserves_native_identity_and_only_selects_html_representation() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Apple-Identity-Token", HeaderValue::from_static("synthetic-private"));
    headers.insert("X-MMe-Client-Info", HeaderValue::from_static("synthetic-native-provider"));
    let headers = bootstrap_headers(headers);
    assert_eq!(headers.len(), 4);
    assert_eq!(headers["Accept"], "text/html");
    assert_eq!(headers["Content-Type"], "application/json");
    assert_eq!(headers["X-Apple-Identity-Token"], "synthetic-private");
    assert_eq!(headers["X-MMe-Client-Info"], "synthetic-native-provider");
    assert!(!headers.contains_key("scnt"));
    assert!(!headers.contains_key("X-Apple-Widget-Key"));
}

#[test]
fn bootstrap_summary_excludes_account_and_session_values() {
    let summary = bootstrap_summary(403, b"<html>Access to this Apple Developer Service was denied. user@example.test secret-token 123456</html>");
    assert!(summary.contains("status=403; page=unclassified-html; marker=developer-service-denied;"));
    for private in ["user@example.test", "secret-token", "123456", "<html>"] {
        assert!(!summary.contains(private));
    }
}

#[test]
fn continuation_replays_only_server_session_headers_as_sensitive_values() {
    let mut response = HeaderMap::new();
    for name in ["scnt", "x-apple-id-session-id", "x-apple-auth-attributes", "x-apple-2fa-app"] {
        response.insert(name, HeaderValue::from_static("synthetic-continuation"));
    }
    for name in ["set-cookie", "authorization", "x-apple-identity-token", "location", "x-apple-widget-key"] {
        response.insert(name, HeaderValue::from_static("must-not-replay"));
    }
    let retained = continuation_headers(&response).unwrap();
    assert_eq!(retained.len(), 4);
    assert!(retained.values().all(HeaderValue::is_sensitive));
    assert!(!format!("{retained:?}").contains("synthetic-continuation"));
    for name in ["set-cookie", "authorization", "x-apple-identity-token", "location", "x-apple-widget-key"] {
        assert!(!retained.contains_key(name));
    }
}

#[test]
fn continuation_rejects_ambiguous_empty_and_oversized_values() {
    assert!(continuation_headers(&HeaderMap::new()).unwrap().is_empty());
    for bytes in [Vec::new(), vec![b'x'; 4097], vec![0x80]] {
        let mut headers = HeaderMap::new();
        headers.insert("x-apple-id-session-id", HeaderValue::from_bytes(&bytes).unwrap());
        assert!(continuation_headers(&headers).is_err());
    }
    let mut headers = HeaderMap::new();
    headers.append("scnt", HeaderValue::from_static("one"));
    headers.append("scnt", HeaderValue::from_static("two"));
    assert!(continuation_headers(&headers).is_err());
}

#[test]
fn continuation_updates_do_not_erase_other_server_values() {
    let mut first = HeaderMap::new();
    first.insert("scnt", HeaderValue::from_static("first"));
    first.insert("x-apple-id-session-id", HeaderValue::from_static("same-session"));
    let mut retained = continuation_headers(&first).unwrap();
    let mut second = HeaderMap::new();
    second.insert("scnt", HeaderValue::from_static("rotated"));
    retained.extend(continuation_headers(&second).unwrap());
    assert_eq!(retained["scnt"], "rotated");
    assert_eq!(retained["x-apple-id-session-id"], "same-session");
}

async fn bounded_auth<T>(operation: impl std::future::Future<Output = Result<T, Error>>) -> Result<T, Error> {
    tokio::time::timeout(Duration::from_secs(45), operation).await
        .map_err(|_| Error::UnexpectedResponse("bounded-network-timeout".to_string()))?
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual authorized password and explicit verification channel; private sealing wrapper only"]
async fn retained_profile_password_sms() {
    let raw = read_private_line(65536);
    let input: PasswordProbeInput = serde_json::from_slice(&raw).expect("invalid private schema");
    log::set_logger(&LOGGER).expect("isolated logger required");
    log::set_max_level(log::LevelFilter::Debug);
    // Interactive input has a separate deadline from each bounded network phase.
    // The private wrapper terminates the process if stdin is never completed.
    match tokio::time::timeout(Duration::from_secs(900), password_sms_probe(input)).await {
        Ok(Ok(())) => {},
        Ok(Err(error)) => println!("probe_error_kind={}", error_kind(&error)),
        Err(_) => println!("probe_error_kind=bounded-network-timeout"),
    }
    let _ = io::stdout().flush();
}
