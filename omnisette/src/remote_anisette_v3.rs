// Implementing the SideStore Anisette v3 protocol

use std::{
    collections::HashMap,
    fs,
    io::Cursor,
    path::PathBuf,
    time::{Duration, Instant},
};

use base64::engine::general_purpose;
use base64::Engine;
use chrono::{DateTime, SubsecRound, Utc};
use futures_util::{stream::StreamExt, SinkExt};
use log::{debug, warn};
use plist::{Data, Dictionary};
use rand::Rng;
use reqwest::{redirect::Policy, Certificate, Client, ClientBuilder, RequestBuilder, Url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

use crate::{AnisetteError, AnisetteProvider, LoginClientInfo};

const APPLE_ROOT: &[u8] = include_bytes!("../../icloud-auth/src/apple_root.der");
const MAX_PROVISION_ATTEMPTS: usize = 3;
const PROVISION_RETRY_DELAY: Duration = Duration::from_millis(750);
const MAX_GET_HEADERS_ATTEMPTS: usize = 3;
const GET_HEADERS_RETRY_DELAY: Duration = Duration::from_millis(500);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const WS_READ_TIMEOUT: Duration = Duration::from_secs(10);
const PROVISION_OVERALL_TIMEOUT: Duration = Duration::from_secs(45);
const ALLOWED_ENDPOINT_HOSTS: [&str; 2] = ["ani.sidestore.io", "ani.sidestore.app"];

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    Ok(s.try_into().unwrap())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(
        serialize_with = "bin_serialize",
        deserialize_with = "bin_deserialize_16"
    )]
    keychain_identifier: [u8; 16],
    #[serde(
        serialize_with = "bin_serialize_opt",
        deserialize_with = "bin_deserialize_opt"
    )]
    adi_pb: Option<Vec<u8>>,
    #[serde(default)]
    endpoint: Option<String>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::thread_rng().gen::<[u8; 16]>(),
            adi_pb: None,
            endpoint: None,
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    fn is_provisioned_for(&self, endpoint: &str) -> bool {
        self.is_provisioned() && self.endpoint.as_deref() == Some(endpoint)
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct AnisetteClient {
    login_info: LoginClientInfo,
    url: String,
    apple_http_client: Client,
    relay_http_client: Client,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "result")]
enum ProvisionInput {
    GiveIdentifier,
    GiveStartProvisioningData,
    GiveEndProvisioningData {
        cpim: String,
    },
    ProvisioningSuccess {
        adi_pb: String,
    },
    Wait,
    CurrentlyStartingProvisioning,
    CurrentlyEndingProvisioning,
    TextOnly,
    WebsocketError {
        #[serde(rename = "message")]
        _message: String,
    },
    ClosingPerRequest,
    Timeout,
    InvalidIdentifier {
        #[serde(rename = "message")]
        _message: String,
    },
    StartProvisioningError {
        #[serde(rename = "message")]
        _message: String,
    },
    EndProvisioningError {
        #[serde(rename = "message")]
        _message: String,
    },
}

impl ProvisionInput {
    fn server_error(&self) -> Option<(bool, String)> {
        match self {
            ProvisionInput::TextOnly => {
                Some((false, "server requires text WebSocket frames".into()))
            }
            ProvisionInput::WebsocketError { .. } => Some((true, "server WebSocket error".into())),
            ProvisionInput::ClosingPerRequest => Some((
                false,
                "server closed the provisioning session per request".into(),
            )),
            ProvisionInput::Timeout => {
                Some((true, "server timed out the provisioning session".into()))
            }
            ProvisionInput::InvalidIdentifier { .. } => {
                Some((false, "invalid provisioning identifier".into()))
            }
            ProvisionInput::StartProvisioningError { .. } => {
                Some((true, "server start provisioning error".into()))
            }
            ProvisionInput::EndProvisioningError { .. } => {
                Some((true, "server end provisioning error".into()))
            }
            _ => None,
        }
    }
}

enum ProvisionAttemptError {
    Fatal(AnisetteError),
    Retryable(AnisetteError),
}

impl From<AnisetteError> for ProvisionAttemptError {
    fn from(error: AnisetteError) -> Self {
        Self::Fatal(error)
    }
}

impl From<plist::Error> for ProvisionAttemptError {
    fn from(error: plist::Error) -> Self {
        Self::Fatal(AnisetteError::PlistError(error))
    }
}

impl From<reqwest::Error> for ProvisionAttemptError {
    fn from(error: reqwest::Error) -> Self {
        Self::Retryable(AnisetteError::ReqwestError(error))
    }
}

impl From<serde_json::Error> for ProvisionAttemptError {
    fn from(error: serde_json::Error) -> Self {
        Self::Fatal(AnisetteError::SerdeError(error))
    }
}

impl From<tokio_tungstenite::tungstenite::error::Error> for ProvisionAttemptError {
    fn from(error: tokio_tungstenite::tungstenite::error::Error) -> Self {
        Self::Retryable(AnisetteError::WsError(error))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String,
}

impl AnisetteData {
    pub fn get_headers(&self) -> HashMap<String, String> {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        HashMap::from_iter(
            [
                (
                    "X-Apple-I-Client-Time".to_string(),
                    dt.format("%+").to_string().replace("+00:00", "Z"),
                ),
                ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
                ("X-Apple-Locale".to_string(), "en_US".to_string()),
                ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
                ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
                (
                    "X-Mme-Device-Id".to_string(),
                    self.device_unique_identifier.clone(),
                ),
                ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
                ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
                (
                    "X-Mme-Client-Info".to_string(),
                    self.device_description.clone(),
                ),
            ]
            .into_iter(),
        )
    }
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_READ_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30))
        // .proxy(Proxy::https("https://localhost:8080").unwrap())
        // .danger_accept_invalid_certs(true)
        .build()?)
}

fn make_relay_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_READ_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30))
        // Never replay the identifier or ADI body to a redirect target. The
        // configured relay host is already normalized and allowlisted.
        .redirect(Policy::none())
        .build()?)
}

fn normalize_endpoint(raw: &str) -> Result<String, AnisetteError> {
    let parsed = Url::parse(raw)
        .map_err(|_| AnisetteError::InvalidArgument("invalid Anisette endpoint".into()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AnisetteError::InvalidArgument("Anisette endpoint has no host".into()))?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port().is_some()
        || (parsed.path() != "" && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !ALLOWED_ENDPOINT_HOSTS.contains(&host)
    {
        return Err(AnisetteError::InvalidArgument(
            "Anisette endpoint is not an allowed HTTPS host".into(),
        ));
    }
    Ok(format!("https://{host}"))
}

fn error_kind(error: &AnisetteError) -> &'static str {
    match error {
        AnisetteError::UnsupportedDevice => "unsupported_device",
        AnisetteError::InvalidArgument(_) => "invalid_argument",
        AnisetteError::AnisetteNotProvisioned => "not_provisioned",
        AnisetteError::PlistError(_) => "plist_error",
        AnisetteError::ReqwestError(_) => "http_error",
        AnisetteError::WsError(_) => "websocket_error",
        AnisetteError::SerdeError(_) => "json_error",
        AnisetteError::ProvisioningServerError(_) => "server_error",
        AnisetteError::ProvisioningSocketClosed => "socket_closed",
        AnisetteError::IOError(_) => "io_error",
        AnisetteError::InvalidLibraryFormat => "invalid_library",
        AnisetteError::Misc => "misc_error",
        AnisetteError::MissingLibraries => "missing_libraries",
        #[cfg(feature = "remote-clearadi")]
        AnisetteError::ClearADIError(_) => "clearadi_error",
        AnisetteError::Anyhow(_) => "internal_error",
    }
}

fn map_get_headers_error(message: &str) -> AnisetteError {
    if message.contains("-45061") {
        AnisetteError::AnisetteNotProvisioned
    } else {
        AnisetteError::ProvisioningServerError("get_headers server error".into())
    }
}

fn retryable_get_headers_connect_error(is_connect: bool) -> bool {
    is_connect
}

fn retryable_get_headers_error(error: &AnisetteError) -> bool {
    // Only connection-establishment failures are proven to precede submission
    // of the identifier and ADI body. Timeouts, response status, decode errors,
    // and parsed server errors may occur after submission and must not replay.
    matches!(
        error,
        AnisetteError::ReqwestError(error)
            if retryable_get_headers_connect_error(error.is_connect())
    )
}

#[derive(Debug, PartialEq, Eq)]
enum StateBindingAction {
    Unchanged,
    AdoptedLegacy,
    InvalidatedExplicitMismatch,
}

fn reconcile_state_endpoint(state: &mut AnisetteState, endpoint: &str) -> StateBindingAction {
    if !state.is_provisioned() {
        return StateBindingAction::Unchanged;
    }
    match state.endpoint.as_deref() {
        None => {
            state.endpoint = Some(endpoint.to_owned());
            StateBindingAction::AdoptedLegacy
        }
        Some(bound_endpoint) if bound_endpoint != endpoint => {
            state.adi_pb = None;
            state.endpoint = None;
            StateBindingAction::InvalidatedExplicitMismatch
        }
        Some(_) => StateBindingAction::Unchanged,
    }
}

impl AnisetteClient {
    pub async fn new(
        url: String,
        login_info: LoginClientInfo,
    ) -> Result<AnisetteClient, AnisetteError> {
        let url = normalize_endpoint(&url)?;
        Ok(AnisetteClient {
            login_info,
            url,
            apple_http_client: make_reqwest()?,
            relay_http_client: make_relay_reqwest()?,
        })
    }

    fn build_apple_request(
        &self,
        state: &AnisetteState,
        mut builder: RequestBuilder,
    ) -> RequestBuilder {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        // missing: Connection, Accept-Encdoing
        builder = builder
            .header("User-Agent", &self.login_info.akd_user_agent)
            .header("X-Apple-Baa-E", "-10000")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-Baa-Avail", "2")
            .header("X-Mme-Client-Info", &self.login_info.mme_client_info)
            .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("X-Apple-Client-App-Name", "akd")
            .header("Accept", "*/*")
            .header("Content-Type", "application/x-www-form-urlencoded") // not a bug, it's how you *think different*
            .header(
                "X-Apple-Baa-UE",
                "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
            )
            .header("X-Apple-Host-Baa-E", "-7066");

        for item in &self.login_info.hardware_headers {
            builder = builder.header(item.0, item.1);
        }

        builder
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData, AnisetteError> {
        let path = format!("{}/v3/get_headers", self.url);

        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(
                state
                    .adi_pb
                    .as_ref()
                    .ok_or(AnisetteError::AnisetteNotProvisioned)?,
            ),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String,
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            },
        }

        let headers = self
            .relay_http_client
            .post(path)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteHeaders>()
            .await?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } => Err(map_get_headers_error(&message)),
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                device_description: self.login_info.mme_client_info.clone(),
                local_user_id: encode_hex(&state.md_lu()),
                device_unique_identifier: state.device_id(),
            }),
        }
    }

    async fn get_headers_with_retry(
        &self,
        state: &AnisetteState,
    ) -> Result<AnisetteData, AnisetteError> {
        let mut last_error = None;
        for attempt in 1..=MAX_GET_HEADERS_ATTEMPTS {
            match self.get_headers(state).await {
                Ok(headers) => return Ok(headers),
                Err(error) if retryable_get_headers_error(&error) => {
                    warn!(
                        "anisette_v3 stage=get_headers result={} attempt={attempt}/{MAX_GET_HEADERS_ATTEMPTS}. State is preserved.",
                        error_kind(&error),
                    );
                    last_error = Some(error);
                    if attempt < MAX_GET_HEADERS_ATTEMPTS {
                        sleep(GET_HEADERS_RETRY_DELAY * attempt as u32).await;
                    }
                }
                Err(error) => return Err(error),
            }
        }

        Err(last_error.expect("get_headers retry loop must record a failure"))
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        let mut last_error = None;

        for attempt in 1..=MAX_PROVISION_ATTEMPTS {
            let attempt_started = Instant::now();
            let attempt_result =
                timeout(PROVISION_OVERALL_TIMEOUT, self.provision_once(state)).await;
            match attempt_result {
                Ok(Ok(())) => {
                    state.endpoint = Some(self.url.clone());
                    debug!(
                        "anisette_v3 stage=provision_complete elapsed_ms={}",
                        attempt_started.elapsed().as_millis()
                    );
                    return Ok(());
                }
                Ok(Err(ProvisionAttemptError::Fatal(error))) => return Err(error),
                Ok(Err(ProvisionAttemptError::Retryable(error))) => {
                    warn!(
                        "anisette_v3 stage=provision_attempt result={} attempt={attempt}/{MAX_PROVISION_ATTEMPTS} elapsed_ms={}. State is preserved.",
                        error_kind(&error),
                        attempt_started.elapsed().as_millis()
                    );
                    last_error = Some(error);
                    if attempt < MAX_PROVISION_ATTEMPTS {
                        sleep(PROVISION_RETRY_DELAY * attempt as u32).await;
                    }
                }
                Err(_) => {
                    let error = AnisetteError::ProvisioningServerError(
                        "provisioning overall timeout".into(),
                    );
                    warn!(
                        "anisette_v3 stage=provision_attempt result=overall_timeout attempt={attempt}/{MAX_PROVISION_ATTEMPTS} elapsed_ms={}. State is preserved.",
                        attempt_started.elapsed().as_millis()
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AnisetteError::ProvisioningServerError(
                "provisioning did not complete and did not report an error".into(),
            )
        }))
    }

    async fn provision_once(&self, state: &mut AnisetteState) -> Result<(), ProvisionAttemptError> {
        let stage_started = Instant::now();
        debug!("anisette_v3 stage=apple_lookup_start");
        let resp = self
            .build_apple_request(
                &state,
                self.apple_http_client
                    .get("https://gsa.apple.com/grandslam/GsService2/lookup"),
            )
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(ProvisionAttemptError::Retryable(
                AnisetteError::ProvisioningServerError("Apple lookup HTTP error".into()),
            ));
        }
        let text = resp.text().await?;
        debug!(
            "anisette_v3 stage=apple_lookup_complete elapsed_ms={}",
            stage_started.elapsed().as_millis()
        );

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let urls = protocol_val
            .as_dictionary()
            .unwrap()
            .get("urls")
            .unwrap()
            .as_dictionary()
            .unwrap();

        let start_provisioning_url = urls
            .get("midStartProvisioning")
            .unwrap()
            .as_string()
            .unwrap();
        let end_provisioning_url = urls
            .get("midFinishProvisioning")
            .unwrap()
            .as_string()
            .unwrap();
        let provision_ws_url =
            format!("{}/v3/provisioning_session", self.url).replacen("https://", "wss://", 1);
        debug!("anisette_v3 stage=websocket_connect_start");
        let connected = timeout(WS_CONNECT_TIMEOUT, connect_async(&provision_ws_url))
            .await
            .map_err(|_| {
                ProvisionAttemptError::Retryable(AnisetteError::ProvisioningServerError(
                    "websocket connect timeout".into(),
                ))
            })?;
        let (mut connection, _) = connected
            .map_err(|error| ProvisionAttemptError::Retryable(AnisetteError::WsError(error)))?;
        debug!("anisette_v3 stage=websocket_connect_complete");

        loop {
            let data = match timeout(WS_READ_TIMEOUT, connection.next()).await {
                Err(_) => {
                    return Err(ProvisionAttemptError::Retryable(
                        AnisetteError::ProvisioningServerError("websocket read timeout".into()),
                    ));
                }
                Ok(Some(Ok(data))) => data,
                Ok(Some(Err(error))) => {
                    return Err(ProvisionAttemptError::Retryable(AnisetteError::WsError(
                        error,
                    )));
                }
                Ok(None) => {
                    return Err(ProvisionAttemptError::Retryable(
                        AnisetteError::ProvisioningSocketClosed,
                    ));
                }
            };

            if data.is_text() {
                let txt = data.to_text().unwrap();
                let msg: ProvisionInput = serde_json::from_str(txt)?;
                if let Some((retryable, message)) = msg.server_error() {
                    let error = AnisetteError::ProvisioningServerError(message);
                    return Err(if retryable {
                        ProvisionAttemptError::Retryable(error)
                    } else {
                        ProvisionAttemptError::Fatal(error)
                    });
                }

                match msg {
                    ProvisionInput::GiveIdentifier => {
                        #[derive(Serialize)]
                        struct Identifier {
                            identifier: String, // base64
                        }
                        let identifier = Identifier {
                            identifier: base64_encode(&state.keychain_identifier),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&identifier)?))
                            .await?;
                    }
                    ProvisionInput::GiveStartProvisioningData => {
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::new(),
                        };
                        let stage_started = Instant::now();
                        debug!("anisette_v3 stage=apple_start_begin");
                        let resp = self
                            .build_apple_request(
                                state,
                                self.apple_http_client.post(start_provisioning_url),
                            )
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?;
                        if !resp.status().is_success() {
                            return Err(ProvisionAttemptError::Retryable(
                                AnisetteError::ProvisioningServerError(
                                    "Apple start HTTP error".into(),
                                ),
                            ));
                        }
                        let text = resp.text().await?;
                        debug!(
                            "anisette_v3 stage=apple_start_complete elapsed_ms={}",
                            stage_started.elapsed().as_millis()
                        );

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let spim = protocol_val
                            .as_dictionary()
                            .unwrap()
                            .get("Response")
                            .unwrap()
                            .as_dictionary()
                            .unwrap()
                            .get("spim")
                            .unwrap()
                            .as_string()
                            .unwrap();

                        debug!("anisette_v3 stage=send_start_data");
                        #[derive(Serialize)]
                        struct Spim {
                            spim: String, // base64
                        }
                        let spim = Spim {
                            spim: spim.to_string(),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&spim)?))
                            .await?;
                    }
                    ProvisionInput::GiveEndProvisioningData { cpim } => {
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::from_iter([("cpim", cpim)].into_iter()),
                        };
                        let stage_started = Instant::now();
                        debug!("anisette_v3 stage=apple_end_begin");
                        let resp = self
                            .build_apple_request(
                                state,
                                self.apple_http_client.post(end_provisioning_url),
                            )
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?;
                        if !resp.status().is_success() {
                            return Err(ProvisionAttemptError::Retryable(
                                AnisetteError::ProvisioningServerError(
                                    "Apple end HTTP error".into(),
                                ),
                            ));
                        }
                        let text = resp.text().await?;
                        debug!(
                            "anisette_v3 stage=apple_end_complete elapsed_ms={}",
                            stage_started.elapsed().as_millis()
                        );

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let response = protocol_val
                            .as_dictionary()
                            .unwrap()
                            .get("Response")
                            .unwrap()
                            .as_dictionary()
                            .unwrap();

                        debug!("anisette_v3 stage=send_end_data");

                        #[derive(Serialize)]
                        struct EndProvisioning<'t> {
                            ptm: &'t str,
                            tk: &'t str,
                        }
                        let end_provisioning = EndProvisioning {
                            ptm: response.get("ptm").unwrap().as_string().unwrap(),
                            tk: response.get("tk").unwrap().as_string().unwrap(),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&end_provisioning)?))
                            .await?;
                    }
                    ProvisionInput::ProvisioningSuccess { adi_pb } => {
                        debug!("anisette_v3 stage=provisioning_success");
                        let adi_pb =
                            general_purpose::STANDARD
                                .decode(adi_pb.trim())
                                .map_err(|_| {
                                    ProvisionAttemptError::Fatal(
                                        AnisetteError::ProvisioningServerError(
                                            "invalid provisioning result".into(),
                                        ),
                                    )
                                })?;
                        state.adi_pb = Some(adi_pb);
                        return Ok(());
                    }
                    ProvisionInput::Wait
                    | ProvisionInput::CurrentlyStartingProvisioning
                    | ProvisionInput::CurrentlyEndingProvisioning => {
                        debug!("anisette_v3 stage=server_message result=nonterminal_state");
                    }
                    ProvisionInput::TextOnly
                    | ProvisionInput::WebsocketError { .. }
                    | ProvisionInput::ClosingPerRequest
                    | ProvisionInput::Timeout
                    | ProvisionInput::InvalidIdentifier { .. }
                    | ProvisionInput::StartProvisioningError { .. }
                    | ProvisionInput::EndProvisioningError { .. } => {
                        unreachable!("server errors are handled before provisioning dispatch")
                    }
                }
            } else if data.is_close() {
                return Err(ProvisionAttemptError::Retryable(
                    AnisetteError::ProvisioningSocketClosed,
                ));
            }
        }
    }
}

pub struct RemoteAnisetteProviderV3 {
    client_url: String,
    client: Option<AnisetteClient>,
    pub state: Option<AnisetteState>,
    configuration_path: PathBuf,
    info: LoginClientInfo,
}

impl RemoteAnisetteProviderV3 {
    pub fn new(
        url: String,
        info: LoginClientInfo,
        configuration_path: PathBuf,
    ) -> RemoteAnisetteProviderV3 {
        RemoteAnisetteProviderV3 {
            client_url: url,
            client: None,
            state: None,
            configuration_path,
            info,
        }
    }
}

impl AnisetteProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        if self.client.is_none() {
            self.client =
                Some(AnisetteClient::new(self.client_url.clone(), self.info.clone()).await?);
        }
        let client = self.client.as_ref().unwrap();

        fs::create_dir_all(&self.configuration_path)?;

        let config_path = self.configuration_path.join("state.plist");
        if self.state.is_none() {
            self.state = Some(if let Ok(text) = plist::from_file(&config_path) {
                text
            } else {
                AnisetteState::new()
            });
        }

        let state = self.state.as_mut().unwrap();
        match reconcile_state_endpoint(state, &client.url) {
            StateBindingAction::AdoptedLegacy => {
                debug!("anisette_v3 stage=state_validation result=legacy_endpoint_adopted");
                plist::to_file_xml(&config_path, state)?;
            }
            StateBindingAction::InvalidatedExplicitMismatch => {
                debug!("anisette_v3 stage=state_validation result=explicit_endpoint_mismatch");
            }
            StateBindingAction::Unchanged => {}
        }
        if !state.is_provisioned_for(&client.url) {
            client.provision(state).await?;
            plist::to_file_xml(&config_path, state)?;
        }
        let data = match client.get_headers_with_retry(&state).await {
            Ok(data) => data,
            Err(err) => {
                if matches!(err, AnisetteError::AnisetteNotProvisioned) {
                    state.adi_pb = None;
                    state.endpoint = None;
                    client.provision(state).await?;
                    plist::to_file_xml(config_path, state)?;
                    client.get_headers_with_retry(&state).await?
                } else {
                    return Err(err);
                }
            }
        };
        Ok(data.get_headers())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_end_provisioning_error_as_retryable_server_error() {
        let message: ProvisionInput = serde_json::from_str(
            r#"{"result":"EndProvisioningError","message":"Apple service temporarily rejected the request"}"#,
        )
        .unwrap();

        assert_eq!(
            message.server_error(),
            Some((true, "server end provisioning error".into()))
        );
    }

    #[test]
    fn accepts_nonterminal_server_states() {
        for raw in [
            r#"{"result":"Wait"}"#,
            r#"{"result":"CurrentlyStartingProvisioning"}"#,
            r#"{"result":"CurrentlyEndingProvisioning"}"#,
        ] {
            let message: ProvisionInput = serde_json::from_str(raw).unwrap();
            assert!(message.server_error().is_none());
        }
    }

    #[test]
    fn endpoint_allowlist_requires_exact_https_hosts() {
        assert_eq!(
            normalize_endpoint("https://ani.sidestore.io/").unwrap(),
            "https://ani.sidestore.io"
        );
        assert_eq!(
            normalize_endpoint("https://ani.sidestore.app").unwrap(),
            "https://ani.sidestore.app"
        );
        assert_eq!(
            normalize_endpoint("https://ani.sidestore.io:443").unwrap(),
            "https://ani.sidestore.io"
        );
        for rejected in [
            "http://ani.sidestore.io",
            "https://ani.sidestore.io:444",
            "https://ani.sidestore.io/?redirect=evil",
            "https://ani.stikstore.app",
            "https://evil.example",
            "https://ani.sidestore.io.evil.example",
        ] {
            assert!(normalize_endpoint(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn legacy_provisioned_state_is_adopted_without_changing_adi() {
        let mut state = AnisetteState::new();
        state.adi_pb = Some(vec![1, 2, 3]);
        assert_eq!(
            reconcile_state_endpoint(&mut state, "https://ani.sidestore.io"),
            StateBindingAction::AdoptedLegacy
        );
        assert_eq!(state.adi_pb, Some(vec![1, 2, 3]));
        assert_eq!(state.endpoint.as_deref(), Some("https://ani.sidestore.io"));
        assert!(state.is_provisioned_for("https://ani.sidestore.io"));
    }

    #[test]
    fn explicit_endpoint_mismatch_invalidates_adi() {
        let mut state = AnisetteState::new();
        state.adi_pb = Some(vec![1, 2, 3]);
        state.endpoint = Some("https://ani.sidestore.io".into());

        assert_eq!(
            reconcile_state_endpoint(&mut state, "https://ani.sidestore.app"),
            StateBindingAction::InvalidatedExplicitMismatch
        );
        assert_eq!(state.adi_pb, None);
        assert_eq!(state.endpoint, None);
        assert!(!state.is_provisioned_for("https://ani.sidestore.app"));
    }

    #[test]
    fn transport_timeouts_are_explicit_and_bounded() {
        assert!(HTTP_CONNECT_TIMEOUT > Duration::ZERO);
        assert!(HTTP_READ_TIMEOUT > HTTP_CONNECT_TIMEOUT);
        assert!(WS_CONNECT_TIMEOUT > Duration::ZERO);
        assert!(WS_READ_TIMEOUT > Duration::ZERO);
        assert!(PROVISION_OVERALL_TIMEOUT > WS_READ_TIMEOUT);
        assert_eq!(MAX_GET_HEADERS_ATTEMPTS, 3);
        assert!(GET_HEADERS_RETRY_DELAY > Duration::ZERO);
    }

    #[test]
    fn get_headers_retry_policy_is_pre_submission_only() {
        assert!(retryable_get_headers_connect_error(true));
        assert!(!retryable_get_headers_connect_error(false));
        assert!(!retryable_get_headers_error(
            &AnisetteError::ProvisioningServerError("private-message-sentinel".into())
        ));
        assert!(!retryable_get_headers_error(
            &AnisetteError::AnisetteNotProvisioned
        ));
        assert!(!retryable_get_headers_error(
            &AnisetteError::InvalidArgument("private-message-sentinel".into())
        ));
    }

    #[test]
    fn failed_endpoint_does_not_trigger_unproven_implicit_failover() {
        // The three observed endpoints all reached GiveIdentifier, but no
        // endpoint-specific completion evidence exists yet. Keep selection
        // explicit until a deliberate failover policy is justified.
        let primary = normalize_endpoint("https://ani.sidestore.io").unwrap();
        assert_eq!(primary, "https://ani.sidestore.io");
        assert!(normalize_endpoint("https://unapproved-fallback.example").is_err());
    }

    #[test]
    fn diagnostic_kind_is_constant_and_secret_free() {
        let error =
            AnisetteError::ProvisioningServerError("identifier=redacted adi_pb=redacted".into());
        let kind = error_kind(&error);
        assert_eq!(kind, "server_error");
        assert!(!kind.contains("identifier"));
        assert!(!kind.contains("adi"));
        assert!(!kind.contains("header"));
    }

    #[test]
    fn get_headers_error_redacts_server_message_but_preserves_not_provisioned_code() {
        let secret = "identifier=secret adi_pb=secret";
        let error = map_get_headers_error(secret);
        assert_eq!(
            error.to_string(),
            "Anisette provisioning server error: get_headers server error"
        );
        assert!(!error.to_string().contains(secret));
        assert!(matches!(
            map_get_headers_error("request failed with -45061"),
            AnisetteError::AnisetteNotProvisioned
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_client_refuses_body_preserving_redirects() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
        };

        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let target_address = redirect_target.local_addr().unwrap();
        let target_received_request = Arc::new(AtomicBool::new(false));
        let target_received_request_thread = Arc::clone(&target_received_request);
        let target_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(750);
            while Instant::now() < deadline {
                match redirect_target.accept() {
                    Ok(_) => {
                        target_received_request_thread.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("redirect target accept failed: {error}"),
                }
            }
        });

        let redirect_source = TcpListener::bind("127.0.0.1:0").unwrap();
        let source_address = redirect_source.local_addr().unwrap();
        let source_thread = thread::spawn(move || {
            let (mut socket, _) = redirect_source.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/v3/get_headers\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).unwrap();
        });

        let response = make_relay_reqwest()
            .unwrap()
            .post(format!("http://{source_address}/v3/get_headers"))
            .body("sentinel-sensitive-body")
            .send()
            .await
            .unwrap();

        source_thread.join().unwrap();
        target_thread.join().unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        assert!(!target_received_request.load(Ordering::SeqCst));
    }
}
