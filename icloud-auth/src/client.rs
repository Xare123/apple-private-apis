use std::{collections::HashMap, str::FromStr, sync::Arc, time::{Duration, SystemTime}};

// use crate::anisette::AnisetteData;
use crate::{anisette::AnisetteData, Error};
use aes::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use omnisette::{AnisetteClient, AnisetteProvider, ArcAnisetteClient, LoginClientInfo};
use plist::{Dictionary, Value};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE}, Certificate, Client, ClientBuilder, Proxy, Response
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};
use log::{debug, error, warn};
use tokio::sync::Mutex;
use uuid::Uuid;

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");
// https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
// DER SHA256: 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179.
// Apple's Android secondary-auth service chains to G3, not the legacy root.
const APPLE_ROOT_G3: &[u8] = include_bytes!("./apple_root_g3.pem");

#[path = "auth_options.rs"]
mod auth_options;
#[path = "auth_routes.rs"]
mod auth_routes;
use auth_routes::{AuthRoutes, BoundAuthRoutes};

#[derive(Clone, Copy)]
enum AuthResponseStage {
    SrpInit,
    SrpComplete,
    TrustedDeviceVerification,
}

impl AuthResponseStage {
    fn label(self) -> &'static str {
        match self {
            Self::SrpInit => "srp-init",
            Self::SrpComplete => "srp-complete",
            Self::TrustedDeviceVerification => "trusted-device-verification",
        }
    }
}

// Only fixed stage names and numeric status may enter this diagnostic. Never
// include the response dictionary, server message, account name or SRP material.
fn auth_status_summary(stage: AuthResponseStage, code: Option<i64>, hsc: Option<i64>) -> String {
    let code = code.map(|value| value.to_string()).unwrap_or_else(|| "missing-or-invalid".to_string());
    let hsc = hsc.map(|value| value.to_string()).unwrap_or_else(|| "absent-or-invalid".to_string());
    format!("stage={}; code={code}; hsc={hsc}", stage.label())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequestBody {
    #[serde(rename = "A2k")]
    a_pub: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    ps: Vec<String>,
    #[serde(rename = "u")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestHeader {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: InitRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequestBody {
    #[serde(rename = "M1")]
    m: plist::Value,
    cpd: plist::Dictionary,
    c: String,
    #[serde(rename = "o")]
    operation: String,
    #[serde(rename = "u")]
    username: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: ChallengeRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequestBody {
    app: Vec<String>,
    c: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    t: String,
    u: String,
    checksum: plist::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: AuthTokenRequestBody,
}

pub struct FetchedToken {
    token: String,
    expiration: SystemTime,
}

fn remaining_token_lifetime(expiration: SystemTime, now: SystemTime) -> Duration {
    expiration.duration_since(now).unwrap_or_default()
}

#[cfg(test)]
mod token_lifetime_diagnostic_tests {
    use super::*;

    #[test]
    fn lifetime_is_observed_without_extending_expired_tokens() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert_eq!(remaining_token_lifetime(now + Duration::from_secs(20), now), Duration::from_secs(20));
        assert_eq!(remaining_token_lifetime(now, now), Duration::ZERO);
        assert_eq!(remaining_token_lifetime(now - Duration::from_secs(20), now), Duration::ZERO);
    }
}

pub struct AppleAccount<T: AnisetteProvider> {
    //TODO: move this to omnisette
    pub anisette: ArcAnisetteClient<T>,
    pub client_info: LoginClientInfo,
    // pub spd:  Option<plist::Dictionary>,
    //mutable spd
    pub spd: Option<plist::Dictionary>,
    pub username: Option<String>,
    client: Client,
    pub tokens: HashMap<String, FetchedToken>,
    pub hashed_password: Option<Vec<u8>>,
    // Bound only after a verified SRP exchange. Verification must keep the
    // same client and service selection that created its identity token.
    auth_routes: Option<BoundAuthRoutes>,
    // Synthetic/manual route fixtures only; production always uses lookup.
    #[cfg(test)]
    auth_routes_override: Option<AuthRoutes>,
    // Isolated comparison only, enabled explicitly by the private probe.
    #[cfg(all(test, feature = "remote-anisette-v3"))]
    secondary_auth_session: Option<Mutex<HeaderMap>>,
}

#[derive(Serialize)]
pub struct CircleSendMessage {
    pub atxid: String,
    pub circlestep: u32,
    pub idmsdata: Option<String>,
    pub pakedata: Option<String>,
    pub ptkn: String,
    pub ec: Option<i32>,
}

#[derive(Clone)]
pub struct AppToken {
    pub app_tokens: plist::Dictionary,
    pub auth_token: String,
    pub app: String,
}
//Just make it return a custom enum, with LoggedIn(account: AppleAccount) or Needs2FA(FinishLoginDel: fn(i32) -> TFAResponse)
#[repr(C)]
#[derive(Debug)]
pub enum LoginState {
    LoggedIn,
    // NeedsSMS2FASent(Send2FAToDevices),
    NeedsDevice2FA,
    Needs2FAVerification,
    NeedsSMS2FA,
    NeedsSMS2FAVerification(VerifyBody),
    NeedsExtraStep(String),
    NeedsLogin,
}

#[derive(Serialize, Debug, Clone)]
struct VerifyCode {
    code: String,
}

#[derive(Serialize, Debug, Clone)]
#[repr(C)]
struct PhoneNumber {
    id: u32
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[repr(C)]
pub struct VerifyBody {
    phone_number: PhoneNumber,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_code: Option<VerifyCode>
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum GenerateVerificationTokenRequest {
    Passkey {
        client_data_hash: String,
    }
}

#[derive(Deserialize)]
pub struct CircleResponse {
    pub sid: Option<String>,
}

#[repr(C)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPhoneNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtras {
    #[serde(default)]
    pub trusted_phone_numbers: Vec<TrustedPhoneNumber>,
    pub recovery_url: Option<String>,
    pub cant_use_phone_number_url: Option<String>,
    pub dont_have_access_url: Option<String>,
    pub recovery_web_url: Option<String>,
    pub repair_phone_number_url: Option<String>,
    pub repair_phone_number_web_url: Option<String>,
    #[serde(skip)]
    pub new_state: Option<LoginState>,
}

// impl Send2FAToDevices {
//     pub fn send_2fa_to_devices(&self) -> LoginResponse {
//         self.account.send_2fa_to_devices().unwrap()
//     }
// }

// impl Verify2FA {
//     pub fn verify_2fa(&self, tfa_code: &str) -> LoginResponse {
//         self.account.verify_2fa(&tfa_code).unwrap()
//     }
// }

fn looks_like_html(value: &str) -> bool {
    let prefix = value.trim_start().chars().take(64).collect::<String>().to_ascii_lowercase();
    prefix.contains("<html") || prefix.contains("<!doctype html")
}

fn classify_html_page(body: &str) -> &'static str {
    let lowercase = body.to_ascii_lowercase();
    if lowercase.contains("mobileme_terms_of_service_update")
        || lowercase.contains("terms and conditions")
        || lowercase.contains("terms of service") {
        "terms-update"
    } else if lowercase.contains("update_account_ui")
        || (lowercase.contains("account") && lowercase.contains("repair")) {
        "account-repair"
    } else if lowercase.contains("boot_args") && lowercase.contains("appleauth") {
        "apple-account-web-auth"
    } else if lowercase.contains("securitycode")
        || lowercase.contains("verification code")
        || lowercase.contains("two-factor") {
        "two-factor"
    } else if lowercase.contains("sign in") || lowercase.contains("signin") {
        "sign-in"
    } else {
        "unclassified-html"
    }
}

fn safe_response_origin(value: &str) -> String {
    match reqwest::Url::parse(value) {
        Ok(url) if matches!(url.scheme(), "https" | "http") && url.host_str().is_some() => {
            format!("{}://{}", url.scheme(), url.host_str().unwrap())
        }
        _ => "unknown-origin".to_string(),
    }
}

fn unexpected_response_summary(stage: &str, status: reqwest::StatusCode, content_type: &str, final_url: &str, body: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(body.as_bytes()));
    let final_origin = safe_response_origin(final_url);
    format!(
        "stage={stage}; status={}; content_type={}; final_origin={final_origin}; body_kind=html; page={}; bytes={}; sha256={}",
        status.as_u16(), content_type.split(';').next().unwrap_or("unknown"), classify_html_page(body),
        body.len(), &digest[..16]
    )
}

/// Strict bounds for the single HTTP/500 exception below. Every other 5xx and
/// 429 never reads the body. A 500 body that is larger, slower, malformed,
/// HTML, or success-shaped stays a generic service error.
const HTTP500_MAX_BODY_BYTES: usize = 16 * 1024;
const HTTP500_BODY_TIMEOUT: Duration = Duration::from_secs(1);

async fn parse_response(stage: &str, res: Result<Response, reqwest::Error>) -> Result<plist::Dictionary, crate::Error> {
    let response = res?;
    #[cfg(all(test, feature = "remote-anisette-v3"))]
    auth_probe::report_session_headers(stage, response.headers());
    let status = response.status();
    // Rate limiting is never an SRP challenge or an account rejection.
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        warn!("Apple authentication HTTP: stage={stage}; status={}", status.as_u16());
        return Err(crate::Error::AuthenticationRateLimited);
    }
    // Other infrastructure 5xx responses are not SRP challenges either. Do not
    // read an arbitrary error body, retry the login, or replace the primary
    // HTTP failure with a plist/body-read failure.
    if status.is_server_error() && status != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        warn!("Apple authentication HTTP: stage={stage}; status={}", status.as_u16());
        return Err(crate::Error::AuthenticationServiceUnavailable(status.as_u16()));
    }
    if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        // Bounded HTTP/500 exception only: Apple can return a structured SRP
        // rejection (for example ec -80045, upstream provider issue 61)
        // inside a plist on HTTP 500. Preserve only a nonzero structured
        // rejection for the existing stage check. Everything else stays
        // fail-closed as generic 500 without logging body contents.
        let unavailable = || {
            warn!("Apple authentication HTTP: stage={stage}; status={}", status.as_u16());
            crate::Error::AuthenticationServiceUnavailable(status.as_u16())
        };
        if let Some(len) = response.content_length() {
            if len > HTTP500_MAX_BODY_BYTES as u64 {
                return Err(unavailable());
            }
        }
        // Incrementally cap the body BEFORE retaining each chunk, inside one
        // total <=1s budget. This bounds unknown/chunked bodies too: an
        // oversized first chunk (or stalled remainder) is rejected without
        // buffering the full body or waiting for the stalled remainder.
        let mut bytes: Vec<u8> = Vec::new();
        let mut response = response;
        let read = async {
            loop {
                let chunk = response.chunk().await?;
                let Some(chunk) = chunk else {
                    break;
                };
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|total| *total <= HTTP500_MAX_BODY_BYTES)
                    .is_none()
                {
                    return Err(crate::Error::AuthenticationServiceUnavailable(
                        status.as_u16(),
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, crate::Error>(())
        };
        // A timeout, read failure, or size limit preserves the original 500.
        if !matches!(tokio::time::timeout(HTTP500_BODY_TIMEOUT, read).await, Ok(Ok(()))) {
            return Err(unavailable());
        }
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if looks_like_html(text) {
                return Err(unavailable());
            }
        }
        let root: plist::Value = match plist::from_bytes(&bytes) {
            Ok(root) => root,
            Err(_) => return Err(unavailable()),
        };
        if let plist::Value::String(value) = &root {
            if looks_like_html(value) {
                return Err(unavailable());
            }
        }
        let plist::Value::Dictionary(mut root) = root else {
            return Err(unavailable());
        };
        let Some(dict) = root.remove("Response").and_then(|value| match value {
            plist::Value::Dictionary(dict) => Some(dict),
            _ => None,
        }) else {
            return Err(unavailable());
        };
        let status_dict = dict
            .get("Status")
            .and_then(plist::Value::as_dictionary)
            .unwrap_or(&dict);
        let Some(code) = status_dict.get("ec").and_then(plist_i64) else {
            return Err(unavailable());
        };
        if code == 0 {
            // Never accept HTTP 500 ec=0 as authentication success.
            return Err(unavailable());
        }
        return Ok(dict);
    }
    let final_url = safe_response_origin(response.url().as_str());
    let content_type = response.headers().get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok()).unwrap_or("unknown").to_string();
    let body = response.text().await?;
    if looks_like_html(&body) {
        let summary = unexpected_response_summary(stage, status, &content_type, &final_url, &body);
        warn!("Unexpected Apple authentication response: {summary}");
        return Err(crate::Error::UnexpectedResponse(summary));
    }

    let root: plist::Value = plist::from_bytes(body.as_bytes())?;
    if let plist::Value::String(value) = &root {
        if looks_like_html(value) {
            let summary = unexpected_response_summary(stage, status, &content_type, &final_url, value);
            warn!("Unexpected Apple authentication response: {summary}");
            return Err(crate::Error::UnexpectedResponse(summary));
        }
    }
    let plist::Value::Dictionary(mut root) = root else { return Err(crate::Error::Parse) };
    match root.remove("Response") {
        Some(plist::Value::Dictionary(dict)) => Ok(dict),
        _ => Err(crate::Error::Parse),
    }
}

struct SrpInitParams {
    salt: Vec<u8>,
    b_pub: Vec<u8>,
    iters: u32,
    c: String,
}

fn plist_u32(value: &plist::Value) -> Option<u32> {
    value
        .as_unsigned_integer()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| {
            value
                .as_signed_integer()
                .and_then(|value| u32::try_from(value).ok())
        })
}

fn plist_i64(value: &plist::Value) -> Option<i64> {
    value.as_signed_integer().or_else(|| {
        value
            .as_unsigned_integer()
            .and_then(|value| i64::try_from(value).ok())
    })
}

fn srp_init_params(res: &Dictionary) -> Result<SrpInitParams, crate::Error> {
    let salt = res
        .get("s")
        .and_then(|v| v.as_data())
        .ok_or(crate::Error::MalformedSrpInit("s"))?
        .to_vec();
    let b_pub = res
        .get("B")
        .and_then(|v| v.as_data())
        .ok_or(crate::Error::MalformedSrpInit("B"))?
        .to_vec();
    let iters = res
        .get("i")
        .and_then(plist_u32)
        .ok_or(crate::Error::MalformedSrpInit("i"))?;
    let c = res
        .get("c")
        .and_then(|v| v.as_string())
        .ok_or(crate::Error::MalformedSrpInit("c"))?
        .to_string();
    Ok(SrpInitParams { salt, b_pub, iters, c })
}

fn srp_complete_parts(res: &Dictionary) -> Result<(&[u8], &[u8], &Dictionary), crate::Error> {
    let m2 = res
        .get("M2")
        .and_then(|v| v.as_data())
        .ok_or(crate::Error::MalformedSrpComplete("M2"))?;
    let spd = res
        .get("spd")
        .and_then(|v| v.as_data())
        .ok_or(crate::Error::MalformedSrpComplete("spd"))?;
    let status = res
        .get("Status")
        .and_then(|v| v.as_dictionary())
        .ok_or(crate::Error::MalformedSrpComplete("Status"))?;
    Ok((m2, spd, status))
}

fn spd_account_name(decoded_spd: &Dictionary) -> Result<&str, crate::Error> {
    decoded_spd
        .get("acname")
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .ok_or(crate::Error::MalformedSpd("acname"))
}

fn map_login_state(status: &Dictionary) -> LoginState {
    match status.get("au") {
        Some(plist::Value::String(s)) => match s.as_str() {
            "trustedDeviceSecondaryAuth" => LoginState::NeedsDevice2FA,
            "secondaryAuth" => LoginState::NeedsSMS2FA,
            unk => LoginState::NeedsExtraStep(unk.to_string()),
        },
        // Apple can omit `au` when a trusted-device verification challenge was
        // already sent. A valid SRP proof is not completed two-factor login.
        _ if status.get("hsc").and_then(Value::as_signed_integer) == Some(409) =>
            LoginState::Needs2FAVerification,
        _ => LoginState::LoggedIn,
    }
}

impl<T: AnisetteProvider> AppleAccount<T> {

    pub fn new_with_anisette(client_info: LoginClientInfo, anisette:  ArcAnisetteClient<T>) -> Result<Self, crate::Error> {
        let client = ClientBuilder::new()
            .cookie_store(true)
            .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
            .add_root_certificate(Certificate::from_pem(APPLE_ROOT_G3)?)
            // .proxy(Proxy::https("https://192.168.99.71:8080").unwrap())
            // .danger_accept_invalid_certs(true)
            .http1_title_case_headers()
            .connection_verbose(true)
            .build()?;

        Ok(AppleAccount {
            client,
            anisette,
            client_info,
            spd: None,
            username: None,
            tokens: HashMap::new(),
            hashed_password: None,
            auth_routes: None,
            #[cfg(test)]
            auth_routes_override: None,
            #[cfg(all(test, feature = "remote-anisette-v3"))]
            secondary_auth_session: None,
        })
    }

    pub async fn login(
        appleid_closure: impl Fn() -> (String, Vec<u8>),
        tfa_closure: impl Fn() -> String,
        client_info: LoginClientInfo,
        anisette: ArcAnisetteClient<T>
    ) -> Result<AppleAccount<T>, Error> {
        AppleAccount::login_with_anisette(appleid_closure, tfa_closure, client_info, anisette).await
    }

    pub async fn get_anisette(&self) -> Result<AnisetteData, crate::Error> {
        let mut locked = self.anisette.lock().await;
        Ok(AnisetteData::new(&mut *locked, self.client_info.clone()).await?)
    }

    fn create_checksum(session_key: &Vec<u8>, dsid: &str, app_name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&session_key)
            .unwrap()
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app_name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }

    /// # Arguments
    ///
    /// * `appleid_closure` - A closure that takes no arguments and returns a tuple of the Apple ID and password
    /// * `tfa_closure` - A closure that takes no arguments and returns the 2FA code
    /// * `anisette` - AnisetteData
    /// # Examples
    ///
    /// ```
    /// use icloud_auth::AppleAccount;
    /// use omnisette::AnisetteData;
    ///
    /// let anisette = AnisetteData::new();
    /// let account = AppleAccount::login(
    ///   || ("test@waffle.me", "password")
    ///   || "123123",
    ///  anisette
    /// );
    /// ```
    /// Note: You would not provide the 2FA code like this, you would have to actually ask input for it.
    //TODO: add login_with_anisette and login, where login autodetcts anisette
    pub async fn login_with_anisette<F: Fn() -> (String, Vec<u8>), G: Fn() -> String>(
        appleid_closure: F,
        tfa_closure: G,
        client_info: LoginClientInfo,
        anisette: ArcAnisetteClient<T>
    ) -> Result<AppleAccount<T>, Error> {
        let mut _self = AppleAccount::new_with_anisette(client_info, anisette)?;
        let (username, password) = appleid_closure();

        let mut response = _self.login_email_pass(&username, &password).await?;
        loop {
            match response {
                // LoginState::NeedsDevice2FA => response = _self.send_2fa_to_devices().await?,
                LoginState::Needs2FAVerification => {
                    response = _self.verify_2fa(tfa_closure()).await?
                }
                LoginState::NeedsSMS2FA | LoginState::NeedsDevice2FA => {
                    _self.send_2fa_to_devices().await?;
                    response = _self.send_sms_2fa_to_devices(1).await?
                }
                LoginState::NeedsSMS2FAVerification(body) => {
                    response = _self.verify_sms_2fa(tfa_closure(), body).await?
                }
                LoginState::NeedsLogin => {
                    response = _self.login_email_pass(&username, &password).await?
                }
                LoginState::LoggedIn => return Ok(_self),
                LoginState::NeedsExtraStep(step) => {
                    if _self.get_pet().is_some() {
                        return Ok(_self)
                    } else {
                        return Err(Error::ExtraStep(step))
                    }
                }
            }
        }
    }

    pub fn get_pet(&self) -> Option<String> {
        self.tokens.get("com.apple.gs.idms.pet").map(|t| &t.token).cloned()
    }

    /// Non-secret diagnostic only. Does not refresh or extend the token.
    pub fn pet_remaining_lifetime(&self) -> Option<Duration> {
        self.tokens.get("com.apple.gs.idms.pet")
            .map(|token| remaining_token_lifetime(token.expiration, SystemTime::now()))
    }

    pub fn get_name(&self) -> (String, String) {
        (
            self.spd.as_ref().unwrap().get("fn").unwrap().as_string().unwrap().to_string(),
            self.spd.as_ref().unwrap().get("ln").unwrap().as_string().unwrap().to_string()
        )
    }

    pub async fn get_token(&mut self, token: &str) -> Option<String> {
        let has_valid_token = if !self.tokens.is_empty() {
            let data = self.tokens.get(token)?; // if it's not here, we don't have one
            
            data.expiration.elapsed().is_err()
        } else {
            false
        };
        if !has_valid_token {
            // we've elapsed, get new tokens...
            let username = self.username.clone()?;
            let hashed_password = self.hashed_password.clone()?;
            match self.login_email_pass(&username, &hashed_password).await {
                Ok(LoginState::LoggedIn) => {},
                _err => {
                    error!("Failed to refresh account tokens");
                    return None
                }
            }
        }

        Some(self.tokens.get(token)?.token.to_string())
    }

    pub async fn generate_verification_token(&mut self, request: GenerateVerificationTokenRequest) -> Result<String, Error> {
        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();

        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_generate_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));
        
        let token = self.get_token("com.apple.gs.idms.hb").await.ok_or(Error::HappyBirthdayError)?;
        gsa_headers.insert("X-Apple-HB-Token", HeaderValue::from_str(&base64::encode(format!("{}:{}", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap(), token))).unwrap());
        gsa_headers.insert("X-Apple-I-UrlSwitch-Info", HeaderValue::from_str(&base64::encode(format!("{}:generateVerificationToken", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap()))).unwrap());
        

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post("https://gsa.apple.com/grandslam/ws/common/generateVerificationToken")
            .headers(gsa_headers.clone())
            .json(&json!({
                "apd": request
            }))
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp)
        }

        let header = res.headers().get("X-Apple-I-GS-Token").expect("No GS Token!");

        let decoded = String::from_utf8(base64::decode(&header.as_bytes()).expect("Not base64!")).expect("Decoded not utf8!");

        Ok(decoded)
    }

    pub async fn circle(
        &mut self,
        message: &CircleSendMessage,
        is_twofa: bool,
    ) -> Result<CircleResponse, Error> {

        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );

        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_circle_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));
        
        if is_twofa {
            let spd = self.spd.as_ref().unwrap();
            let dsid = spd.get("adsid").unwrap().as_string().unwrap();
            let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

            let identity_token = base64::encode(format!("{}:{}", dsid, token));
            gsa_headers.insert("X-Apple-Identity-Token", HeaderValue::from_str(&identity_token).unwrap());
        } else {
            let token = self.get_token("com.apple.gs.idms.hb").await.ok_or(Error::HappyBirthdayError)?;
            gsa_headers.insert("X-Apple-HB-Token", HeaderValue::from_str(&base64::encode(format!("{}:{}", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap(), token))).unwrap());
        }
        
        let data = plist::to_value(&message)?;

        let packet = Dictionary::from_iter([
            ("Header", Value::Dictionary(Default::default())),
            ("Request", data)
        ]);

        // ptkn


        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post(format!("{GSA_ENDPOINT}/circle"))
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp)
        }

        let response = res.bytes().await?;

        Ok(plist::from_bytes(&response)?)
    }

    pub async fn logout_all(&mut self, device_name: &str) -> Result<(), Error> {
        let mut services = vec!["icloud", "imessage", "facetime"];

        while services.len() > 0 {
            let service = services.remove(0);
            self.update_postdata(device_name, Some(service), &services).await?;
        }

        self.update_postdata(device_name, Some("all"), &services).await?;

        Ok(())
    }

    pub async fn update_postdata(
        &mut self,
        device_name: &str,
        logout: Option<&'static str>,
        services: &[&'static str],
    ) -> Result<LoginState, Error> {

        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );

        let token = self.get_token("com.apple.gs.idms.hb").await.ok_or(Error::HappyBirthdayError)?;

        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_postdata_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));
        gsa_headers.insert("X-Apple-I-UrlSwitch-Info", HeaderValue::from_str(&base64::encode(format!("{}:postdata", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap()))).unwrap());
        gsa_headers.insert("X-Apple-HB-Token", HeaderValue::from_str(&base64::encode(format!("{}:{}", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap(), token))).unwrap());

        let data = if let Some(logout) = logout {
            gsa_headers.remove("X-Apple-I-Service-Type");
            gsa_headers.remove("X-Apple-AK-DataRecoveryService-Status");
            gsa_headers.remove("X-Apple-I-CDP-Status");
            gsa_headers.remove("X-Apple-I-OT-Status");
            gsa_headers.insert("X-Apple-I-CDP-Status", HeaderValue::from_str("false").unwrap());
            gsa_headers.insert("X-Apple-I-OT-Status", HeaderValue::from_str("false").unwrap());
            Dictionary::from_iter([
                ("cdpStatus", Value::Boolean(false)),
                ("circleStatus", Value::Boolean(false)),
                ("dn", Value::String(device_name.to_string())),
                ("event", Value::String(format!("signout-{logout}"))),
                ("loc", Value::String("en_US".to_string())),
                ("otStatus", Value::Boolean(false)),
                ("prkgen", Value::Boolean(true)),
                ("rep", Value::Integer(1.into())),
                ("services", Value::Array(services.iter().map(|s| Value::String(s.to_string())).collect())),
                ("ut", Value::Integer(1.into())),
            ])
        } else {
            let mut data = Dictionary::from_iter([
                ("cdpStatus", Value::Boolean(true)),
                ("cfuids", Value::Array(vec![])),
                ("circleStatus", Value::Boolean(true)),
                ("denyICloudWebAccess", Value::Boolean(true)),
                ("dn", Value::String(device_name.to_string())),
                ("event", Value::String("liveness".to_string())),
                ("icloudMailEnabled", Value::Boolean(false)),
                ("icscStatus", Value::Boolean(true)),
                ("isLegacyContactAssignee", Value::Integer(1.into())),
                ("isRecoveryContactAssignee", Value::Integer(1.into())),
                ("loc", Value::String("en_US".to_string())),
                ("otStatus", Value::Boolean(true)),
                ("pkc", Value::String("1".to_string())),
                ("prkgen", Value::Boolean(true)),
                ("reason", Value::Integer(5.into())),
                ("rep", Value::Integer(1.into())),
                ("services", Value::Array(services.iter().map(|s| Value::String(s.to_string())).collect())),
                ("signinPartition", Value::Integer(1.into())),
                ("stingrayDisabledIndicator", Value::Boolean(false)),
                ("usrt", Value::Integer(4.into())),
                ("ut", Value::Integer(1.into())),
            ]);
    
            if let Some(ptkn) = &self.client_info.push_token {
                data.insert("ptkn".to_string(), Value::String(ptkn.clone()));
            }
            data
        };

        let packet = Dictionary::from_iter([
            ("Header", Value::Dictionary(Default::default())),
            ("Request", Value::Dictionary(data))
        ]);

        // ptkn


        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        // note the S
        let res = self
            .client
            .post("https://gsas.apple.com/grandslam/GsService2/postdata")
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp)
        }

        Ok(LoginState::LoggedIn)
    }


    pub async fn teardown(
        &mut self,
        action: &str,
        cmd: u32,
        txnid: &str,
    ) -> Result<LoginState, Error> {

        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );

        let token = self.get_token("com.apple.gs.idms.hb").await.ok_or(Error::HappyBirthdayError)?;

        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_takedown_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));
        gsa_headers.insert("X-Apple-I-UrlSwitch-Info", HeaderValue::from_str(&base64::encode(format!("{}:teardown", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap()))).unwrap());
        gsa_headers.insert("X-Apple-HB-Token", HeaderValue::from_str(&base64::encode(format!("{}:{}", self.spd.as_ref().unwrap().get("adsid").expect("no adsid!!").as_string().unwrap(), token))).unwrap());

        let mut data = Dictionary::from_iter([
            ("action", Value::String(action.to_string())),
            ("cmd", Value::Integer(cmd.into())),
            ("prkgen", Value::Boolean(false)),
            ("txnid", Value::String(txnid.to_string())),
        ]);

        let packet = Dictionary::from_iter([
            ("Header", Value::Dictionary(Default::default())),
            ("Request", Value::Dictionary(data))
        ]);

        // ptkn


        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post("https://gsas.apple.com/grandslam/GsService2/teardown")
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp)
        }

        Ok(LoginState::LoggedIn)
    }

    async fn request_srp_init(
        &self,
        endpoint: &str,
        username: &str,
        a_pub: Vec<u8>,
        valid_anisette: &AnisetteData,
        request_id: &str,
    ) -> Result<(Dictionary, HeaderMap), Error> {
        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_gsservice_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: valid_anisette.get_cpd_data(request_id),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.to_string(),
        };

        let packet = InitRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post(endpoint)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let stage = AuthResponseStage::SrpInit;
        let res = parse_response(stage.label(), res).await?;
        Self::check_error_at_stage(stage, &res)?;
        Ok((res, gsa_headers))
    }

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        hashed_password: &[u8],
    ) -> Result<LoginState, Error> {
        // A new exchange supersedes the previous verification challenge even
        // if lookup, transport, proof verification, or cancellation stops it.
        // Drop only this ephemeral authority before the first await; do not
        // erase saved profile data. Only verified SRP below grants a new binding.
        self.auth_routes = None;
        let srp_client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        self.username = Some(username.to_string());
        let valid_anisette = self.get_anisette().await?;
        // Use the effective provider metadata, not the activation hardware's
        // original description. A single selection governs both SRP stages.
        let routes = self.select_auth_routes(&valid_anisette.client_info).await?;
        let request_id = Uuid::new_v4().to_string().to_uppercase();
        let header = RequestHeader { version: "1.0.1".to_string() };
        let (res, gsa_headers) = self.request_srp_init(
            routes.srp, username, a_pub, &valid_anisette, &request_id,
        ).await?;
        // println!("{:?}", res);
        let init = srp_init_params(&res)?;
        let salt = init.salt;
        let b_pub = init.b_pub;
        let iters = init.iters;
        let c = init.c;

        self.hashed_password = Some(hashed_password.to_vec());

        // Check which SRP protocol the server selected
        let selected_protocol = res.get("sp").and_then(|v| v.as_string()).unwrap_or("s2k");

        let password_for_srp: Vec<u8> = if selected_protocol == "s2k_fo" {
            // s2k_fo: hex-encode the already-SHA256'd password bytes.
            // hashed_password is already SHA256(raw_password), so just hex-encode it.
            hashed_password.iter().map(|b| format!("{:02x}", b)).collect::<String>().into_bytes()
        } else {
            // s2k: use the SHA256-hashed password bytes directly
            hashed_password.to_vec()
        };
        
        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &password_for_srp,
            &salt,
            iters,
            &mut password_buf,
        );

        let verifier: SrpClientVerifier<Sha256> = srp_client
            .process_reply(&a, &username.as_bytes(), &password_buf, &salt, &b_pub, true)
            .map_err(|_| crate::Error::SrpFailure("process-reply"))?;

        let m = verifier.proof();

        let body = ChallengeRequestBody {
            m: plist::Value::Data(m.to_vec()),
            c: c.to_string(),
            cpd: valid_anisette.get_cpd_data(&request_id),
            operation: "complete".to_string(),
            username: username.to_string(),
        };

        let packet = ChallengeRequest {
            header,
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        let res = self
            .client
            .post(routes.srp)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let stage = AuthResponseStage::SrpComplete;
        let res = parse_response(stage.label(), res).await?;
        Self::check_error_at_stage(stage, &res)?;
        // println!("{:?}", res);
        let (m2, spd, status) = srp_complete_parts(&res)?;
        verifier
            .verify_server(m2)
            .map_err(|_| crate::Error::SrpFailure("verify-server"))?;

        let decrypted_spd = Self::decrypt_cbc(&verifier, spd)?;
        let decoded_spd: plist::Dictionary = plist::from_bytes(&decrypted_spd)?;

        if let Some(Value::Dictionary(dict)) = decoded_spd.get("t") {
            let keys: HashMap<String, FetchedToken> = dict.iter().filter_map(|(service, value)| {
                Some((service.clone(), FetchedToken {
                    token: value.as_dictionary()?.get("token")?.as_string()?.to_string(),
                    expiration: if let Some(expiry) = value.as_dictionary()?.get("expiry") {
                        SystemTime::UNIX_EPOCH + Duration::from_millis(expiry.as_unsigned_integer()?)
                    } else {
                        SystemTime::now() + Duration::from_secs(value.as_dictionary()?.get("duration")?.as_unsigned_integer()?)
                    },
                }))
            }).collect();
            self.tokens = keys;
        }
        debug!(
            "Parsed SPD response (keys={}, has_account_name={}, has_token_dictionary={})",
            decoded_spd.len(),
            decoded_spd.contains_key("acname"),
            decoded_spd.contains_key("t")
        );

        let account_name = spd_account_name(&decoded_spd)?.to_string();
        self.username = Some(account_name);
        self.spd = Some(decoded_spd);
        self.auth_routes = Some(BoundAuthRoutes::new(routes, &valid_anisette.client_info));

        Ok(map_login_state(status))
    }

    fn create_session_key(usr: &SrpClientVerifier<Sha256>, name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&usr.key())
            .unwrap()
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }

    fn decrypt_cbc(usr: &SrpClientVerifier<Sha256>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:");
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:");
        let extra_data_iv = &extra_data_iv[..16];

        let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
            .map_err(|_| crate::Error::SpdDecryptFailed)?;
        decryptor
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| crate::Error::SpdDecryptFailed)
    }

    async fn select_auth_routes(&self, info: &LoginClientInfo) -> Result<AuthRoutes, Error> {
        #[cfg(test)]
        if let Some(routes) = self.auth_routes_override { return Ok(routes); }
        // Refresh lookup at a new SRP exchange. No per-request discovery while
        // entering a code and no guessing/default route on lookup failure.
        auth_routes::lookup(info).await
    }

    fn session_auth_routes(&self) -> Result<AuthRoutes, Error> {
        self.auth_routes.as_ref().map(|binding| binding.routes)
            .ok_or(Error::TwoFactorSessionMissing)
    }

    fn secondary_auth_endpoint(&self, suffix: &str) -> Result<String, Error> {
        Ok(self.session_auth_routes()?.secondary_endpoint(suffix))
    }

    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, crate::Error> {
        let headers = self.build_2fa_headers(false);

        let res = self
            .client
            .get(self.session_auth_routes()?.trusted_device)
            .headers(headers.await?)
            .send().await?;

        debug!("Apple authentication HTTP: stage=trusted-device-push; status={}", res.status().as_u16());
        if !res.status().is_success() {
            let status = res.status();
            error!("send_2fa_to_devices failed: HTTP {}", status);
            return Err(Error::AuthSrp);
        }

        return Ok(LoginState::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginState, crate::Error> {
        let headers = self.build_2fa_headers(true);


        let body = VerifyBody {
            phone_number: PhoneNumber {
                id: phone_id
            },
            mode: "sms".to_string(),
            security_code: None
        };

        let res = self
            .client
            .put(self.secondary_auth_endpoint("/verify/phone")?)
            .headers(headers.await?)
            .header("Accept", "application/json")
            .json(&body)
            .send().await?;

        debug!("Apple authentication HTTP: stage=sms-request; status={}", res.status().as_u16());
        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }
        #[cfg(all(test, feature = "remote-anisette-v3"))]
        self.retain_probe_session(&res, "/verify/phone").await?;

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true);

        let req = self.client
            .get(self.secondary_auth_endpoint("")?)
            .headers(headers.await?)
            .header("Accept", "application/json")
            .send().await?;
        #[cfg(all(test, feature = "remote-anisette-v3"))]
        if req.status().is_success() {
            self.retain_probe_session(&req, "").await?;
        }
        auth_options::parse_auth_options_response(req).await
    }

    #[cfg(all(test, feature = "remote-anisette-v3"))]
    async fn retain_probe_session(&self, response: &Response, suffix: &str) -> Result<(), Error> {
        if let Some(session) = &self.secondary_auth_session {
            if response.url().as_str() != self.secondary_auth_endpoint(suffix)? {
                return Err(Error::UnexpectedResponse("secondary-auth-origin-changed".into()));
            }
            let updates = auth_probe::continuation_headers(response.headers())?;
            session.lock().await.extend(updates);
        }
        Ok(())
    }

    pub async fn request_update_account(&self) -> Result<String, Error> {
        let mut map = HashMap::new();
        let adsid = self.spd.as_ref().unwrap()["adsid"].as_string().unwrap().to_string();
        let base_headers = self.anisette.lock().await.get_headers().await?.clone();
        map.extend(base_headers);

        map.extend([
            ("Authorization", format!("Basic {}", base64::encode(format!("{}:{}", self.username.as_ref().unwrap().trim(), self.get_pet().expect("No pet?"))))),
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string()),
            ("X-Apple-ADSID", adsid.clone()),
            ("X-Apple-GS-Token", base64::encode(format!("{}:{}", adsid, self.tokens["com.apple.gs.icloud.family.auth"].token))),
            ("X-Apple-I-Current-Application", "com.apple.systempreferences.AppleIDSettings".to_string()),
            ("X-Apple-I-Current-Application-Version", "1".to_string()),
            ("X-MMe-Client-Info", self.client_info.update_account_bundle_id.clone()),
            ("X-MMe-Country", "US".to_string()),
            ("X-MMe-Language", "en,en-US".to_string()),
            ("x-apple-i-device-type", "1".to_string()),
        ].into_iter().map(|(a, b)| (a.to_string(), b)));

        let header_map = HeaderMap::from_iter(map.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &Dictionary::new())?;

        let text = self.client.post("https://setup.icloud.com/setup/update_account_ui")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Accept-Language", "en-US,en")
            .header("Content-Type", "text/plist")
            .header("Origin", "null")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "cross-site")
            .headers(header_map)
            .body(buffer)
            .send().await?
            .text().await?;

        Ok(text)
    }

    pub async fn verify_2fa(&mut self, code: String) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false);
        // println!("Recieved code: {}", code);
        let res = self
            .client
            .get(self.session_auth_routes()?.validate_code)
            .headers(headers.await?)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send().await?;

        // A success-shaped body/token on an HTTP error cannot authenticate.
        // Check before parsing or replacing any of the account's token state.
        let status = res.status();
        debug!("Apple authentication HTTP: stage=trusted-device-verification; status={}", status.as_u16());
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(Error::AuthenticationRateLimited);
        }
        if status.is_server_error() {
            return Err(Error::AuthenticationServiceUnavailable(status.as_u16()));
        }
        if !status.is_success() {
            return Err(Error::AuthSrp);
        }

        let headers = res.headers().clone();

        let res: plist::Dictionary =
            plist::from_bytes(res.text().await?.as_bytes())?;

        Self::check_error_at_stage(AuthResponseStage::TrustedDeviceVerification, &res)?;

        // this endpoint is stupid
        // in the SMS 2fa endpoint, all tokens have format ID:TOKEN:DURATION:EXP (MS SINCE EPOCH)

        // here, well, the PE token has no duration OR expiration (ID:TOKEN)
        // the HB token has format ID:TOKEN:EXP
        // and the GS tokens (I have checked, god knows there's one that has a different format to mess with me) have format ID:TOKEN:DURATION
        // conclusion

        // so what to do? Don't trust apple at all. For PET, assume 300s if no duration. For everything else, guess whether the token is epoch time or duration
        // by seeing if the number is greater than 40 years in milliseconds. No token should reasonably have a duration longer than that (besides otherwise its in secs)

        self.tokens = headers.get_all("X-Apple-GS-Token").iter().chain(headers.get_all("X-Apple-HB-Token").iter()).map(|header| {
            let decoded = String::from_utf8(base64::decode(&header.as_bytes()).expect("Not base64!")).expect("Decoded not utf8!");
            let parts = decoded.split(":").collect::<Vec<&str>>();
            let exp = parts.get(2).map(|i| i.parse().expect("Bad expiration format?")).unwrap_or(31536000);

            let time = if exp > 40 * 365 * 24 * 60 * 60 * 1000 {
                // ms since epoch
                SystemTime::UNIX_EPOCH + Duration::from_millis(exp)
            } else {
                SystemTime::now() + Duration::from_secs(exp)
            };

            (parts[0].to_string(), FetchedToken {
                token: parts[1].to_string(),
                expiration: time,
            })
        }).collect();

        if let Some(pet) = headers.get("X-Apple-PE-Token") {
            self.parse_pet_header(pet.to_str().unwrap());
            return Ok(LoginState::LoggedIn);
        }

        Ok(LoginState::NeedsLogin)
    }

    pub async fn verify_sms_2fa(&mut self, code: String, mut body: VerifyBody) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await?;
        // println!("Recieved code: {}", code);

        body.security_code = Some(VerifyCode { code });

        let res = self
            .client
            .post(self.secondary_auth_endpoint("/verify/phone/securitycode")?)
            .headers(headers)
            .header("accept", "application/json")
            .json(&body)
            .send().await?;

        if res.status() != 200 {
            error!("SMS security-code verification failed");
            return Err(Error::Bad2faCode);
        }

        self.tokens = res.headers().get_all("X-Apple-GS-Token").iter().chain(res.headers().get_all("X-Apple-HB-Token").iter()).map(|header| {
            let decoded = String::from_utf8(base64::decode(&header.as_bytes()).expect("Not base64!")).expect("Decoded not utf8!");
            let parts = decoded.split(":").collect::<Vec<&str>>();

            // default one year; this won't bite me in the back at all...
            let exp = parts.get(3).or(parts.get(2)).map(|i| i.parse().expect("Bad expiration format?")).unwrap_or(31536000);
            let time = if exp > 40 * 365 * 24 * 60 * 60 * 1000 {
                // ms since epoch
                SystemTime::UNIX_EPOCH + Duration::from_millis(exp)
            } else {
                SystemTime::now() + Duration::from_secs(exp)
            };
            
            (parts[0].to_string(), FetchedToken {
                token: parts[1].to_string(),
                expiration: time,
            })
        }).collect();

        if let Some(pet) = res.headers().get("X-Apple-PE-Token") {
            self.parse_pet_header(pet.to_str().unwrap());
            return Ok(LoginState::LoggedIn);
        }

        Ok(LoginState::NeedsLogin)
    }

    fn parse_pet_header(&mut self, data: &str) {
        let decoded = String::from_utf8(base64::decode(data).unwrap()).unwrap();
        self.tokens.insert("com.apple.gs.idms.pet".to_string(), FetchedToken { token: decoded.split(":").nth(1).unwrap().to_string(), expiration: SystemTime::now() + Duration::from_secs(decoded.split(":").nth(2).map(|a| a.parse::<u64>().expect("Bad pet format")).unwrap_or(300)) });
    }

    fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
        let status = match res.get("Status") {
            Some(plist::Value::Dictionary(d)) => d,
            // Some responses carry ec/em at the top level without a Status dictionary.
            _ => &res,
        };

        let code = status
            .get("ec")
            .and_then(plist_i64)
            .ok_or(crate::Error::Parse)?;

        if code != 0 {
            let message = status
                .get("em")
                .and_then(|v| v.as_string())
                .unwrap_or("unknown");
            return Err(Error::AuthSrpWithMessage(code, message.to_owned()));
        }

        Ok(())
    }

    fn check_error_at_stage(stage: AuthResponseStage, res: &plist::Dictionary) -> Result<(), Error> {
        let result = Self::check_error(res);
        let status = res.get("Status").and_then(Value::as_dictionary).unwrap_or(res);
        let hsc = status.get("hsc").and_then(plist_i64);
        match &result {
            Ok(()) => debug!("Apple authentication status: {}", auth_status_summary(stage, Some(0), hsc)),
            Err(Error::AuthSrpWithMessage(code, _)) => {
                warn!("Apple authentication status: {}", auth_status_summary(stage, Some(*code), hsc));
            }
            Err(_) => warn!("Apple authentication status: {}", auth_status_summary(stage, None, hsc)),
        }
        // Preserve the existing error variant, message and retry behavior.
        result
    }

    // pub async 

    fn two_factor_identity(
        spd: Option<&plist::Dictionary>,
    ) -> Result<(&str, &str), crate::Error> {
        let spd = spd.ok_or(Error::TwoFactorSessionMissing)?;
        let dsid = spd
            .get("adsid")
            .and_then(plist::Value::as_string)
            .filter(|value| !value.is_empty())
            .ok_or(Error::TwoFactorSessionMissing)?;
        let token = spd
            .get("GsIdmsToken")
            .and_then(plist::Value::as_string)
            .filter(|value| !value.is_empty())
            .ok_or(Error::TwoFactorSessionMissing)?;
        Ok((dsid, token))
    }

    pub async fn build_2fa_headers(&self, sms: bool) -> Result<HeaderMap, crate::Error> {
        let (dsid, token) = Self::two_factor_identity(self.spd.as_ref())?;

        let identity_token = base64::encode(format!("{}:{}", dsid, token));

        let binding = self.auth_routes.as_ref().ok_or(Error::TwoFactorSessionMissing)?;
        let valid_anisette = self.get_anisette().await?;
        binding.require_matching(&valid_anisette.client_info)?;

        let mut headers = HeaderMap::new();
        valid_anisette
            .get_extra_headers()
            .iter()
            .for_each(|(k, v)| {
                headers.append(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            });

        if !sms {
            headers.insert(
                "Content-Type",
                HeaderValue::from_str("text/x-xml-plist").unwrap(),
            );
            headers.insert("Accept", HeaderValue::from_str("text/x-xml-plist").unwrap());
        }
        // headers.insert("User-Agent", HeaderValue::from_str("Xcode").unwrap());
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );
        #[cfg(all(test, feature = "remote-anisette-v3"))]
        if sms {
            if let Some(session) = &self.secondary_auth_session {
                headers.extend(session.lock().await.clone());
            }
        }

        Ok(headers)
    }
}

#[cfg(all(test, feature = "remote-anisette-v3"))]
#[path = "auth_probe.rs"]
mod auth_probe;

#[cfg(test)]
#[path = "public_transport_tests.rs"]
mod public_transport_tests;

#[cfg(test)]
#[path = "response_error_tests.rs"]
mod response_error_tests;

#[cfg(test)]
#[path = "auth_routing_integration_tests.rs"]
mod auth_routing_integration_tests;

#[cfg(test)]
mod tests {
    use super::{
        AppleAccount, map_login_state, spd_account_name, srp_complete_parts,
        srp_init_params, unexpected_response_summary, auth_status_summary, AuthResponseStage, LoginState,
    };
    use crate::Error;
    use plist::{Dictionary, Value};
    use reqwest::StatusCode;

    #[test]
    fn two_factor_identity_rejects_absent_or_incomplete_spd() {
        assert!(matches!(
            AppleAccount::<omnisette::DefaultAnisetteProvider>::two_factor_identity(None),
            Err(Error::TwoFactorSessionMissing)
        ));

        let mut spd = Dictionary::new();
        spd.insert("adsid".to_string(), Value::String("account-id".to_string()));
        assert!(matches!(
            AppleAccount::<omnisette::DefaultAnisetteProvider>::two_factor_identity(Some(&spd)),
            Err(Error::TwoFactorSessionMissing)
        ));

        spd.insert("GsIdmsToken".to_string(), Value::String(String::new()));
        assert!(matches!(
            AppleAccount::<omnisette::DefaultAnisetteProvider>::two_factor_identity(Some(&spd)),
            Err(Error::TwoFactorSessionMissing)
        ));
    }

    #[test]
    fn two_factor_identity_accepts_complete_spd() {
        let mut spd = Dictionary::new();
        spd.insert("adsid".to_string(), Value::String("account-id".to_string()));
        spd.insert(
            "GsIdmsToken".to_string(),
            Value::String("identity-token".to_string()),
        );

        assert_eq!(
            AppleAccount::<omnisette::DefaultAnisetteProvider>::two_factor_identity(Some(&spd))
                .expect("complete SPD should produce 2FA identity"),
            ("account-id", "identity-token")
        );
    }

    #[test]
    fn unexpected_html_response_reports_only_safe_page_classification() {
        let body = r#"<!doctype html><html><head><title>Update Apple Account</title></head>
            <body data-account="person@example.com">MOBILEME_TERMS_OF_SERVICE_UPDATE 123456</body></html>"#;
        let summary = unexpected_response_summary(
            "srp-complete", StatusCode::OK, "text/html; charset=utf-8",
            "https://gsa.apple.com/grandslam/GsService2", body,
        );
        assert!(summary.contains("stage=srp-complete"));
        assert!(summary.contains("status=200"));
        assert!(summary.contains("content_type=text/html"));
        assert!(summary.contains("page=terms-update"));
        assert!(summary.contains("final_origin=https://gsa.apple.com"));
        assert!(!summary.contains("GsService2"));
        assert!(!summary.contains("Update Apple Account"));
        assert!(!summary.contains("person@example.com"));
        assert!(!summary.contains("123456"));
    }

    #[test]
    fn unexpected_html_response_omits_sensitive_title() {
        let body = "<html><head><title>person@example.com 123456</title></head></html>";
        let summary = unexpected_response_summary(
            "srp-init", StatusCode::FORBIDDEN, "text/html",
            "https://idmsa.apple.com/appleauth/auth/signin", body,
        );
        assert!(!summary.contains("title="));
        assert!(!summary.contains("person@example.com"));
        assert!(!summary.contains("123456"));
    }

    #[test]
    fn unexpected_html_response_strips_url_credentials_path_query_and_fragment() {
        let summary = unexpected_response_summary(
            "srp-init", StatusCode::FORBIDDEN, "text/html",
            "https://synthetic-user:synthetic-password@gsa.apple.com/private-path?account=person@example.test#synthetic-code",
            "<html>Sign in</html>",
        );
        assert!(summary.contains("final_origin=https://gsa.apple.com;"));
        for private in ["synthetic-user", "synthetic-password", "private-path", "person@example.test", "synthetic-code"] {
            assert!(!summary.contains(private));
        }
        for invalid in ["not-a-url-with-synthetic-secret", "data:text/plain,synthetic-secret"] {
            let summary = unexpected_response_summary("srp-init", StatusCode::OK, "text/html", invalid, "<html></html>");
            assert!(summary.contains("final_origin=unknown-origin;"));
            assert!(!summary.contains("synthetic-secret"));
        }
    }

    fn wellformed_srp_init() -> Dictionary {
        let mut res = Dictionary::new();
        res.insert("s".to_string(), Value::Data(vec![1, 2, 3, 4]));
        res.insert("B".to_string(), Value::Data(vec![5, 6, 7, 8]));
        res.insert("i".to_string(), Value::Integer(4096.into()));
        res.insert("c".to_string(), Value::String("challenge".to_string()));
        res.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("ec".to_string(), Value::Integer(0.into())),
                ("em".to_string(), Value::String("Success".to_string())),
            ])),
        );
        res
    }

    fn wellformed_srp_complete() -> Dictionary {
        let mut res = Dictionary::new();
        res.insert("M2".to_string(), Value::Data(vec![9, 10, 11]));
        res.insert("spd".to_string(), Value::Data(vec![12, 13, 14]));
        res.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("ec".to_string(), Value::Integer(0.into())),
                ("em".to_string(), Value::String("Success".to_string())),
                ("au".to_string(), Value::String("trustedDeviceSecondaryAuth".to_string())),
            ])),
        );
        res
    }

    #[test]
    fn srp_init_accepts_wellformed_response() {
        let res = wellformed_srp_init();
        let init = srp_init_params(&res).expect("wellformed srp-init should parse");
        assert_eq!(init.salt, vec![1, 2, 3, 4]);
        assert_eq!(init.b_pub, vec![5, 6, 7, 8]);
        assert_eq!(init.iters, 4096);
        assert_eq!(init.c, "challenge");
    }

    #[test]
    fn srp_init_rejects_missing_fields_without_panicking() {
        for missing in ["s", "B", "i", "c"] {
            let mut res = wellformed_srp_init();
            res.remove(missing);
            assert!(
                matches!(srp_init_params(&res), Err(Error::MalformedSrpInit(_))),
                "missing {missing} should be MalformedSrpInit"
            );
        }
    }

    #[test]
    fn srp_init_rejects_wrong_types_and_negative_iters() {
        let mut res = wellformed_srp_init();
        res.insert("s".to_string(), Value::String("not-data".to_string()));
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("s"))));

        let mut res = wellformed_srp_init();
        res.insert("B".to_string(), Value::Integer(1.into()));
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("B"))));

        let mut res = wellformed_srp_init();
        res.insert("i".to_string(), Value::String("many".to_string()));
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("i"))));

        let mut res = wellformed_srp_init();
        res.insert("i".to_string(), Value::Integer((-1).into()));
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("i"))));

        let mut res = wellformed_srp_init();
        res.insert(
            "i".to_string(),
            Value::Integer((u64::from(u32::MAX) + 1).into()),
        );
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("i"))));

        let mut res = wellformed_srp_init();
        res.insert("c".to_string(), Value::Data(vec![0]));
        assert!(matches!(srp_init_params(&res), Err(Error::MalformedSrpInit("c"))));
    }

    #[test]
    fn srp_complete_accepts_wellformed_response() {
        let res = wellformed_srp_complete();
        let (m2, spd, status) =
            srp_complete_parts(&res).expect("wellformed srp-complete should parse");
        assert_eq!(m2, &[9, 10, 11]);
        assert_eq!(spd, &[12, 13, 14]);
        assert!(status.contains_key("ec"));
    }

    #[test]
    fn srp_complete_rejects_missing_or_mistyped_fields() {
        for missing in ["M2", "spd", "Status"] {
            let mut res = wellformed_srp_complete();
            res.remove(missing);
            assert!(
                matches!(srp_complete_parts(&res), Err(Error::MalformedSrpComplete(_))),
                "missing {missing} should be MalformedSrpComplete"
            );
        }

        let mut res = wellformed_srp_complete();
        res.insert("M2".to_string(), Value::String("not-data".to_string()));
        assert!(matches!(
            srp_complete_parts(&res),
            Err(Error::MalformedSrpComplete("M2"))
        ));

        let mut res = wellformed_srp_complete();
        res.insert("Status".to_string(), Value::String("not-a-dict".to_string()));
        assert!(matches!(
            srp_complete_parts(&res),
            Err(Error::MalformedSrpComplete("Status"))
        ));
    }

    #[test]
    fn auth_status_summary_distinguishes_fixed_stages_without_response_contents() {
        for (stage, expected) in [
            (AuthResponseStage::SrpInit, "srp-init"),
            (AuthResponseStage::SrpComplete, "srp-complete"),
            (AuthResponseStage::TrustedDeviceVerification, "trusted-device-verification"),
        ] {
            assert_eq!(auth_status_summary(stage, Some(-80045), None), format!("stage={expected}; code=-80045; hsc=absent-or-invalid"));
            assert_eq!(auth_status_summary(stage, Some(0), Some(409)), format!("stage={expected}; code=0; hsc=409"));
            assert_eq!(auth_status_summary(stage, None, Some(434)), format!("stage={expected}; code=missing-or-invalid; hsc=434"));
        }
    }

    #[test]
    fn auth_stage_diagnostics_preserve_server_rejection_and_success() {
        type Provider = omnisette::DefaultAnisetteProvider;
        for stage in [AuthResponseStage::SrpInit, AuthResponseStage::SrpComplete, AuthResponseStage::TrustedDeviceVerification] {
            let response = Dictionary::from_iter([(
                "Status".to_string(),
                Value::Dictionary(Dictionary::from_iter([
                    ("ec".to_string(), Value::Integer((-80045).into())),
                    ("hsc".to_string(), Value::Integer(434.into())),
                    ("em".to_string(), Value::String("synthetic account@example.test response".to_string())),
                    ("X-Apple-I-MD-DATA".to_string(), Value::String("synthetic-challenge-secret".to_string())),
                ])),
            )]);
            match AppleAccount::<Provider>::check_error_at_stage(stage, &response) {
                Err(Error::AuthSrpWithMessage(code, message)) => {
                    assert_eq!(code, -80045);
                    assert_eq!(message, "synthetic account@example.test response");
                    let diagnostic = auth_status_summary(stage, Some(code), Some(434));
                    assert!(!diagnostic.contains(&message));
                    assert!(!diagnostic.contains("account@example.test"));
                    assert!(!diagnostic.contains("synthetic-challenge-secret"));
                }
                other => panic!("expected unchanged server rejection, got {other:?}"),
            }
            let success = Dictionary::from_iter([("ec".to_string(), Value::Integer(0.into()))]);
            assert!(AppleAccount::<Provider>::check_error_at_stage(stage, &success).is_ok());
        }
    }

    #[test]
    fn auth_stage_diagnostics_preserve_malformed_status_failure() {
        type Provider = omnisette::DefaultAnisetteProvider;
        for invalid in [Value::String("synthetic-secret".to_string()), Value::Data(vec![1, 2, 3])] {
            let response = Dictionary::from_iter([("ec".to_string(), invalid)]);
            assert!(matches!(
                AppleAccount::<Provider>::check_error_at_stage(AuthResponseStage::SrpInit, &response),
                Err(Error::Parse)
            ));
        }
        assert!(matches!(
            AppleAccount::<Provider>::check_error_at_stage(AuthResponseStage::SrpComplete, &Dictionary::new()),
            Err(Error::Parse)
        ));
    }

    #[test]
    fn check_error_maps_server_status_without_panicking() {
        type Provider = omnisette::DefaultAnisetteProvider;
        let mut ok = Dictionary::new();
        ok.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("ec".to_string(), Value::Integer(0.into())),
                ("em".to_string(), Value::String("Success".to_string())),
            ])),
        );
        assert!(AppleAccount::<Provider>::check_error(&ok).is_ok());

        let mut failed = Dictionary::new();
        failed.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("ec".to_string(), Value::Integer((-8711).into())),
                ("em".to_string(), Value::String("Bad password".to_string())),
            ])),
        );
        match AppleAccount::<Provider>::check_error(&failed) {
            Err(Error::AuthSrpWithMessage(code, message)) => {
                assert_eq!(code, -8711);
                assert_eq!(message, "Bad password");
            }
            other => panic!("expected AuthSrpWithMessage, got {other:?}"),
        }

        let mut missing_code = Dictionary::new();
        missing_code.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::new()),
        );
        assert!(matches!(
            AppleAccount::<Provider>::check_error(&missing_code),
            Err(Error::Parse)
        ));

        let mut missing_message = Dictionary::new();
        missing_message.insert(
            "Status".to_string(),
            Value::Dictionary(Dictionary::from_iter([(
                "ec".to_string(),
                Value::Integer(1.into()),
            )])),
        );
        match AppleAccount::<Provider>::check_error(&missing_message) {
            Err(Error::AuthSrpWithMessage(code, _)) => assert_eq!(code, 1),
            other => panic!("expected AuthSrpWithMessage, got {other:?}"),
        }

        let unsigned_code = Dictionary::from_iter([
            ("ec".to_string(), Value::Integer(2u64.into())),
            ("em".to_string(), Value::String("Retry".to_string())),
        ]);
        match AppleAccount::<Provider>::check_error(&unsigned_code) {
            Err(Error::AuthSrpWithMessage(code, message)) => {
                assert_eq!(code, 2);
                assert_eq!(message, "Retry");
            }
            other => panic!("expected unsigned AuthSrpWithMessage, got {other:?}"),
        }
    }

    #[test]
    fn already_sent_challenge_is_not_treated_as_logged_in() {
        let mut status = Dictionary::from_iter([
            ("ec".to_string(), Value::Integer(0.into())),
            ("hsc".to_string(), Value::Integer(409.into())),
        ]);
        assert!(matches!(map_login_state(&status), LoginState::Needs2FAVerification));
        status.insert("au".to_string(), Value::String("secondaryAuth".to_string()));
        assert!(matches!(map_login_state(&status), LoginState::NeedsSMS2FA));
        status.remove("au");
        status.insert("hsc".to_string(), Value::Integer(200.into()));
        assert!(matches!(map_login_state(&status), LoginState::LoggedIn));
    }

    #[test]
    fn spd_account_name_and_login_state_mapping_are_preserved() {
        let mut spd = Dictionary::new();
        assert!(matches!(
            spd_account_name(&spd),
            Err(Error::MalformedSpd("acname"))
        ));
        spd.insert("acname".to_string(), Value::String(String::new()));
        assert!(matches!(
            spd_account_name(&spd),
            Err(Error::MalformedSpd("acname"))
        ));
        spd.insert("acname".to_string(), Value::String("user@example.com".to_string()));
        assert_eq!(spd_account_name(&spd).expect("acname"), "user@example.com");

        let mut status = Dictionary::new();
        status.insert("ec".to_string(), Value::Integer(0.into()));
        assert!(matches!(map_login_state(&status), LoginState::LoggedIn));

        status.insert(
            "au".to_string(),
            Value::String("trustedDeviceSecondaryAuth".to_string()),
        );
        assert!(matches!(map_login_state(&status), LoginState::NeedsDevice2FA));

        status.insert(
            "au".to_string(),
            Value::String("secondaryAuth".to_string()),
        );
        assert!(matches!(map_login_state(&status), LoginState::NeedsSMS2FA));

        status.insert(
            "au".to_string(),
            Value::String("customStep".to_string()),
        );
        match map_login_state(&status) {
            LoginState::NeedsExtraStep(step) => assert_eq!(step, "customStep"),
            other => panic!("expected NeedsExtraStep, got {other:?}"),
        }

        status.insert("au".to_string(), Value::Integer(1.into()));
        assert!(matches!(map_login_state(&status), LoginState::LoggedIn));
    }

    #[test]
    fn unavailable_verification_options_do_not_instruct_security_downgrade() {
        for error in [Error::FailedGetting2FAConfig, Error::HardwareKeyError] {
            let message = error.to_string();
            assert!(!message.to_lowercase().contains("disable"));
        }
        let options_failure = Error::FailedGetting2FAConfig.to_string();
        assert!(options_failure.contains("could not request an SMS"));
        assert!(options_failure.contains("Sign-in is still waiting for verification"));
        assert!(!options_failure.contains("trusted-device"));
        assert!(Error::HardwareKeyError.to_string().contains("trusted-device verification code"));
    }
}
