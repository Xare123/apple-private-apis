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
use log::{debug, error, info, warn};
use tokio::sync::Mutex;
use uuid::Uuid;

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");

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

fn safe_response_url(response: &Response) -> String {
    let url = response.url();
    format!("{}://{}", url.scheme(), url.host_str().unwrap_or("unknown-host"))
}

fn unexpected_response_summary(stage: &str, status: reqwest::StatusCode, content_type: &str, final_url: &str, body: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(body.as_bytes()));
    format!(
        "stage={stage}; status={}; content_type={}; final_origin={final_url}; body_kind=html; page={}; bytes={}; sha256={}",
        status.as_u16(), content_type.split(';').next().unwrap_or("unknown"), classify_html_page(body),
        body.len(), &digest[..16]
    )
}

async fn parse_response(stage: &str, res: Result<Response, reqwest::Error>) -> Result<plist::Dictionary, crate::Error> {
    let response = res?;
    let status = response.status();
    let final_url = safe_response_url(&response);
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
        _ => LoginState::LoggedIn,
    }
}

impl<T: AnisetteProvider> AppleAccount<T> {

    pub fn new_with_anisette(client_info: LoginClientInfo, anisette:  ArcAnisetteClient<T>) -> Result<Self, crate::Error> {
        let client = ClientBuilder::new()
            .cookie_store(true)
            .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
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

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        hashed_password: &[u8],
    ) -> Result<LoginState, Error> {
        let srp_client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        self.username = Some(username.to_string());

        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_gsservice_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));

        let request_id = Uuid::new_v4().to_string().to_uppercase();

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: valid_anisette.get_cpd_data(&request_id),
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
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response("srp-init", res).await?;
        Self::check_error(&res)?;
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
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response("srp-complete", res).await?;
        Self::check_error(&res)?;
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

    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, crate::Error> {
        let headers = self.build_2fa_headers(false);

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers.await?)
            .send().await?;

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
            .put("https://gsa.apple.com/auth/verify/phone")
            .headers(headers.await?)
            .header("Accept", "application/json")
            .json(&body)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true);

        let req = self.client
            .get("https://gsa.apple.com/auth")
            .headers(headers.await?)
            .header("Accept", "application/json")
            .send().await?;
        let status = req.status().as_u16();
        if status == 403 {
            warn!("Failed to retrieve GSA authentication extras (HTTP 403)");
            return Err(Error::FailedGetting2FAConfig);
        }
        let resp = req.bytes().await?;
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
                    id: new_state.trusted_phone_numbers.first().unwrap().id
                },
                mode: "sms".to_string(),
                security_code: None
            }));
        }

        Ok(new_state)
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
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers.await?)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send().await?;

        let headers = res.headers().clone();

        let res: plist::Dictionary =
            plist::from_bytes(res.text().await?.as_bytes())?;

        Self::check_error(&res)?;

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
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
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

        let valid_anisette = self.get_anisette().await?;

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


        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppleAccount, map_login_state, spd_account_name, srp_complete_parts,
        srp_init_params, unexpected_response_summary, LoginState,
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
}
