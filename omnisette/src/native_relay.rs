//! Transient native-iPhone authentication over the existing authenticated relay.
//! Never serialize these types or fall back to a different proof device.
use std::{collections::HashMap, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use reqwest::{redirect::Policy, Client, Url};
use serde::{Deserialize, Deserializer};

use crate::{AnisetteClientInfo, AnisetteError, AnisetteProvider};

const MAX_RESPONSE: usize = 65_536;
const MAX_BUNDLE: usize = 32_768;
// Local transport policy, not a claimed Apple acceptance tolerance.
const MAX_CLOCK_SKEW_SECONDS: i64 = 120;

#[derive(Clone)]
pub struct NativeRelayIdentity {
    pub device_id: String,
    pub serial_number: String,
    pub hardware_version: String,
}

#[derive(Clone)]
pub struct NativeRelayConfig {
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
    pub identity: NativeRelayIdentity,
}

#[derive(Deserialize)]
struct VersionResponse {
    versions: VersionWire,
}

#[derive(Deserialize)]
struct VersionWire {
    unique_device_id: String,
    serial_number: String,
    hardware_version: String,
    ob_auth_bundle_v1: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: u32,
    headers: Headers,
    native_empty_qualifier: String,
    elapsed_ms: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Headers {
    #[serde(rename = "X-Apple-I-MD")]
    otp: String,
    #[serde(rename = "X-Apple-I-MD-M")]
    machine: String,
    #[serde(
        rename = "X-Apple-I-MD-LU",
        default,
        deserialize_with = "present_string"
    )]
    local_user: Option<String>,
    #[serde(rename = "X-Apple-I-MD-RINFO")]
    routing: String,
    #[serde(rename = "X-Mme-Device-Id")]
    device: String,
    #[serde(rename = "X-Mme-Client-Info")]
    client: String,
    #[serde(rename = "X-Apple-I-Client-Time")]
    time: String,
    #[serde(rename = "X-Apple-I-SRL-NO")]
    serial: String,
    #[serde(rename = "User-Agent")]
    agent: String,
    #[serde(
        rename = "X-Apple-Locale",
        default,
        deserialize_with = "present_string"
    )]
    locale: Option<String>,
    #[serde(
        rename = "X-Apple-I-TimeZone",
        default,
        deserialize_with = "present_string"
    )]
    timezone: Option<String>,
}

fn present_string<'de, D: Deserializer<'de>>(input: D) -> Result<Option<String>, D::Error> {
    String::deserialize(input).map(Some)
}

fn unavailable(reason: &'static str) -> AnisetteError {
    AnisetteError::NativeRelayUnavailable(reason)
}

fn valid_agent(value: &str) -> bool {
    fn version(value: &str) -> bool {
        let parts: Vec<_> = value.split('.').collect();
        (2..=6).contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|b| b.is_ascii_digit()))
    }
    value
        .strip_prefix("akd/1.0 CFNetwork/")
        .and_then(|rest| rest.split_once(" Darwin/"))
        .is_some_and(|(network, kernel)| version(network) && version(kernel))
}

fn proof(value: &str) -> Result<Vec<u8>, AnisetteError> {
    if value.len() > 5464 {
        return Err(unavailable("invalid-proof"));
    }
    STANDARD
        .decode(value)
        .ok()
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(|| unavailable("invalid-proof"))
}

struct Accepted {
    headers: HashMap<String, String>,
    qualifier: Vec<u8>,
    client_info: AnisetteClientInfo,
}

fn decode(
    bytes: &[u8],
    identity: &NativeRelayIdentity,
    now: i64,
) -> Result<Accepted, AnisetteError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE {
        return Err(unavailable("response-size"));
    }
    let wire: VersionResponse = serde_json::from_slice(bytes)
        .map_err(|_| unavailable("native-bundle-missing-or-invalid"))?;
    let v = wire.versions;
    if identity.device_id.is_empty()
        || identity.serial_number.is_empty()
        || identity.hardware_version.is_empty()
        || !v.unique_device_id.eq_ignore_ascii_case(&identity.device_id)
        || v.serial_number != identity.serial_number
        || v.hardware_version != identity.hardware_version
    {
        return Err(unavailable("device-identity-mismatch"));
    }
    if v.ob_auth_bundle_v1.is_empty() || v.ob_auth_bundle_v1.len() > MAX_BUNDLE {
        return Err(unavailable("bundle-size"));
    }
    let raw = STANDARD
        .decode(&v.ob_auth_bundle_v1)
        .map_err(|_| unavailable("bundle-format"))?;
    let bundle: Bundle = serde_json::from_slice(&raw).map_err(|_| unavailable("bundle-format"))?;
    if bundle.schema != 1 || bundle.elapsed_ms > 45_000 {
        return Err(unavailable("bundle-version-or-duration"));
    }
    let qualifier = proof(&bundle.native_empty_qualifier)?;
    let h = bundle.headers;
    if !h.device.eq_ignore_ascii_case(&identity.device_id)
        || h.serial != identity.serial_number
        || !h
            .client
            .contains(&format!("<{}>", identity.hardware_version))
        || !valid_agent(&h.agent)
        || h.routing.len() > 20
        || !h.routing.bytes().all(|b| b.is_ascii_digit())
        || h.routing.parse::<u64>().ok().filter(|v| *v > 0).is_none()
    {
        return Err(unavailable("header-identity-or-context"));
    }
    proof(&h.otp)?;
    proof(&h.machine)?;
    let time = DateTime::parse_from_rfc3339(&h.time)
        .map_err(|_| unavailable("native-time"))?
        .timestamp();
    if now.abs_diff(time) > MAX_CLOCK_SKEW_SECONDS as u64 {
        return Err(unavailable("native-time-skew"));
    }
    let client_info = AnisetteClientInfo {
        client_info: h.client.clone(),
        user_agent: h.agent.clone(),
    };
    let mut headers = HashMap::from_iter([
        ("X-Apple-I-MD".into(), h.otp),
        ("X-Apple-I-MD-M".into(), h.machine),
        ("X-Apple-I-MD-RINFO".into(), h.routing),
        ("X-Mme-Device-Id".into(), h.device),
        ("X-Mme-Client-Info".into(), h.client),
        ("X-Apple-I-Client-Time".into(), h.time),
        ("X-Apple-I-SRL-NO".into(), h.serial),
        ("User-Agent".into(), h.agent),
    ]);
    if let Some(value) = h.local_user {
        headers.insert("X-Apple-I-MD-LU".into(), value);
    }
    if let Some(value) = h.locale {
        headers.insert("X-Apple-Locale".into(), value);
    }
    if let Some(value) = h.timezone {
        headers.insert("X-Apple-I-TimeZone".into(), value);
    }
    if headers
        .values()
        .any(|v| v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (32..=126).contains(&b)))
    {
        return Err(unavailable("invalid-header"));
    }
    Ok(Accepted {
        headers,
        qualifier,
        client_info,
    })
}

pub struct NativeRelayProvider {
    config: NativeRelayConfig,
    info: Option<AnisetteClientInfo>,
}

impl NativeRelayProvider {
    pub fn new(config: NativeRelayConfig) -> Self {
        Self { config, info: None }
    }

    fn endpoint(&self) -> Result<Url, AnisetteError> {
        let mut url = Url::parse(&self.config.host).map_err(|_| unavailable("relay-origin"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(unavailable("relay-origin"));
        }
        url.set_path("/api/v1/bridge/get-version-info");
        Ok(url)
    }

    async fn fetch(&mut self) -> Result<Accepted, AnisetteError> {
        self.info = None;
        let endpoint = self.endpoint()?;
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(55))
            .build()
            .map_err(|_| unavailable("transport-init"))?;
        let mut request = client
            .post(endpoint)
            .bearer_auth(&self.config.code)
            .header("Content-Length", "0")
            .header("Cache-Control", "no-cache, no-store");
        if let Some(token) = &self.config.beeper_token {
            request = request.header("X-Beeper-Access-Token", token);
        }
        let mut response = request.send().await.map_err(|_| unavailable("transport"))?;
        if response.status().as_u16() != 200 {
            return Err(AnisetteError::NativeRelayHttp(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE as u64)
        {
            return Err(unavailable("response-size"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| unavailable("response-read"))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE {
                return Err(unavailable("response-size"));
            }
            body.extend_from_slice(&chunk);
        }
        let accepted = decode(&body, &self.config.identity, Utc::now().timestamp())?;
        self.info = Some(accepted.client_info.clone());
        Ok(accepted)
    }
}

impl AnisetteProvider for NativeRelayProvider {
    fn auth_client_info(&self) -> Option<&AnisetteClientInfo> {
        self.info.as_ref()
    }

    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        // One POST per fresh request. Never load proof values from disk/cache.
        Ok(self.fetch().await?.headers)
    }

    async fn native_account_validation_data(&mut self) -> Result<Option<Vec<u8>>, AnisetteError> {
        // This is ACAccountStore signing, not activation/IDS NAC data. It is
        // consumed only by the account delegates call, with fresh ADI afterward.
        Ok(Some(self.fetch().await?.qualifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn identity() -> NativeRelayIdentity {
        NativeRelayIdentity {
            device_id: "synthetic-device".into(),
            serial_number: "synthetic-serial".into(),
            hardware_version: "iPhone9,3".into(),
        }
    }
    fn bundle() -> Value {
        json!({"schema":1,"elapsed_ms":27,"native_empty_qualifier":STANDARD.encode([3;261]),"headers":{
            "X-Apple-I-MD":STANDARD.encode([1;16]),"X-Apple-I-MD-M":STANDARD.encode([2;16]),
            "X-Apple-I-MD-RINFO":"17106176","X-Mme-Device-Id":"SYNTHETIC-DEVICE",
            "X-Mme-Client-Info":"<iPhone9,3> <iPhone OS;15.7.9;19H365> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            "X-Apple-I-Client-Time":"2026-10-20T12:00:00Z","X-Apple-I-SRL-NO":"synthetic-serial",
            "User-Agent":"akd/1.0 CFNetwork/1335.0.3.1 Darwin/21.6.0"}})
    }
    fn wire(bundle: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"versions":{"unique_device_id":"synthetic-device","serial_number":"synthetic-serial",
            "hardware_version":"iPhone9,3","software_name":"iPhone OS","software_version":"15.7.9",
            "software_build_id":"19H365","ob_auth_bundle_v1":STANDARD.encode(serde_json::to_vec(&bundle).unwrap())}})).unwrap()
    }
    fn now() -> i64 {
        DateTime::parse_from_rfc3339("2026-10-20T12:00:00Z")
            .unwrap()
            .timestamp()
    }

    #[test]
    fn native_relay_accepts_matching_physical_context_and_genuine_absent_lu() {
        let accepted = decode(&wire(bundle()), &identity(), now()).unwrap();
        assert_eq!(accepted.qualifier.len(), 261);
        assert!(!accepted.headers.contains_key("X-Apple-I-MD-LU"));
        assert!(accepted.client_info.client_info.contains("iPhone9,3"));
    }
    #[test]
    fn native_relay_optional_headers_are_preserved_but_null_and_unknown_are_rejected() {
        for name in ["X-Apple-I-MD-LU", "X-Apple-Locale", "X-Apple-I-TimeZone"] {
            let mut value = bundle();
            value["headers"][name] = json!("native-value");
            assert_eq!(
                decode(&wire(value), &identity(), now()).unwrap().headers[name],
                "native-value"
            );
            let mut value = bundle();
            value["headers"][name] = Value::Null;
            assert!(decode(&wire(value), &identity(), now()).is_err());
        }
        let mut value = bundle();
        value["headers"]["Authorization"] = json!("not-allowed");
        assert!(decode(&wire(value), &identity(), now()).is_err());
    }
    #[test]
    fn native_relay_refuses_identity_changes_at_both_boundaries() {
        for field in ["unique_device_id", "serial_number", "hardware_version"] {
            let mut value: Value = serde_json::from_slice(&wire(bundle())).unwrap();
            value["versions"][field] = json!("different");
            assert!(decode(&serde_json::to_vec(&value).unwrap(), &identity(), now()).is_err());
        }
        for field in ["X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-Mme-Client-Info"] {
            let mut value = bundle();
            value["headers"][field] = json!("different");
            assert!(decode(&wire(value), &identity(), now()).is_err());
        }
    }
    #[test]
    fn native_relay_refuses_invalid_routing_proof_agent_and_header_injection() {
        for (name, value) in [
            ("X-Apple-I-MD", "not-base64"),
            ("X-Apple-I-MD-M", ""),
            ("X-Apple-I-MD-RINFO", "0"),
            ("X-Apple-I-MD-RINFO", "-1"),
            ("X-Apple-I-MD-RINFO", "18446744073709551616"),
            ("User-Agent", "borrowed-Mac-agent"),
            ("X-Mme-Client-Info", "<iPhone9,3>\r\nInjected: bad"),
        ] {
            let mut item = bundle();
            item["headers"][name] = json!(value);
            assert!(decode(&wire(item), &identity(), now()).is_err());
        }
    }
    #[test]
    fn native_relay_time_and_generation_bounds_are_explicit_transport_policy() {
        assert!(decode(&wire(bundle()), &identity(), now() + 120).is_ok());
        for offset in [-121, 121] {
            assert!(decode(&wire(bundle()), &identity(), now() + offset).is_err());
        }
        for value in [json!(45001), json!(-1), json!(1.5), Value::Null] {
            let mut item = bundle();
            item["elapsed_ms"] = value;
            assert!(decode(&wire(item), &identity(), now()).is_err());
        }
    }
    #[test]
    fn native_relay_requires_versioned_complete_bounded_bundle() {
        for key in ["schema", "headers", "native_empty_qualifier", "elapsed_ms"] {
            let mut item = bundle();
            item.as_object_mut().unwrap().remove(key);
            assert!(decode(&wire(item), &identity(), now()).is_err());
        }
        for value in [json!(0), json!(2), json!(true)] {
            let mut item = bundle();
            item["schema"] = value;
            assert!(decode(&wire(item), &identity(), now()).is_err());
        }
        let mut item = bundle();
        item["native_empty_qualifier"] = json!("");
        assert!(decode(&wire(item), &identity(), now()).is_err());
        assert!(decode(&vec![b'x'; MAX_RESPONSE + 1], &identity(), now()).is_err());
        let mut value: Value = serde_json::from_slice(&wire(bundle())).unwrap();
        value["versions"]
            .as_object_mut()
            .unwrap()
            .remove("ob_auth_bundle_v1");
        assert!(decode(&serde_json::to_vec(&value).unwrap(), &identity(), now()).is_err());
    }
    #[test]
    fn native_relay_rejects_credentials_paths_redirect_targets_and_plaintext_origins() {
        for host in [
            "http://relay.example",
            "https://user:secret@relay.example",
            "https://relay.example/path",
            "https://relay.example?code=secret",
            "https://relay.example/#secret",
        ] {
            let provider = NativeRelayProvider::new(NativeRelayConfig {
                host: host.into(),
                code: "synthetic-code".into(),
                beeper_token: None,
                identity: identity(),
            });
            assert!(provider.endpoint().is_err());
        }
        let provider = NativeRelayProvider::new(NativeRelayConfig {
            host: "https://relay.example/".into(),
            code: "synthetic-code".into(),
            beeper_token: None,
            identity: identity(),
        });
        assert_eq!(
            provider.endpoint().unwrap().path(),
            "/api/v1/bridge/get-version-info"
        );
    }
    #[tokio::test]
    async fn native_relay_failed_refresh_clears_metadata_without_using_another_provider() {
        let mut provider = NativeRelayProvider::new(NativeRelayConfig {
            host: "invalid-origin".into(),
            code: "synthetic-code".into(),
            beeper_token: None,
            identity: identity(),
        });
        provider.info = Some(AnisetteClientInfo {
            client_info: "old-context".into(),
            user_agent: "old-agent".into(),
        });
        assert!(provider.get_anisette_headers().await.is_err());
        assert!(provider.auth_client_info().is_none());
        assert!(provider.native_account_validation_data().await.is_err());
        assert!(provider.auth_client_info().is_none());
    }
}
