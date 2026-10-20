use crate::Error;
use omnisette::{AnisetteClient, AnisetteHeaders, AnisetteProvider, LoginClientInfo};
use plist::{Dictionary, Value};
use std::{collections::HashMap, time::SystemTime};

pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub client_info: LoginClientInfo,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub async fn new<T: AnisetteProvider>(provider: &mut AnisetteClient<T>, mut client_info: LoginClientInfo) -> Result<Self, crate::Error> {
        let base_headers = provider.get_headers().await?.clone();
        if let Some(info) = provider.provider.auth_client_info() {
            client_info.use_anisette_client_info(info);
        }

        Ok(AnisetteData { base_headers, client_info })
    }

    pub fn get_gsservice_headers(&self) -> HashMap<String, String> {
        // user must supply, content-type and accept
        // unaccounted headers: Accept-Encoding, Connection, Host
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-AK-Context-Type", self.client_info.ak_context_type.as_str()),
                ("X-Apple-Client-App-Name", &self.client_info.client_app_name),
                ("X-Apple-I-Client-Bundle-Id", &self.client_info.client_bundle_id),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info_akd),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("User-Agent", &self.client_info.akd_user_agent),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
        .collect()
    }

    pub fn get_postdata_headers(&self) -> HashMap<String, String> {
        // user must supply, content-type and accept
        // unaccounted headers: Accept-Encoding, Connection, Host
        // also unaccounted: X-Apple-I-UrlSwitch-Info, X-Apple-I-SRL-NO (opt), X-Apple-I-ROM (opt)
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("X-Apple-I-CDP-Status", "true"),
                ("X-Apple-I-OT-Status", "true"),
                ("User-Agent", &self.client_info.akd_user_agent),
                ("X-Apple-Requested-Partition", "0"),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info_akd),
                ("X-Apple-I-CK-Presence", "true"),
                ("X-Apple-I-DeviceUserMode", "0"),
                ("X-Apple-AK-DataRecoveryService-Status", "1"),
                ("X-Apple-I-TimeZone-Offset", "0"),
                ("X-Apple-I-Service-Type", "itunesstore"),
                ("x-apple-i-device-type", "1"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
        .collect()
    }

    pub fn get_circle_headers(&self) -> HashMap<String, String> {
        // user must supply, content-type and accept
        // unaccounted headers: Accept-Encoding, Connection, Host
        // also unaccounted: X-Apple-I-UrlSwitch-Info, X-Apple-I-SRL-NO (opt), X-Apple-I-ROM (opt)
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("User-Agent", &self.client_info.akd_user_agent),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info_akd),
                ("X-Apple-I-DeviceUserMode", "0"),
                ("X-Apple-I-TimeZone-Offset", "0"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
        .collect()
    }

    pub fn get_generate_headers(&self) -> HashMap<String, String> {
        // user must supply, content-type and accept
        // unaccounted headers: Accept-Encoding, Connection, Host
        // also unaccounted: X-Apple-I-UrlSwitch-Info, X-Apple-I-SRL-NO (opt), X-Apple-I-ROM (opt)
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("User-Agent", &self.client_info.akd_user_agent),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info_akd),
                ("X-Apple-I-DeviceUserMode", "0"),
                ("X-Apple-I-TimeZone-Offset", "0"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
        .collect()
    }

    pub fn get_takedown_headers(&self) -> HashMap<String, String> {
        // user must supply, content-type and accept
        // unaccounted headers: Accept-Encoding, Connection, Host
        // also unaccounted: X-Apple-I-UrlSwitch-Info, X-Apple-I-SRL-NO (opt), X-Apple-I-ROM (opt)
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Mme-Device-Id"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("User-Agent", &self.client_info.akd_user_agent),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info_akd),
                ("X-Apple-I-DeviceUserMode", "0"),
                ("X-Apple-AK-DataRecoveryService-Status", "1"),
                ("X-Apple-I-TimeZone-Offset", "0"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
        .collect()
    }

    pub fn get_cpd_data(&self, request: &str) -> Dictionary {
        const ACCEPTABLE_HEADERS: &[&'static str] = &[
            "X-Apple-I-Client-Time",
            "X-Apple-I-MD",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id",
        ];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .map(|(a, b)| (a, Value::String(b)))
            .chain(self.client_info.push_token.as_ref().map(|v| ("ptkn".to_string(), Value::String(v.clone()))).into_iter())
            .chain([
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("X-Apple-I-Request-UUID", request),
                ("X-Apple-Requested-Partition", "0"),
                ("X-Apple-Security-Upgrade-Context", "com.apple.authkit.generic"),
                ("capp", &self.client_info.client_app_name),
                ("cbid", &self.client_info.client_bundle_id),
                ("cou", "US"),
                ("loc", "en_US"),
                ("svct", &self.client_info.ak_context_type),
                
            ].into_iter().map(|(a, b)| (a.to_string(), Value::String(b.to_string()))))
            .chain([
                ("X-Apple-Offer-Security-Upgrade", Value::Boolean(true)),
                ("at", Value::Integer(0.into())),
                ("bootstrap", Value::Boolean(true)),
                ("ckgen", Value::Boolean(true)),
                ("fcd", Value::Boolean(true)),
                ("icdrsDisabled", Value::Boolean(false)),
                ("icscrec", Value::Boolean(true)),
                ("pbe", Value::Boolean(false)),
                ("prkgen", Value::Boolean(true)),
                ("webAccessEnabled", Value::Boolean(false)),
            ].into_iter().map(|(a, b)| (a.to_string(), b))
        ).chain(self.client_info.hardware_headers.clone().into_iter().map(|(a, b)| (a, Value::String(b)))).collect()
    }

    pub fn get_extra_headers(&self) -> HashMap<String, String> {
        // unaccounted headers: Accept-Encoding, Connection, Host, content-type
        const ACCEPTABLE_HEADERS: &[&'static str] = &["X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-M", "X-Apple-I-MD", "X-Mme-Device-Id"];
        self.base_headers.clone().into_iter().filter(|(key, _)| ACCEPTABLE_HEADERS.contains(&key.as_str()))
            .chain([
                ("X-Apple-Client-App-Name", self.client_info.client_app_name.as_str()),
                ("X-Apple-I-Client-Bundle-Id", &self.client_info.client_bundle_id),
                ("X-MMe-Client-Info", &self.client_info.mme_client_info),
                ("X-Apple-I-CDP-Circle-Status", "false"),
                ("X-Apple-I-ICSCREC", "true"),
                ("User-Agent", &self.client_info.browser_user_agent),
                ("Sec-Fetch-Site", "same-origin"), // diff
                ("X-Apple-Requested-Partition", "0"),
                ("X-Apple-I-DeviceUserMode", "0"),
                ("X-Apple-I-Locale", "en_US"),
                ("X-Apple-Security-Upgrade-Context", "com.apple.authkit.generic"),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("X-Apple-I-PRK-Gen", "true"),
                ("Sec-Fetch-Mode", "cors"), // diff
                ("X-Apple-I-TimeZone", "UTC"),
                ("X-Apple-I-OT-Status", "false"),
                ("X-Apple-I-TimeZone-Offset", "0"), // check, -21600 denver
                ("X-MMe-Country", "US"),
                ("X-Apple-I-CDP-Status", "false"),
                ("X-Apple-I-Device-Configuration-Mode", "0"),
                ("Sec-Fetch-Dest", "empty"), // diff
                ("X-Apple-AK-Context-Type", self.client_info.ak_context_type.as_str()),
                ("X-Apple-I-CFU-State", "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8YXJyYXkvPgo8L3BsaXN0Pgo="),
            ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())))
            .chain(self.client_info.hardware_headers.clone())
        .collect()
    }
}

#[cfg(test)]
mod provider_client_info_tests {
    use super::*;
    use omnisette::{AnisetteClientInfo, AnisetteError};

    struct FixtureProvider {
        metadata: Option<AnisetteClientInfo>,
        calls: usize,
        fail: bool,
    }

    impl AnisetteProvider for FixtureProvider {
        async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
            self.calls += 1;
            if self.fail { return Err(AnisetteError::Misc); }
            Ok(HashMap::from_iter([
                ("X-Apple-I-MD".into(), "synthetic-proof".into()),
                ("X-Mme-Device-Id".into(), "synthetic-provider-id".into()),
                ("X-Mme-Client-Info".into(), "synthetic-activation-client".into()),
            ]))
        }
        fn auth_client_info(&self) -> Option<&AnisetteClientInfo> { self.metadata.as_ref() }
    }

    fn activation_info() -> LoginClientInfo {
        LoginClientInfo {
            ak_context_type: "imessage".into(),
            client_app_name: "Messages".into(),
            client_bundle_id: "com.apple.MobileSMS".into(),
            mme_client_info: "synthetic-activation-client".into(),
            mme_client_info_akd: "synthetic-activation-akd".into(),
            akd_user_agent: "synthetic-activation-agent".into(),
            browser_user_agent: "synthetic-browser-agent".into(),
            hardware_headers: HashMap::from_iter([("X-Apple-I-SRL-NO".into(), "synthetic-serial".into())]),
            push_token: Some("synthetic-aps-token".into()),
            update_account_bundle_id: "synthetic-recovery-context".into(),
        }
    }

    #[tokio::test]
    async fn provider_client_metadata_follows_adi_without_changing_activation() {
        let original = activation_info();
        let mut provider = AnisetteClient::new(FixtureProvider {
            metadata: Some(AnisetteClientInfo { client_info: "synthetic-android-auth".into(), user_agent: "synthetic-provider-agent".into() }),
            calls: 0, fail: false,
        });
        // Cached proofs must retain the same provider metadata too.
        for _ in 0..2 {
            let data = AnisetteData::new(&mut provider, original.clone()).await.unwrap();
            assert_eq!(data.get_gsservice_headers()["X-MMe-Client-Info"], "synthetic-android-auth");
            assert_eq!(data.get_gsservice_headers()["User-Agent"], "synthetic-provider-agent");
            assert_eq!(data.get_extra_headers()["X-MMe-Client-Info"], "synthetic-android-auth");
            assert_eq!(data.get_postdata_headers()["X-MMe-Client-Info"], "synthetic-android-auth");
            assert_eq!(data.base_headers["X-Mme-Client-Info"], "synthetic-activation-client");
            assert_eq!(data.get_gsservice_headers()["X-Apple-I-MD"], "synthetic-proof");
            let cpd = data.get_cpd_data("synthetic-request");
            assert_eq!(cpd["X-Apple-I-SRL-NO"].as_string(), Some("synthetic-serial"));
            assert_eq!(cpd["ptkn"].as_string(), Some("synthetic-aps-token"));
            assert_eq!(cpd["X-Mme-Device-Id"].as_string(), Some("synthetic-provider-id"));
            assert_eq!(data.client_info.ak_context_type, original.ak_context_type);
            assert_eq!(data.client_info.client_app_name, original.client_app_name);
            assert_eq!(data.client_info.client_bundle_id, original.client_bundle_id);
            assert_eq!(data.client_info.hardware_headers, original.hardware_headers);
            assert_eq!(data.client_info.browser_user_agent, original.browser_user_agent);
            assert_eq!(data.client_info.update_account_bundle_id, original.update_account_bundle_id);
        }
        assert_eq!(provider.provider.calls, 1);
        assert_eq!(original.mme_client_info, "synthetic-activation-client");
    }

    #[tokio::test]
    async fn provider_without_metadata_keeps_native_client_info() {
        let mut provider = AnisetteClient::new(FixtureProvider { metadata: None, calls: 0, fail: false });
        let original = activation_info();
        let data = AnisetteData::new(&mut provider, original.clone()).await.unwrap();
        assert_eq!(data.client_info.mme_client_info, original.mme_client_info);
        assert_eq!(data.client_info.mme_client_info_akd, original.mme_client_info_akd);
        assert_eq!(data.client_info.akd_user_agent, original.akd_user_agent);
    }

    #[tokio::test]
    async fn provider_failure_never_produces_authentication_headers() {
        let mut provider = AnisetteClient::new(FixtureProvider { metadata: None, calls: 0, fail: true });
        assert!(AnisetteData::new(&mut provider, activation_info()).await.is_err());
        assert_eq!(provider.provider.calls, 1);
    }
}
