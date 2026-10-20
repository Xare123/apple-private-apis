//! A library to generate "anisette" data. Docs are coming soon.
//!
//! If you want an async API, enable the `async` feature.
//!
//! If you want remote anisette, make sure the `remote-anisette` feature is enabled. (it's currently on by default)

use std::collections::HashMap;
use std::io;
#[cfg(any(
    feature = "remote-anisette-v3",
    feature = "remote-clearadi",
    target_os = "macos"
))]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
#[cfg(feature = "remote-clearadi")]
use anisette_clearadi::ClearADIClient;
#[cfg(target_os = "macos")]
use aos_kit::AOSKitAnisetteProvider;
use thiserror::Error;
use tokio::sync::Mutex;

#[cfg(feature = "remote-anisette-v3")]
use crate::remote_anisette_v3::RemoteAnisetteProviderV3;

#[cfg(feature = "remote-clearadi")]
pub mod anisette_clearadi;

#[cfg(feature = "remote-anisette-v3")]
pub mod remote_anisette_v3;

pub mod native_relay;

#[cfg(target_os = "macos")]
pub mod aos_kit;

#[allow(dead_code)]
pub struct AnisetteHeaders;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AnisetteError {
    #[allow(dead_code)]
    #[error("Unsupported device")]
    UnsupportedDevice,
    #[error("Invalid argument {0}")]
    InvalidArgument(String),
    #[error("Anisette not provisioned!")]
    AnisetteNotProvisioned,
    #[error("Plist serialization error {0}")]
    PlistError(#[from] plist::Error),
    #[error("Request Error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Provisioning socket error {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::error::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("JSON error {0}")]
    SerdeError(#[from] serde_json::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Anisette provisioning server error: {0}")]
    ProvisioningServerError(String),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Anisette provisioning socket closed before completion")]
    ProvisioningSocketClosed,
    #[error("IO error {0}")]
    IOError(#[from] io::Error),
    #[error("Invalid library format")]
    InvalidLibraryFormat,
    #[error("Misc")]
    Misc,
    #[error("Missing Libraries")]
    MissingLibraries,
    #[error("The authentication provider returned invalid client metadata. Saved activation and account data have not been reset.")]
    InvalidClientMetadata,
    #[error("The iPhone relay could not provide native authentication ({0}). Keep the updated relay open and connected. Saved activation and account data have not been reset.")]
    NativeRelayUnavailable(&'static str),
    #[error("The iPhone relay authentication request failed (HTTP {0}). Check its connection and relay access. Saved activation and account data have not been reset.")]
    NativeRelayHttp(u16),
    #[cfg(feature = "remote-clearadi")]
    #[error("ClearADI Error {0}")]
    ClearADIError(#[from] clearadi::ClearAdiError),
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error)
}

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

pub const DEFAULT_ANISETTE_URL_V3: &str = "https://ani.sidestore.io";

pub trait AnisetteProvider {
    fn get_anisette_headers(&mut self) -> impl std::future::Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send;
    /// Describes the library that produced the ADI proof, not the user's IDS
    /// activation hardware. Available after a successful header request.
    fn auth_client_info(&self) -> Option<&AnisetteClientInfo> { None }
    /// Optional service context from this proof provider. Existing providers
    /// leave delegate context to the activation configuration. The isolated
    /// Windows diagnostic opts in without changing proof or hardware identity.
    fn delegate_client_info(&self, _service: &str) -> Option<String> { None }
    /// Optional existing proof-device identifier for the delegate request body.
    /// Default providers preserve the original per-request client identifier.
    fn delegate_client_id(&self) -> Option<String> { None }
    /// Test-only discriminator: omit the delegate validation header while
    /// keeping proof, identity and payload unchanged. Default keeps it.
    fn omit_delegate_validation(&self) -> bool { false }
    /// Native account signing is separate from the NAC validation used for
    /// activation and IDS registration. Existing providers keep their NAC path.
    fn native_account_validation_data(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, AnisetteError>> + Send {
        async { Ok(None) }
    }
    fn get_2fa_code(&mut self) -> impl std::future::Future<Output = Result<u32, AnisetteError>> + Send {
        async {
            Err(AnisetteError::MissingLibraries)
        }
    }
}

#[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
pub type DefaultAnisetteProvider = SelectedAnisetteProvider<RemoteAnisetteProviderV3>;
#[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
pub fn default_provider(info: LoginClientInfo, path: PathBuf) -> ArcAnisetteClient<DefaultAnisetteProvider> {
    Arc::new(Mutex::new(AnisetteClient::new(SelectedAnisetteProvider::Platform(RemoteAnisetteProviderV3::new(
        DEFAULT_ANISETTE_URL_V3.to_string(),
        info,
        path
    )))))
}

#[cfg(all(not(target_os = "macos"), feature = "remote-clearadi"))]
pub type DefaultAnisetteProvider = SelectedAnisetteProvider<ClearADIClient>;
#[cfg(all(not(target_os = "macos"), feature = "remote-clearadi"))]
pub fn default_provider(info: LoginClientInfo, path: PathBuf) -> ArcAnisetteClient<DefaultAnisetteProvider> {
    Arc::new(Mutex::new(AnisetteClient::new(SelectedAnisetteProvider::Platform(ClearADIClient {
        login_info: info,
        configuration_path: path
    }))))
}

#[cfg(any(
    feature = "remote-anisette-v3",
    feature = "remote-clearadi",
    target_os = "macos"
))]
#[tokio::test]
#[ignore = "manual integration test; contacts the configured Anisette service"]
async fn test_adi() {
    let default = default_provider(LoginClientInfo {
        ak_context_type: "imessage".to_string(),
        client_app_name: "Messages".to_string(),
        client_bundle_id: "com.apple.MobileSMS".to_string(),
        mme_client_info: "<iPhone7,2> <iPhone OS;12.5.5;16H62> <com.apple.akd/1.0 (com.apple.akd/1.0)>".to_string(),
        mme_client_info_akd: "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".to_string(),
        akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".to_string(),
        browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
        hardware_headers: HashMap::from_iter([]),
        push_token: None,
        update_account_bundle_id: "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)>".to_string(),
    }, PathBuf::from("anisette_test"));
    let mut client = default.lock().await;
    let headers = client.get_headers().await.expect("Anisette headers unavailable");
    assert!(!headers.is_empty());
}


#[cfg(target_os = "macos")]
pub type DefaultAnisetteProvider = SelectedAnisetteProvider<AOSKitAnisetteProvider<'static>>;
#[cfg(target_os = "macos")]
pub fn default_provider(info: LoginClientInfo, path: PathBuf) -> ArcAnisetteClient<DefaultAnisetteProvider> {
    Arc::new(Mutex::new(AnisetteClient::new(SelectedAnisetteProvider::Platform(AOSKitAnisetteProvider::new().expect("Failed to load anisette provider?")))))
}

/// Keep existing typed account/CloudKit clients while selecting the proof
/// source once, before password authentication. No fallback mixes providers.
pub enum SelectedAnisetteProvider<T> {
    Platform(T),
    NativeRelay(native_relay::NativeRelayProvider),
}

impl<T: AnisetteProvider + Send> AnisetteProvider for SelectedAnisetteProvider<T> {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        match self {
            Self::Platform(provider) => provider.get_anisette_headers().await,
            Self::NativeRelay(provider) => provider.get_anisette_headers().await,
        }
    }
    fn auth_client_info(&self) -> Option<&AnisetteClientInfo> {
        match self {
            Self::Platform(provider) => provider.auth_client_info(),
            Self::NativeRelay(provider) => provider.auth_client_info(),
        }
    }
    fn delegate_client_info(&self, service: &str) -> Option<String> {
        match self {
            Self::Platform(provider) => provider.delegate_client_info(service),
            Self::NativeRelay(provider) => provider.delegate_client_info(service),
        }
    }
    fn delegate_client_id(&self) -> Option<String> {
        match self {
            Self::Platform(provider) => provider.delegate_client_id(),
            Self::NativeRelay(provider) => provider.delegate_client_id(),
        }
    }
    fn omit_delegate_validation(&self) -> bool {
        match self {
            Self::Platform(provider) => provider.omit_delegate_validation(),
            Self::NativeRelay(provider) => provider.omit_delegate_validation(),
        }
    }
    async fn native_account_validation_data(&mut self) -> Result<Option<Vec<u8>>, AnisetteError> {
        match self {
            Self::Platform(provider) => provider.native_account_validation_data().await,
            Self::NativeRelay(provider) => provider.native_account_validation_data().await,
        }
    }
    async fn get_2fa_code(&mut self) -> Result<u32, AnisetteError> {
        match self {
            Self::Platform(provider) => provider.get_2fa_code().await,
            Self::NativeRelay(provider) => provider.get_2fa_code().await,
        }
    }
}

#[cfg(any(feature = "remote-anisette-v3", feature = "remote-clearadi", target_os = "macos"))]
pub fn native_relay_provider(config: native_relay::NativeRelayConfig) -> ArcAnisetteClient<DefaultAnisetteProvider> {
    Arc::new(Mutex::new(AnisetteClient::new(SelectedAnisetteProvider::NativeRelay(
        native_relay::NativeRelayProvider::new(config)
    ))))
}

pub type ArcAnisetteClient<T> = Arc<Mutex<AnisetteClient<T>>>;


pub struct AnisetteClient<T: AnisetteProvider> {
    pub provider: T,
    cached_headers: HashMap<String, String>,
    generated_at: SystemTime,
}

impl<T: AnisetteProvider> AnisetteClient<T> {
    pub fn new(p: T) -> AnisetteClient<T> {
        AnisetteClient {
            provider: p,
            cached_headers: HashMap::new(),
            generated_at: SystemTime::UNIX_EPOCH,
        }
    }

    pub async fn get_headers(&mut self) -> Result<&HashMap<String, String>, AnisetteError> {
        let last_generated = SystemTime::now().duration_since(self.generated_at).unwrap_or(Duration::from_secs(120));

        if last_generated > Duration::from_secs(60) {
            self.cached_headers = self.provider.get_anisette_headers().await?;
            self.generated_at = SystemTime::now();
        }

        Ok(&self.cached_headers)
    }

    /// Generate proof for a new authorization exchange using the existing provider.
    /// This does not replace the provider or request an identity/provisioning reset.
    pub async fn get_fresh_headers(&mut self) -> Result<&HashMap<String, String>, AnisetteError> {
        // Failure must not make the preceding exchange's cached proof usable.
        self.generated_at = SystemTime::UNIX_EPOCH;
        self.cached_headers.clear();
        self.cached_headers = self.provider.get_anisette_headers().await?;
        self.generated_at = SystemTime::now();
        Ok(&self.cached_headers)
    }
}

#[cfg(test)]
mod fresh_header_tests {
    use super::*;

    struct Provider { calls: usize, fail_next: bool }

    impl AnisetteProvider for Provider {
        async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
            self.calls += 1;
            if std::mem::take(&mut self.fail_next) { return Err(AnisetteError::Misc); }
            Ok(HashMap::from_iter([
                ("X-Apple-I-MD".into(), format!("synthetic-proof-{}", self.calls)),
                ("X-Mme-Device-Id".into(), "existing-synthetic-device".into()),
            ]))
        }
    }

    #[tokio::test]
    async fn selected_platform_preserves_legacy_refresh_and_no_native_qualifier() {
        let mut client = AnisetteClient::new(SelectedAnisetteProvider::Platform(Provider {
            calls: 0, fail_next: false,
        }));
        assert!(client.provider.native_account_validation_data().await.unwrap().is_none());
        assert_eq!(client.get_fresh_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-1");
        assert_eq!(client.get_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-1");
        assert!(client.provider.auth_client_info().is_none());
        assert!(client.provider.delegate_client_info("synthetic-service").is_none());
        assert!(client.provider.delegate_client_id().is_none());
        assert!(!client.provider.omit_delegate_validation());
        assert!(matches!(client.provider.get_2fa_code().await, Err(AnisetteError::MissingLibraries)));
    }

    #[tokio::test]
    async fn authorization_refresh_does_not_reuse_the_password_exchange_proof() {
        let mut client = AnisetteClient::new(Provider { calls: 0, fail_next: false });
        assert_eq!(client.get_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-1");
        assert_eq!(client.get_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-1");
        let fresh = client.get_fresh_headers().await.unwrap();
        assert_eq!(fresh["X-Apple-I-MD"], "synthetic-proof-2");
        assert_eq!(fresh["X-Mme-Device-Id"], "existing-synthetic-device");
        assert_eq!(client.get_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-2");
        assert_eq!(client.provider.calls, 2);
    }

    #[tokio::test]
    async fn failed_authorization_refresh_cannot_reuse_the_old_cached_proof() {
        let mut client = AnisetteClient::new(Provider { calls: 0, fail_next: false });
        client.get_headers().await.unwrap();
        client.provider.fail_next = true;
        assert!(client.get_fresh_headers().await.is_err());
        assert_eq!(client.get_headers().await.unwrap()["X-Apple-I-MD"], "synthetic-proof-3");
        assert_eq!(client.provider.calls, 3);
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoginClientInfo {
    pub ak_context_type: String,
    pub client_app_name: String,
    pub client_bundle_id: String,
    pub mme_client_info: String,
    pub mme_client_info_akd: String,
    pub akd_user_agent: String,
    pub browser_user_agent: String,
    pub hardware_headers: HashMap<String, String>,
    pub push_token: Option<String>,
    pub update_account_bundle_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct AnisetteClientInfo {
    pub client_info: String,
    pub user_agent: String,
}

impl LoginClientInfo {
    /// Keep account context, genuine hardware headers, APS token and recovery
    /// identity intact. Only authentication-client descriptions follow ADI.
    pub fn use_anisette_client_info(&mut self, info: &AnisetteClientInfo) {
        self.mme_client_info = info.client_info.clone();
        self.mme_client_info_akd = info.client_info.clone();
        self.akd_user_agent = info.user_agent.clone();
    }
}


