pub mod anisette;
mod client;
use std::fmt::Display;

pub use client::{AppleAccount, LoginState, TrustedPhoneNumber, AuthenticationExtras, VerifyBody, CircleSendMessage, GenerateVerificationTokenRequest};
pub use omnisette::{LoginClientInfo, default_provider, ArcAnisetteClient, DefaultAnisetteProvider};



use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse the response")]
    Parse,
    #[error("Failed to authenticate.")]
    AuthSrp,
    #[error("Failed to have a happy birthday!.")]
    HappyBirthdayError,
    #[error("Bad 2fa code.")]
    Bad2faCode,
    #[error("{1} ({0})")]
    AuthSrpWithMessage(i64, String),
    #[error("Please login to appleid.apple.com to fix this account")]
    ExtraStep(String),
    #[error("Failed to parse a plist {0}")]
    PlistError(#[from] plist::Error),
    #[error("Unexpected Apple authentication response ({0})")]
    UnexpectedResponse(String),
    #[error("Apple's sign-in service returned a server error (HTTP {0}). Please try again later. This error does not require resetting your activation details.")]
    AuthenticationServiceUnavailable(u16),
    #[error("Apple is limiting sign-in requests (HTTP 429). Please wait before trying again.")]
    AuthenticationRateLimited,
    #[error("Request failed {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Failed getting anisette data {0}")]
    ErrorGettingAnisette(#[from] omnisette::AnisetteError),
    #[error("Apple could not load text-message verification options, so the app could not request an SMS. Sign-in is still waiting for verification.")]
    FailedGetting2FAConfig,
    #[error("Serde Error")]
    SerdeError(#[from] serde_json::Error),
    #[error("Apple did not return a supported trusted phone number. Use a trusted-device verification code if available.")]
    HardwareKeyError,
    #[error("Malformed Apple SRP init response: missing or invalid '{0}'")]
    MalformedSrpInit(&'static str),
    #[error("Malformed Apple SRP complete response: missing or invalid '{0}'")]
    MalformedSrpComplete(&'static str),
    #[error("Apple SRP cryptography failed at '{0}'")]
    SrpFailure(&'static str),
    #[error("Failed to decrypt Apple SPD payload")]
    SpdDecryptFailed,
    #[error("Malformed Apple SPD payload: missing or invalid '{0}'")]
    MalformedSpd(&'static str),
    #[error("cloud_sync_2fa_session_missing")]
    TwoFactorSessionMissing,
}
