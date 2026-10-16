//! Apple's public URL bag selects the authentication services for the actual
//! ADI client. Activation hardware is not the authentication client platform.
use super::{Error, APPLE_ROOT, APPLE_ROOT_G3};
use omnisette::LoginClientInfo;
use plist::{Dictionary, Value};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Certificate, ClientBuilder, Response,
};
use std::time::Duration;

const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const MAX_BAG_BYTES: usize = 65536;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AuthRoutes {
    pub srp: &'static str,
    pub secondary: &'static str,
    pub trusted_device: &'static str,
    pub validate_code: &'static str,
}

impl AuthRoutes {
    pub(super) fn from_bag(bag: &Dictionary) -> Result<Self, Error> {
        let urls = bag
            .get("urls")
            .and_then(Value::as_dictionary)
            .ok_or_else(|| invalid("missing-auth-services"))?;
        let select = |key: &str, allowed: &[&'static str]| -> Result<&'static str, Error> {
            let value = urls.get(key).and_then(Value::as_string);
            allowed
                .iter()
                .copied()
                .find(|candidate| Some(*candidate) == value)
                .ok_or_else(|| invalid("unsupported-auth-service"))
        };
        let routes = Self {
            srp: select(
                "gsService",
                &[
                    "https://gsa.apple.com/grandslam/GsService2",
                    "https://gsd.apple.com/grandslam/GsService2",
                ],
            )?,
            secondary: select(
                "secondaryAuth",
                &["https://gsa.apple.com/auth", "https://gsd.apple.com/auth"],
            )?,
            trusted_device: select(
                "trustedDeviceSecondaryAuth",
                &[
                    "https://gsa.apple.com/auth/verify/trusteddevice",
                    "https://gsd.apple.com/auth/verify/trusteddevice",
                ],
            )?,
            validate_code: select(
                "validateCode",
                &[
                    "https://gsa.apple.com/grandslam/GsService2/validate",
                    "https://gsd.apple.com/grandslam/GsService2/validate",
                ],
            )?,
        };
        let origin = routes
            .secondary
            .strip_suffix("/auth")
            .expect("exact allowlist");
        if !routes.srp.starts_with(&format!("{origin}/"))
            || routes.trusted_device != format!("{}/verify/trusteddevice", routes.secondary)
        {
            return Err(invalid("inconsistent-auth-services"));
        }
        // validateCode is independently selected. Current Android bags select
        // GSD for SRP/secondary auth but GSA for code verification.
        Ok(routes)
    }

    pub(super) fn secondary_endpoint(self, suffix: &str) -> String {
        format!("{}{suffix}", self.secondary)
    }
}

pub(super) struct BoundAuthRoutes {
    pub routes: AuthRoutes,
    descriptor: String,
    user_agent: String,
}

impl BoundAuthRoutes {
    pub(super) fn new(routes: AuthRoutes, info: &LoginClientInfo) -> Self {
        Self {
            routes,
            descriptor: info.mme_client_info_akd.clone(),
            user_agent: info.akd_user_agent.clone(),
        }
    }

    pub(super) fn matches(&self, info: &LoginClientInfo) -> bool {
        self.descriptor == info.mme_client_info_akd && self.user_agent == info.akd_user_agent
    }

    pub(super) fn require_matching(&self, info: &LoginClientInfo) -> Result<AuthRoutes, Error> {
        if !self.matches(info) {
            return Err(invalid("authentication-client-changed"));
        }
        Ok(self.routes)
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::UnexpectedResponse(reason.into())
}

fn lookup_headers(info: &LoginClientInfo) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("X-MMe-Client-Info", &info.mme_client_info_akd),
        ("User-Agent", &info.akd_user_agent),
    ] {
        if value.is_empty() || value.len() > 4096 {
            return Err(invalid("invalid-auth-client"));
        }
        headers.insert(
            name,
            HeaderValue::from_str(value).map_err(|_| invalid("invalid-auth-client"))?,
        );
    }
    headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
    // No username, password, ADI proof, identity token, hardware or cookies.
    Ok(headers)
}

async fn read_bag(mut response: Response, requested_url: &str) -> Result<AuthRoutes, Error> {
    if response.url().as_str() != requested_url {
        return Err(invalid("auth-lookup-redirected"));
    }
    let status = response.status();
    if status.as_u16() == 429 {
        return Err(Error::AuthenticationRateLimited);
    }
    if status.is_server_error() {
        return Err(Error::AuthenticationServiceUnavailable(status.as_u16()));
    }
    if !status.is_success() {
        return Err(invalid("auth-service-lookup-rejected"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BAG_BYTES as u64)
    {
        return Err(invalid("auth-service-lookup-too-large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_BAG_BYTES - bytes.len() {
            return Err(invalid("auth-service-lookup-too-large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let bag: Dictionary =
        plist::from_bytes(&bytes).map_err(|_| invalid("malformed-auth-service-lookup"))?;
    AuthRoutes::from_bag(&bag)
}

fn lookup_client_builder() -> Result<ClientBuilder, Error> {
    // Dedicated no-cookie/no-redirect client: an unexpected Location must not
    // receive even the public metadata, and account cookies never enter lookup.
    Ok(ClientBuilder::new()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        .add_root_certificate(Certificate::from_pem(APPLE_ROOT_G3)?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(LOOKUP_TIMEOUT))
}

async fn lookup_with_client(
    client: &reqwest::Client,
    requested_url: &str,
    info: &LoginClientInfo,
    budget: Duration,
) -> Result<AuthRoutes, Error> {
    let headers = lookup_headers(info)?;
    tokio::time::timeout(budget, async {
        read_bag(
            client.get(requested_url).headers(headers).send().await?,
            requested_url,
        )
        .await
    })
    .await
    .map_err(|_| invalid("auth-service-lookup-timeout"))?
}

pub(super) async fn lookup(info: &LoginClientInfo) -> Result<AuthRoutes, Error> {
    let client = lookup_client_builder()?.build()?;
    lookup_with_client(&client, LOOKUP, info, LOOKUP_TIMEOUT).await
}

#[cfg(test)]
#[path = "auth_routes_http_tests.rs"]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn bag(origin: &str) -> Dictionary {
        Dictionary::from_iter([(
            "urls",
            Value::Dictionary(Dictionary::from_iter([
                (
                    "gsService",
                    Value::String(format!("{origin}/grandslam/GsService2")),
                ),
                ("secondaryAuth", Value::String(format!("{origin}/auth"))),
                (
                    "trustedDeviceSecondaryAuth",
                    Value::String(format!("{origin}/auth/verify/trusteddevice")),
                ),
                (
                    "validateCode",
                    Value::String("https://gsa.apple.com/grandslam/GsService2/validate".into()),
                ),
            ])),
        )])
    }

    #[test]
    fn keeps_independent_verification_route_from_android_bag() {
        let routes = AuthRoutes::from_bag(&bag("https://gsd.apple.com")).unwrap();
        assert_eq!(routes.srp, "https://gsd.apple.com/grandslam/GsService2");
        assert_eq!(
            routes.secondary_endpoint("/verify/phone/securitycode"),
            "https://gsd.apple.com/auth/verify/phone/securitycode"
        );
        assert_eq!(
            routes.trusted_device,
            "https://gsd.apple.com/auth/verify/trusteddevice"
        );
        assert_eq!(
            routes.validate_code,
            "https://gsa.apple.com/grandslam/GsService2/validate"
        );
        assert_eq!(
            AuthRoutes::from_bag(&bag("https://gsa.apple.com"))
                .unwrap()
                .secondary,
            "https://gsa.apple.com/auth"
        );
    }

    #[test]
    fn rejects_missing_and_incoherent_services_without_defaulting() {
        assert!(AuthRoutes::from_bag(&Dictionary::new()).is_err());
        for key in [
            "gsService",
            "secondaryAuth",
            "trustedDeviceSecondaryAuth",
            "validateCode",
        ] {
            let mut incomplete = bag("https://gsa.apple.com");
            incomplete
                .get_mut("urls")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .remove(key);
            assert!(AuthRoutes::from_bag(&incomplete).is_err());
        }
        let mut mixed = bag("https://gsd.apple.com");
        mixed
            .get_mut("urls")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "secondaryAuth".into(),
                Value::String("https://gsa.apple.com/auth".into()),
            );
        assert!(AuthRoutes::from_bag(&mixed).is_err());
    }

    #[test]
    fn rejects_credential_and_origin_confusion() {
        for invalid in [
            "http://gsd.apple.com/grandslam/GsService2",
            "https://gsd.apple.com.evil.invalid/grandslam/GsService2",
            "https://gsa.apple.com@evil.invalid/grandslam/GsService2",
            "https://gsd.apple.com:443/grandslam/GsService2",
            "https://gsd.apple.com/grandslam/GsService2?token=secret",
            "https://gsd.apple.com/grandslam/GsService2#secret",
            "https://gsd.apple.com/auth",
            "",
        ] {
            let mut value = bag("https://gsd.apple.com");
            value
                .get_mut("urls")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .insert("gsService".into(), Value::String(invalid.into()));
            let error = AuthRoutes::from_bag(&value).unwrap_err().to_string();
            assert!(!error.contains(invalid) || invalid.is_empty());
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn lookup_headers_contain_public_effective_metadata_only() {
        let info = LoginClientInfo {
            mme_client_info_akd: "provider-descriptor".into(),
            akd_user_agent: "provider-agent".into(),
            push_token: Some("private-push".into()),
            hardware_headers: std::collections::HashMap::from([(
                "private-hardware".into(),
                "secret".into(),
            )]),
            ..Default::default()
        };
        let headers = lookup_headers(&info).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers["x-mme-client-info"], "provider-descriptor");
        assert_eq!(headers["user-agent"], "provider-agent");
        assert!(!format!("{headers:?}").contains("secret"));
        assert!(lookup_headers(&LoginClientInfo::default()).is_err());
        assert!(lookup_headers(&LoginClientInfo {
            akd_user_agent: "bad\r\nheader".into(),
            ..info
        })
        .is_err());
    }

    #[test]
    fn verification_binding_rejects_provider_drift() {
        let info = LoginClientInfo {
            mme_client_info_akd: "provider".into(),
            akd_user_agent: "agent".into(),
            ..Default::default()
        };
        let bound = BoundAuthRoutes::new(
            AuthRoutes::from_bag(&bag("https://gsd.apple.com")).unwrap(),
            &info,
        );
        assert!(bound.require_matching(&info).is_ok());
        assert!(bound
            .require_matching(&LoginClientInfo {
                akd_user_agent: "changed".into(),
                ..info.clone()
            })
            .is_err());
        assert!(bound
            .require_matching(&LoginClientInfo {
                mme_client_info_akd: "changed".into(),
                ..info
            })
            .is_err());
    }
}
