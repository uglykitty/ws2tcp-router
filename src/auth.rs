use std::{fs, net::SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request},
    http::{StatusCode, header},
};
use tracing::warn;

use crate::args::Args;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    expected_authorizations: Vec<String>,
}

const ANONYMOUS_AUTH_USER: &str = "anonymous";
const INVALID_AUTH_USER: &str = "invalid";

pub fn build_auth_config(args: &Args) -> Result<Option<AuthConfig>> {
    let auth_enabled = !args.basic_auth.is_empty() || args.basic_auth_file.is_some();
    if !auth_enabled {
        return Ok(None);
    }

    let mut credentials = args.basic_auth.clone();

    if let Some(path) = &args.basic_auth_file {
        let file = fs::read_to_string(path)
            .with_context(|| format!("failed to read basic auth file {}", path.display()))?;
        for (index, line) in file.lines().enumerate() {
            let credential = line.trim();
            if credential.is_empty() || credential.starts_with('#') {
                continue;
            }
            validate_basic_auth_credential(credential).with_context(|| {
                format!(
                    "invalid basic auth credential in {} at line {}",
                    path.display(),
                    index + 1
                )
            })?;
            credentials.push(credential.to_owned());
        }
    }

    if credentials.is_empty() {
        bail!("basic auth is enabled, but no credentials were configured");
    }

    let expected_authorizations = credentials
        .iter()
        .map(|credential| {
            validate_basic_auth_credential(credential)?;
            Ok(format!("Basic {}", STANDARD.encode(credential)))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(AuthConfig {
        expected_authorizations,
    }))
}

fn validate_basic_auth_credential(credential: &str) -> Result<()> {
    let (username, password) = credential
        .split_once(':')
        .ok_or_else(|| anyhow!("basic auth credential must be formatted as USER:PASS"))?;

    if username.is_empty() {
        bail!("basic auth username must not be empty");
    }
    if password.is_empty() {
        bail!("basic auth password must not be empty");
    }

    Ok(())
}

#[allow(clippy::result_large_err)]
pub fn authorize_request(
    request: &Request,
    auth: Option<&AuthConfig>,
    peer_addr: SocketAddr,
) -> std::result::Result<String, ErrorResponse> {
    let Some(auth) = auth else {
        return Ok(ANONYMOUS_AUTH_USER.to_owned());
    };

    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let auth_user = authorization
        .map(|authorization| {
            basic_auth_username(authorization).unwrap_or_else(|| INVALID_AUTH_USER.to_owned())
        })
        .unwrap_or_else(|| ANONYMOUS_AUTH_USER.to_owned());
    let authorized = authorization.is_some_and(|authorization| {
        auth.expected_authorizations
            .iter()
            .any(|expected| authorization == expected)
    });

    if authorized {
        Ok(auth_user)
    } else {
        warn!(%peer_addr, auth_user = %auth_user, "rejecting websocket request with invalid basic auth");
        Err(unauthorized_response())
    }
}

fn basic_auth_username(authorization: &str) -> Option<String> {
    let encoded = authorization.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let credential = String::from_utf8(decoded).ok()?;
    let (username, _) = credential.split_once(':')?;
    if username.is_empty() {
        return None;
    }

    Some(username.to_owned())
}

fn unauthorized_response() -> ErrorResponse {
    let mut response = ErrorResponse::new(Some("authentication required".to_owned()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        r#"Basic realm="ws2tcp-router", charset="UTF-8""#
            .parse()
            .expect("valid WWW-Authenticate header"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use tokio_tungstenite::tungstenite::http::Uri;

    fn request_with_authorization(authorization: Option<&str>) -> Request {
        let mut request = Request::builder()
            .uri(Uri::from_static("/tcp:127.0.0.1:80"))
            .body(())
            .unwrap();
        if let Some(authorization) = authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, authorization.parse().unwrap());
        }
        request
    }

    fn default_args() -> Args {
        Args {
            bind: "::".to_owned(),
            port: 8000,
            ipv6_only: false,
            buffer_size: 16 * 1024,
            basic_auth: Vec::new(),
            basic_auth_file: None,
            tls_cert: None,
            tls_key: None,
            auto_self_signed_cert: false,
            log_file: None,
            log_level: None,
        }
    }

    #[test]
    fn validates_basic_auth_credentials() {
        assert!(validate_basic_auth_credential("alice:secret").is_ok());
        assert!(validate_basic_auth_credential("alice:sec:ret").is_ok());
        assert!(validate_basic_auth_credential("alice").is_err());
        assert!(validate_basic_auth_credential(":secret").is_err());
        assert!(validate_basic_auth_credential("alice:").is_err());
    }

    #[test]
    fn extracts_basic_auth_username() {
        assert_eq!(
            basic_auth_username("Basic YWxpY2U6c2VjcmV0"),
            Some("alice".to_owned())
        );
        assert_eq!(basic_auth_username("Bearer token"), None);
        assert_eq!(basic_auth_username("Basic not-base64"), None);
        assert_eq!(basic_auth_username("Basic OnNlY3JldA=="), None);
    }

    #[test]
    fn disables_basic_auth_when_no_auth_options_are_set() {
        let args = default_args();

        assert!(build_auth_config(&args).unwrap().is_none());
    }

    #[test]
    fn builds_basic_auth_config_from_repeated_credentials() {
        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned(), "bob:secret2".to_owned()];

        let auth = build_auth_config(&args).unwrap().unwrap();

        assert_eq!(
            auth.expected_authorizations,
            vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ]
        );
    }

    #[test]
    fn rejects_empty_basic_auth_file_when_auth_is_enabled() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ws2tcp-router-empty-auth-{}.txt",
            std::process::id()
        ));
        fs::write(&path, "\n# no credentials\n").unwrap();

        let mut args = default_args();
        args.basic_auth_file = Some(PathBuf::from(&path));
        let result = build_auth_config(&args);

        fs::remove_file(path).unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn allows_request_when_basic_auth_is_disabled() {
        let request = request_with_authorization(None);
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(
            authorize_request(&request, None, peer_addr).unwrap(),
            ANONYMOUS_AUTH_USER
        );
    }

    #[test]
    fn rejects_request_without_basic_auth_header_when_enabled() {
        let request = request_with_authorization(None);
        let auth = AuthConfig {
            expected_authorizations: vec!["Basic YWxpY2U6c2VjcmV0".to_owned()],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        let response = authorize_request(&request, Some(&auth), peer_addr).unwrap_err();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="ws2tcp-router", charset="UTF-8""#
        );
    }

    #[test]
    fn rejects_request_with_invalid_basic_auth_header() {
        let request = request_with_authorization(Some("Basic Ym9iOnNlY3JldA=="));
        let auth = AuthConfig {
            expected_authorizations: vec!["Basic YWxpY2U6c2VjcmV0".to_owned()],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, Some(&auth), peer_addr).is_err());
    }

    #[test]
    fn allows_request_with_matching_basic_auth_header() {
        let request = request_with_authorization(Some("Basic Ym9iOnNlY3JldDI="));
        let auth = AuthConfig {
            expected_authorizations: vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ],
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(
            authorize_request(&request, Some(&auth), peer_addr).unwrap(),
            "bob"
        );
    }
}
