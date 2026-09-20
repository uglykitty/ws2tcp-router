use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request},
    http::{StatusCode, header},
};
use tracing::{info, warn};

use crate::{
    args::Args, client_addr::ClientAddr, proxy::request_user_agent, target::parse_target_addr,
    token::TokenService,
};

#[derive(Debug)]
pub struct AuthConfig {
    expected_authorizations: RwLock<Vec<String>>,
    fixed_authorizations: Vec<String>,
    basic_auth_file: Option<PathBuf>,
    anonymous_targets: RwLock<Vec<String>>,
    fixed_anonymous_targets: Vec<String>,
    anonymous_target_file: Option<PathBuf>,
    /// Always set when the router runs (token authentication is on whenever Basic credentials
    /// are configured); `None` only for test configurations that model Basic Auth alone.
    tokens: Option<TokenService>,
}

const BASIC_CHALLENGE: &str = r#"Basic realm="ws2tcp-router", charset="UTF-8""#;
pub const BEARER_CHALLENGE: &str = r#"Bearer realm="ws2tcp-router""#;
pub const BEARER_INVALID_CHALLENGE: &str = r#"Bearer realm="ws2tcp-router", error="invalid_token""#;

const ANONYMOUS_AUTH_USER: &str = "anonymous";
const INVALID_AUTH_USER: &str = "invalid";

pub fn build_auth_config(args: &Args) -> Result<Option<AuthConfig>> {
    let auth_enabled = !args.basic_auth.is_empty() || args.basic_auth_file.is_some();
    if !auth_enabled {
        return Ok(None);
    }

    let fixed_authorizations = encode_credentials(&args.basic_auth)?;
    let file_authorizations = args
        .basic_auth_file
        .as_deref()
        .map(load_auth_file)
        .transpose()?
        .unwrap_or_default();
    let mut expected_authorizations = fixed_authorizations.clone();
    expected_authorizations.extend(file_authorizations);

    if expected_authorizations.is_empty() {
        bail!("basic auth is enabled, but no credentials were configured");
    }

    let fixed_anonymous_targets = normalize_anonymous_targets(&args.anonymous_target)?;
    let file_anonymous_targets = args
        .anonymous_target_file
        .as_deref()
        .map(load_anonymous_target_file)
        .transpose()?
        .unwrap_or_default();
    let mut anonymous_targets = fixed_anonymous_targets.clone();
    anonymous_targets.extend(file_anonymous_targets);

    Ok(Some(AuthConfig {
        expected_authorizations: RwLock::new(expected_authorizations),
        fixed_authorizations,
        basic_auth_file: args.basic_auth_file.clone(),
        anonymous_targets: RwLock::new(anonymous_targets),
        fixed_anonymous_targets,
        anonymous_target_file: args.anonymous_target_file.clone(),
        tokens: Some(TokenService::from_args(args)?),
    }))
}

fn normalize_anonymous_targets(targets: &[String]) -> Result<Vec<String>> {
    targets
        .iter()
        .map(|target| {
            parse_target_addr(target)
                .map(|target| target.addr())
                .with_context(|| format!("invalid anonymous target {target:?}"))
        })
        .collect()
}

fn load_anonymous_target_file(path: &Path) -> Result<Vec<String>> {
    let file = fs::read_to_string(path)
        .with_context(|| format!("failed to read anonymous target file {}", path.display()))?;
    file.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let target = line.trim();
            (!target.is_empty() && !target.starts_with('#')).then_some((index, target))
        })
        .map(|(index, target)| {
            parse_target_addr(target)
                .map(|target| target.addr())
                .with_context(|| {
                    format!(
                        "invalid anonymous target in {} at line {}",
                        path.display(),
                        index + 1
                    )
                })
        })
        .collect()
}

fn encode_credentials(credentials: &[String]) -> Result<Vec<String>> {
    credentials
        .iter()
        .map(|credential| {
            validate_basic_auth_credential(credential)?;
            Ok(format!("Basic {}", STANDARD.encode(credential)))
        })
        .collect()
}

fn load_auth_file(path: &Path) -> Result<Vec<String>> {
    let file = fs::read_to_string(path)
        .with_context(|| format!("failed to read basic auth file {}", path.display()))?;
    let credentials = file
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let credential = line.trim();
            (!credential.is_empty() && !credential.starts_with('#')).then_some((index, credential))
        })
        .map(|(index, credential)| {
            validate_basic_auth_credential(credential).with_context(|| {
                format!(
                    "invalid basic auth credential in {} at line {}",
                    path.display(),
                    index + 1
                )
            })?;
            Ok(credential.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;

    encode_credentials(&credentials)
}

pub fn spawn_auth_file_reloader(auth: Arc<AuthConfig>) {
    if let Some(path) = auth.basic_auth_file.clone() {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move {
            poll_file_reload(&path, "basic auth", || auth.reload_auth_file(&path)).await;
        });
    }
    if let Some(path) = auth.anonymous_target_file.clone() {
        tokio::spawn(async move {
            poll_file_reload(&path, "anonymous target", || {
                auth.reload_anonymous_target_file(&path)
            })
            .await;
        });
    }
}

async fn poll_file_reload(path: &Path, kind: &str, mut reload: impl FnMut() -> Result<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_error = None;
    interval.tick().await;
    loop {
        interval.tick().await;
        match reload() {
            Ok(true) => {
                last_error = None;
                info!(path = %path.display(), "reloaded {kind} file");
            }
            Ok(false) => last_error = None,
            Err(err) => {
                let error = format!("{err:#}");
                if last_error.as_deref() != Some(error.as_str()) {
                    warn!(
                        path = %path.display(),
                        error,
                        "failed to reload {kind} file; retaining previous values"
                    );
                    last_error = Some(error);
                }
            }
        }
    }
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
    peer_addr: ClientAddr,
) -> std::result::Result<String, ErrorResponse> {
    let Some(auth) = auth else {
        return Ok(ANONYMOUS_AUTH_USER.to_owned());
    };

    let path = request.uri().path();
    if auth.allows_anonymous_target(path) {
        return Ok(ANONYMOUS_AUTH_USER.to_owned());
    }

    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let mut bearer_presented = false;
    let mut authorized_user = None;
    let auth_user = match authorization {
        None => ANONYMOUS_AUTH_USER.to_owned(),
        Some(authorization) => match bearer_token(authorization) {
            Some(token) => {
                bearer_presented = true;
                authorized_user = auth.verify_access_token(token);
                authorized_user
                    .clone()
                    .unwrap_or_else(|| INVALID_AUTH_USER.to_owned())
            }
            None => {
                authorized_user = auth.basic_user(authorization);
                basic_auth_username(authorization).unwrap_or_else(|| INVALID_AUTH_USER.to_owned())
            }
        },
    };

    match authorized_user {
        Some(user) => Ok(user),
        None => {
            warn!(%peer_addr, auth_user = %auth_user, user_agent = %request_user_agent(request), "rejecting websocket request with invalid credentials");
            let bearer = auth.tokens.as_ref().map(|_| {
                if bearer_presented {
                    BEARER_INVALID_CHALLENGE
                } else {
                    BEARER_CHALLENGE
                }
            });
            Err(unauthorized_response(true, bearer))
        }
    }
}

impl AuthConfig {
    #[cfg(test)]
    pub fn with_basic_auth_for_test(credential: &str) -> Self {
        Self {
            expected_authorizations: RwLock::new(vec![format!(
                "Basic {}",
                STANDARD.encode(credential)
            )]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(Vec::new()),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
        }
    }

    #[cfg(test)]
    pub fn with_tokens_for_test(credential: &str, tokens: TokenService) -> Self {
        Self {
            tokens: Some(tokens),
            ..Self::with_basic_auth_for_test(credential)
        }
    }

    pub fn tokens(&self) -> Option<&TokenService> {
        self.tokens.as_ref()
    }

    /// The user whose Basic `Authorization` header is `authorization`, when the credentials match.
    pub fn basic_user(&self, authorization: &str) -> Option<String> {
        let expected = self
            .expected_authorizations
            .read()
            .expect("basic auth credentials lock poisoned");
        // Look at every credential, and compare in constant time, so that how long a rejection
        // takes reveals nothing about how close a guess was.
        let matched = expected.iter().fold(false, |matched, expected| {
            matched | bool::from(authorization.as_bytes().ct_eq(expected.as_bytes()))
        });
        matched
            .then(|| basic_auth_username(authorization))
            .flatten()
    }

    /// Whether `user` is (still) one of the configured Basic Auth users.
    pub fn has_user(&self, user: &str) -> bool {
        self.expected_authorizations
            .read()
            .expect("basic auth credentials lock poisoned")
            .iter()
            .any(|expected| basic_auth_username(expected).as_deref() == Some(user))
    }

    /// The user of a valid access token. A user removed from the credentials loses their tokens.
    fn verify_access_token(&self, token: &str) -> Option<String> {
        self.tokens
            .as_ref()?
            .verify_access(token)
            .filter(|user| self.has_user(user))
    }

    fn reload_auth_file(&self, path: &Path) -> Result<bool> {
        let file_authorizations = load_auth_file(path)?;
        let mut next = self.fixed_authorizations.clone();
        next.extend(file_authorizations);
        if next.is_empty() {
            bail!("basic auth is enabled, but no credentials were configured");
        }

        let mut current = self
            .expected_authorizations
            .write()
            .expect("basic auth credentials lock poisoned");
        if *current == next {
            return Ok(false);
        }
        *current = next;
        Ok(true)
    }

    fn allows_anonymous_target(&self, path: &str) -> bool {
        let Ok(target) = crate::target::parse_target(path) else {
            return false;
        };
        let addr = target.addr();

        self.anonymous_targets
            .read()
            .expect("anonymous targets lock poisoned")
            .iter()
            .any(|target| target == &addr)
    }

    fn reload_anonymous_target_file(&self, path: &Path) -> Result<bool> {
        let file_targets = load_anonymous_target_file(path)?;
        let mut next = self.fixed_anonymous_targets.clone();
        next.extend(file_targets);
        let mut current = self
            .anonymous_targets
            .write()
            .expect("anonymous targets lock poisoned");
        if *current == next {
            return Ok(false);
        }
        *current = next;
        Ok(true)
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

/// The token of a `Bearer` `Authorization` header. The scheme is case-insensitive (RFC 9110).
pub fn bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
        .filter(|token| !token.is_empty())
}

/// A `401` offering the Basic challenge and/or the given Bearer challenge.
pub fn unauthorized_response(basic: bool, bearer: Option<&'static str>) -> ErrorResponse {
    let mut response = ErrorResponse::new(Some("authentication required".to_owned()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    let challenges = basic.then_some(BASIC_CHALLENGE).into_iter().chain(bearer);
    for challenge in challenges {
        response.headers_mut().append(
            header::WWW_AUTHENTICATE,
            challenge.parse().expect("valid WWW-Authenticate header"),
        );
    }
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
            service_mode: crate::args::ServiceMode::WsOnly,
            port: 80,
            tls_port: 443,
            ipv6_only: false,
            buffer_size: 16 * 1024,
            udp_idle_timeout: 60,
            basic_auth: Vec::new(),
            basic_auth_file: None,
            anonymous_target: Vec::new(),
            anonymous_target_file: None,
            trusted_proxy: Vec::new(),
            token_secret_file: None,
            access_token_ttl: 600,
            refresh_token_ttl: 604_800,
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
            *auth.expected_authorizations.read().unwrap(),
            vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ]
        );
    }

    #[test]
    fn builds_basic_auth_config_with_anonymous_targets() {
        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned()];
        args.anonymous_target = vec![
            "ocs.wangguofang.net:8443".to_owned(),
            "[2001:db8::1]:443".to_owned(),
        ];

        let auth = build_auth_config(&args).unwrap().unwrap();

        assert_eq!(
            *auth.anonymous_targets.read().unwrap(),
            vec![
                "ocs.wangguofang.net:8443".to_owned(),
                "[2001:db8::1]:443".to_owned(),
            ]
        );
    }

    #[test]
    fn loads_and_reloads_anonymous_target_file() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ws2tcp-router-anonymous-targets-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "# public targets\nfile.example:443\n\n[2001:db8::1]:8443\n",
        )
        .unwrap();

        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned()];
        args.anonymous_target = vec!["fixed.example:80".to_owned()];
        args.anonymous_target_file = Some(path.clone());
        let auth = build_auth_config(&args).unwrap().unwrap();

        assert_eq!(
            *auth.anonymous_targets.read().unwrap(),
            vec![
                "fixed.example:80".to_owned(),
                "file.example:443".to_owned(),
                "[2001:db8::1]:8443".to_owned(),
            ]
        );

        fs::write(&path, "updated.example:9443\n").unwrap();
        assert!(auth.reload_anonymous_target_file(&path).unwrap());
        assert_eq!(
            *auth.anonymous_targets.read().unwrap(),
            vec![
                "fixed.example:80".to_owned(),
                "updated.example:9443".to_owned(),
            ]
        );

        fs::write(&path, "invalid\n").unwrap();
        assert!(auth.reload_anonymous_target_file(&path).is_err());
        assert_eq!(
            *auth.anonymous_targets.read().unwrap(),
            vec![
                "fixed.example:80".to_owned(),
                "updated.example:9443".to_owned(),
            ]
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_invalid_anonymous_target() {
        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned()];
        args.anonymous_target = vec!["2001:db8::1:443".to_owned()];

        assert!(build_auth_config(&args).is_err());
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
    fn reloads_basic_auth_file_and_retains_last_valid_credentials() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ws2tcp-router-reload-auth-{}.txt",
            std::process::id()
        ));
        fs::write(&path, "alice:secret\n").unwrap();

        let mut args = default_args();
        args.basic_auth_file = Some(path.clone());
        let auth = build_auth_config(&args).unwrap().unwrap();
        let peer_addr = "127.0.0.1:12345".parse().unwrap();
        let alice = request_with_authorization(Some("Basic YWxpY2U6c2VjcmV0"));
        let bob = request_with_authorization(Some("Basic Ym9iOnNlY3JldDI="));

        assert!(authorize_request(&alice, Some(&auth), peer_addr).is_ok());
        fs::write(&path, "bob:secret2\n").unwrap();
        assert!(auth.reload_auth_file(&path).unwrap());
        assert!(authorize_request(&alice, Some(&auth), peer_addr).is_err());
        assert!(authorize_request(&bob, Some(&auth), peer_addr).is_ok());

        fs::write(&path, "invalid\n").unwrap();
        assert!(auth.reload_auth_file(&path).is_err());
        assert!(authorize_request(&bob, Some(&auth), peer_addr).is_ok());

        fs::remove_file(path).unwrap();
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
            expected_authorizations: RwLock::new(vec!["Basic YWxpY2U6c2VjcmV0".to_owned()]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(Vec::new()),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
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
            expected_authorizations: RwLock::new(vec!["Basic YWxpY2U6c2VjcmV0".to_owned()]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(Vec::new()),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, Some(&auth), peer_addr).is_err());
    }

    #[test]
    fn allows_request_with_matching_basic_auth_header() {
        let request = request_with_authorization(Some("Basic Ym9iOnNlY3JldDI="));
        let auth = AuthConfig {
            expected_authorizations: RwLock::new(vec![
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
                "Basic Ym9iOnNlY3JldDI=".to_owned(),
            ]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(Vec::new()),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(
            authorize_request(&request, Some(&auth), peer_addr).unwrap(),
            "bob"
        );
    }

    #[test]
    fn allows_request_without_basic_auth_header_for_anonymous_target() {
        let request = Request::builder()
            .uri(Uri::from_static("/tcp:ocs.wangguofang.net:8443"))
            .body(())
            .unwrap();
        let auth = AuthConfig {
            expected_authorizations: RwLock::new(vec!["Basic YWxpY2U6c2VjcmV0".to_owned()]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(vec!["ocs.wangguofang.net:8443".to_owned()]),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(
            authorize_request(&request, Some(&auth), peer_addr).unwrap(),
            ANONYMOUS_AUTH_USER
        );
    }

    #[test]
    fn rejects_request_without_basic_auth_header_for_non_anonymous_target() {
        let request = Request::builder()
            .uri(Uri::from_static("/tcp:other.example:8443"))
            .body(())
            .unwrap();
        let auth = AuthConfig {
            expected_authorizations: RwLock::new(vec!["Basic YWxpY2U6c2VjcmV0".to_owned()]),
            fixed_authorizations: Vec::new(),
            basic_auth_file: None,
            anonymous_targets: RwLock::new(vec!["ocs.wangguofang.net:8443".to_owned()]),
            fixed_anonymous_targets: Vec::new(),
            anonymous_target_file: None,
            tokens: None,
        };
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        assert!(authorize_request(&request, Some(&auth), peer_addr).is_err());
    }

    #[test]
    fn access_tokens_of_a_removed_user_are_rejected() {
        use crate::token::TokenService;
        use std::time::Duration;

        let tokens = TokenService::new(
            b"0123456789abcdef0123456789abcdef",
            Duration::from_secs(600),
            Duration::from_secs(3600),
        );
        let alice = tokens.login("alice").unwrap().access_token;
        let bob = tokens.login("bob").unwrap().access_token;
        // Only alice is configured; bob was removed after he logged in.
        let auth = AuthConfig::with_tokens_for_test("alice:secret", tokens);
        let peer_addr = "127.0.0.1:12345".parse().unwrap();

        let request = request_with_authorization(Some(&format!("Bearer {alice}")));
        assert_eq!(
            authorize_request(&request, Some(&auth), peer_addr).unwrap(),
            "alice"
        );
        let request = request_with_authorization(Some(&format!("Bearer {bob}")));
        assert!(authorize_request(&request, Some(&auth), peer_addr).is_err());
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_needs_a_token() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER  abc "), Some("abc"));
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Basic abc"), None);
    }

    #[test]
    fn token_authentication_is_on_whenever_basic_auth_is_configured() {
        let mut args = default_args();
        args.basic_auth = vec!["alice:secret".to_owned()];
        let auth = build_auth_config(&args).unwrap().unwrap();

        assert!(auth.tokens().is_some());

        // Without credentials there is nothing to log in with: authentication is off altogether,
        // and so are the tokens.
        assert!(build_auth_config(&default_args()).unwrap().is_none());
    }
}
