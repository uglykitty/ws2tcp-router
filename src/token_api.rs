//! The token endpoints, served as plain HTTP next to the health check:
//!
//! | endpoint             | credential                        | result                          |
//! |----------------------|-----------------------------------|---------------------------------|
//! | `POST /auth/token`   | Basic Auth                        | a new access + refresh token    |
//! | `POST /auth/refresh` | `Bearer <refresh token>`          | a new pair; the old one is void |
//! | `POST /auth/revoke`  | `Bearer <refresh token>`          | logs out (`204`)                |
//!
//! Requests carry no body; the credential is in the `Authorization` header. Nothing here checks
//! whether the connection is encrypted: with a reverse proxy terminating TLS in front, the router
//! only ever sees plain connections.

use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request},
    http::{HeaderValue, Method, StatusCode, header},
};
use tracing::{info, warn};

use crate::{
    auth::{
        AuthConfig, BEARER_CHALLENGE, BEARER_INVALID_CHALLENGE, bearer_token, unauthorized_response,
    },
    client_addr::ClientAddr,
    proxy::request_user_agent,
    token::{IssuedTokens, TokenError},
};

#[derive(Debug, Clone, Copy)]
enum Endpoint {
    Login,
    Refresh,
    Revoke,
}

/// Answers a plain HTTP request for a path under `/auth/`.
pub fn handle_auth_request(
    request: &Request,
    auth: Option<&AuthConfig>,
    peer_addr: ClientAddr,
) -> ErrorResponse {
    let Some((auth, tokens)) = auth.and_then(|auth| auth.tokens().map(|tokens| (auth, tokens)))
    else {
        return text_response(StatusCode::NOT_FOUND, "not found");
    };
    let endpoint = match request.uri().path() {
        "/auth/token" => Endpoint::Login,
        "/auth/refresh" => Endpoint::Refresh,
        "/auth/revoke" => Endpoint::Revoke,
        _ => return text_response(StatusCode::NOT_FOUND, "not found"),
    };
    if request.method() != Method::POST {
        let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "use POST");
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return response;
    }
    // The credential is in the header. Refusing a body also means there is nothing left unread
    // on the connection that is closed after the answer.
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|length| length != "0")
    {
        return text_response(StatusCode::BAD_REQUEST, "request must not have a body");
    }

    let user_agent = request_user_agent(request);
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    match endpoint {
        Endpoint::Login => {
            let Some(user) = authorization.and_then(|value| auth.basic_user(value)) else {
                warn!(%peer_addr, %user_agent, "rejecting token login with invalid credentials");
                return unauthorized_response(true, None);
            };
            match tokens.login(&user) {
                Ok(issued) => {
                    info!(%peer_addr, auth_user = %user, %user_agent, "issued tokens");
                    tokens_response(&issued)
                }
                Err(err) => token_error_response(&err),
            }
        }
        Endpoint::Refresh => {
            let Some(token) = authorization.and_then(bearer_token) else {
                return unauthorized_response(false, Some(BEARER_CHALLENGE));
            };
            match tokens.refresh(token, |user| auth.has_user(user)) {
                Ok((user, issued)) => {
                    info!(%peer_addr, auth_user = %user, %user_agent, "refreshed tokens");
                    tokens_response(&issued)
                }
                Err(TokenError::Invalid) => {
                    warn!(%peer_addr, %user_agent, "rejecting invalid refresh token");
                    unauthorized_response(false, Some(BEARER_INVALID_CHALLENGE))
                }
                Err(TokenError::Reused { user }) => {
                    warn!(
                        %peer_addr,
                        auth_user = %user,
                        %user_agent,
                        "refresh token reused; the login was revoked"
                    );
                    unauthorized_response(false, Some(BEARER_INVALID_CHALLENGE))
                }
                Err(err) => token_error_response(&err),
            }
        }
        Endpoint::Revoke => {
            let Some(token) = authorization.and_then(bearer_token) else {
                return unauthorized_response(false, Some(BEARER_CHALLENGE));
            };
            // Answer the same whether or not the token was known, so this is no oracle for tokens.
            if tokens.revoke(token) {
                info!(%peer_addr, %user_agent, "revoked a login");
            }
            no_store(text_response(StatusCode::NO_CONTENT, ""))
        }
    }
}

fn tokens_response(issued: &IssuedTokens) -> ErrorResponse {
    // Every value is base64url or a number, so nothing needs JSON escaping.
    let body = format!(
        r#"{{"token_type":"Bearer","access_token":"{}","expires_in":{},"refresh_token":"{}","refresh_expires_in":{}}}"#,
        issued.access_token,
        issued.access_expires_in,
        issued.refresh_token,
        issued.refresh_expires_in
    );
    let mut response = ErrorResponse::new(Some(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    no_store(response)
}

fn token_error_response(err: &TokenError) -> ErrorResponse {
    match err {
        TokenError::Full => {
            warn!("token store is full; refusing to issue tokens");
            text_response(StatusCode::SERVICE_UNAVAILABLE, "too many active logins")
        }
        _ => {
            warn!(error = ?err, "failed to issue tokens");
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to issue tokens")
        }
    }
}

fn text_response(status: StatusCode, message: &str) -> ErrorResponse {
    // `ErrorResponse::new` defaults to 200 OK.
    let mut response = ErrorResponse::new(Some(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Tokens must never be cached by the client or an intermediary.
fn no_store(mut response: ErrorResponse) -> ErrorResponse {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
