//! Token handed out by the health check.
//!
//! For now the token is only returned to the client: it is neither remembered nor verified, and
//! requests are still authenticated with Basic Auth alone.

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};

/// Response header carrying the token, on both the websocket handshake response and the plain
/// HTTP response of a health check.
pub const TOKEN_HEADER: &str = "x-ws2tcp-token";

const TOKEN_BYTES: usize = 32;

/// Generates an opaque, unguessable token: 256 random bits, base64url without padding.
pub fn generate_token() -> Result<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("system random number generator failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_url_safe_and_unique() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();

        assert_eq!(first.len(), 43); // 32 bytes as unpadded base64
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_ne!(first, second);
    }
}
