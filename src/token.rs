//! Access and refresh tokens.
//!
//! A client logs in once with Basic Auth and gets two tokens:
//!
//! - an **access token**, short-lived and stateless: `base64url(payload).base64url(hmac)`, where
//!   the payload carries the user, the token family and the expiry. It is what proxy requests
//!   present (`Authorization: Bearer ...`), so the password is not sent on every connection.
//! - a **refresh token**, long-lived, opaque and stateful: only its SHA-256 is stored. It is used
//!   at `/auth/refresh` to get a new pair. Every refresh **rotates** the token; presenting one
//!   that was already rotated means it leaked, and the whole family is revoked.
//!
//! All tokens of one login form a *family*, so logging out or detecting reuse kills the refresh
//! token and (until they expire) the access tokens of that login. State lives in memory: after a
//! restart refresh tokens are gone and clients log in again with Basic Auth. Access tokens
//! survive a restart only when the signing secret is configured.

use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};

use crate::args::Args;

const TOKEN_BYTES: usize = 32;
const MIN_SECRET_BYTES: usize = 32;
const ACCESS_TOKEN_VERSION: u8 = 1;
/// Longest a login can be kept alive by refreshing, however often the client refreshes.
const MAX_FAMILY_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Bound on remembered refresh tokens (live and already rotated), so that a client with valid
/// credentials cannot grow the store without limit.
const MAX_RECORDS: usize = 100_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Generates an opaque, unguessable token: 256 random bits, base64url without padding.
pub fn generate_token() -> Result<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("system random number generator failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// A freshly issued access and refresh token pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedTokens {
    pub access_token: String,
    pub access_expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

/// Why a refresh (or a login) was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    /// Unknown, expired or revoked token, or its user no longer exists.
    Invalid,
    /// A refresh token that was already rotated was presented again; its family is now revoked.
    Reused { user: String },
    /// The token store is full.
    Full,
    /// The system random number generator failed.
    Random,
}

type Hash = [u8; digest::SHA256_OUTPUT_LEN];

#[derive(Debug)]
struct RefreshRecord {
    family: u64,
    user: String,
    expires: Instant,
    family_deadline: Instant,
}

/// A refresh token that was rotated out. Kept until it would have expired, to spot its reuse.
#[derive(Debug)]
struct SpentRecord {
    family: u64,
    user: String,
    expires: Instant,
}

#[derive(Debug)]
struct State {
    refresh: HashMap<Hash, RefreshRecord>,
    spent: HashMap<Hash, SpentRecord>,
    /// Revoked family -> when its last access token expires, after which it can be forgotten.
    revoked: HashMap<u64, Instant>,
    next_sweep: Instant,
}

impl State {
    fn sweep(&mut self, now: Instant) {
        if now < self.next_sweep {
            return;
        }
        self.force_sweep(now);
    }

    fn force_sweep(&mut self, now: Instant) {
        self.refresh
            .retain(|_, record| now < record.expires && now < record.family_deadline);
        self.spent.retain(|_, record| now < record.expires);
        self.revoked.retain(|_, until| now < *until);
        self.next_sweep = now + SWEEP_INTERVAL;
    }

    fn revoke_family(&mut self, family: u64, now: Instant, access_ttl: Duration) {
        self.refresh.retain(|_, record| record.family != family);
        self.revoked.insert(family, now + access_ttl);
    }
}

#[derive(Debug)]
pub struct TokenService {
    key: hmac::Key,
    access_ttl: Duration,
    refresh_ttl: Duration,
    state: Mutex<State>,
}

impl TokenService {
    /// Builds the service from the command line.
    pub fn from_args(args: &Args) -> Result<Self> {
        let secret = match &args.token_secret_file {
            Some(path) => load_secret(path)?,
            None => {
                let mut secret = vec![0_u8; TOKEN_BYTES];
                SystemRandom::new()
                    .fill(&mut secret)
                    .map_err(|_| anyhow!("system random number generator failed"))?;
                secret
            }
        };

        Ok(Self::new(
            &secret,
            Duration::from_secs(args.access_token_ttl),
            Duration::from_secs(args.refresh_token_ttl),
        ))
    }

    pub fn new(secret: &[u8], access_ttl: Duration, refresh_ttl: Duration) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            access_ttl,
            refresh_ttl,
            state: Mutex::new(State {
                refresh: HashMap::new(),
                spent: HashMap::new(),
                revoked: HashMap::new(),
                next_sweep: Instant::now() + SWEEP_INTERVAL,
            }),
        }
    }

    /// Starts a new family for `user`, who has just authenticated with Basic Auth.
    pub fn login(&self, user: &str) -> Result<IssuedTokens, TokenError> {
        let now = Instant::now();
        let family = random_family()?;
        let mut state = self.state.lock().expect("token state mutex poisoned");
        Self::make_room(&mut state, now)?;
        self.issue(&mut state, family, user, now, now + MAX_FAMILY_LIFETIME)
    }

    /// Exchanges a refresh token for a new pair and retires the old token.
    ///
    /// `user_exists` lets the caller drop the login of a user that was removed from the
    /// credentials in the meantime. Returns the user along with the new tokens.
    pub fn refresh(
        &self,
        refresh_token: &str,
        user_exists: impl Fn(&str) -> bool,
    ) -> Result<(String, IssuedTokens), TokenError> {
        let now = Instant::now();
        let hash = hash_token(refresh_token);
        let mut state = self.state.lock().expect("token state mutex poisoned");
        state.sweep(now);
        // Checked before the presented token is consumed, so a full store never costs the
        // client its refresh token.
        Self::make_room(&mut state, now)?;

        let Some(record) = state.refresh.remove(&hash) else {
            return match state.spent.get(&hash) {
                Some(spent) if now < spent.expires => {
                    let (family, user) = (spent.family, spent.user.clone());
                    state.revoke_family(family, now, self.access_ttl);
                    Err(TokenError::Reused { user })
                }
                _ => Err(TokenError::Invalid),
            };
        };
        if now >= record.expires || now >= record.family_deadline || !user_exists(&record.user) {
            return Err(TokenError::Invalid);
        }

        // Retire the presented token first; the new pair then replaces it, so the store does
        // not grow by more than one record per refresh.
        state.spent.insert(
            hash,
            SpentRecord {
                family: record.family,
                user: record.user.clone(),
                expires: record.expires,
            },
        );
        let issued = self.issue(
            &mut state,
            record.family,
            &record.user,
            now,
            record.family_deadline,
        )?;
        Ok((record.user, issued))
    }

    /// Logs out: revokes the family of `refresh_token`. Returns whether the token was known.
    pub fn revoke(&self, refresh_token: &str) -> bool {
        let now = Instant::now();
        let hash = hash_token(refresh_token);
        let mut state = self.state.lock().expect("token state mutex poisoned");

        let family = match state.refresh.get(&hash) {
            Some(record) => Some(record.family),
            None => state.spent.get(&hash).map(|record| record.family),
        };
        match family {
            Some(family) => {
                state.revoke_family(family, now, self.access_ttl);
                true
            }
            None => false,
        }
    }

    /// Checks the signature, expiry and revocation of an access token and returns its user.
    ///
    /// The caller still has to check that the user exists.
    pub fn verify_access(&self, token: &str) -> Option<String> {
        let (payload, tag) = token.split_once('.')?;
        let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        hmac::verify(&self.key, &payload, &tag).ok()?;

        let (version, rest) = payload.split_first()?;
        if *version != ACCESS_TOKEN_VERSION || rest.len() < 16 {
            return None;
        }
        let family = u64::from_be_bytes(rest[..8].try_into().ok()?);
        let expires = u64::from_be_bytes(rest[8..16].try_into().ok()?);
        let user = String::from_utf8(rest[16..].to_vec()).ok()?;
        if unix_now() >= expires {
            return None;
        }

        let state = self.state.lock().expect("token state mutex poisoned");
        if state.revoked.contains_key(&family) {
            return None;
        }
        Some(user)
    }

    fn make_room(state: &mut State, now: Instant) -> Result<(), TokenError> {
        if state.refresh.len() + state.spent.len() >= MAX_RECORDS {
            state.force_sweep(now);
            if state.refresh.len() + state.spent.len() >= MAX_RECORDS {
                return Err(TokenError::Full);
            }
        }
        Ok(())
    }

    /// Mints a pair for `family` and records the refresh token.
    fn issue(
        &self,
        state: &mut State,
        family: u64,
        user: &str,
        now: Instant,
        family_deadline: Instant,
    ) -> Result<IssuedTokens, TokenError> {
        let refresh_token = generate_token().map_err(|_| TokenError::Random)?;
        let refresh_expires = (now + self.refresh_ttl).min(family_deadline);
        state.refresh.insert(
            hash_token(&refresh_token),
            RefreshRecord {
                family,
                user: user.to_owned(),
                expires: refresh_expires,
                family_deadline,
            },
        );

        Ok(IssuedTokens {
            access_token: self.mint_access(family, user),
            access_expires_in: self.access_ttl.as_secs(),
            refresh_token,
            refresh_expires_in: refresh_expires.saturating_duration_since(now).as_secs(),
        })
    }

    fn mint_access(&self, family: u64, user: &str) -> String {
        let expires = unix_now() + self.access_ttl.as_secs();
        let mut payload = Vec::with_capacity(17 + user.len());
        payload.push(ACCESS_TOKEN_VERSION);
        payload.extend_from_slice(&family.to_be_bytes());
        payload.extend_from_slice(&expires.to_be_bytes());
        payload.extend_from_slice(user.as_bytes());

        let tag = hmac::sign(&self.key, &payload);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(tag.as_ref())
        )
    }
}

fn load_secret(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read(path)
        .with_context(|| format!("failed to read token secret file {}", path.display()))?;
    let secret = contents.trim_ascii();
    if secret.len() < MIN_SECRET_BYTES {
        bail!(
            "token secret file {} must hold at least {MIN_SECRET_BYTES} bytes, found {}",
            path.display(),
            secret.len()
        );
    }
    Ok(secret.to_vec())
}

fn random_family() -> Result<u64, TokenError> {
    let mut bytes = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| TokenError::Random)?;
    Ok(u64::from_be_bytes(bytes))
}

fn hash_token(token: &str) -> Hash {
    let mut hash = [0_u8; digest::SHA256_OUTPUT_LEN];
    hash.copy_from_slice(digest::digest(&digest::SHA256, token.as_bytes()).as_ref());
    hash
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(access_ttl: u64, refresh_ttl: u64) -> TokenService {
        TokenService::new(
            b"0123456789abcdef0123456789abcdef",
            Duration::from_secs(access_ttl),
            Duration::from_secs(refresh_ttl),
        )
    }

    fn everyone(_: &str) -> bool {
        true
    }

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

    #[test]
    fn login_issues_a_verifiable_access_token() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        assert_eq!(issued.access_expires_in, 600);
        assert_eq!(issued.refresh_expires_in, 3600);
        assert_eq!(
            tokens.verify_access(&issued.access_token).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn user_names_with_dots_and_unicode_survive_the_round_trip() {
        let tokens = service(600, 3600);
        for user in ["a.b.c", "用户", "with space"] {
            let issued = tokens.login(user).unwrap();
            assert_eq!(
                tokens.verify_access(&issued.access_token).as_deref(),
                Some(user)
            );
        }
    }

    #[test]
    fn rejects_tampered_foreign_and_malformed_access_tokens() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        // Flip one character of the payload.
        let (payload, tag) = issued.access_token.split_once('.').unwrap();
        let mut forged = payload.to_owned().into_bytes();
        forged[10] = if forged[10] == b'A' { b'B' } else { b'A' };
        let forged = format!("{}.{tag}", String::from_utf8(forged).unwrap());
        assert_eq!(tokens.verify_access(&forged), None);

        // Signed by another secret.
        let other = TokenService::new(
            b"another-secret-another-secret-00",
            Duration::from_secs(600),
            Duration::from_secs(3600),
        );
        assert_eq!(other.verify_access(&issued.access_token), None);

        // A refresh token is not an access token.
        assert_eq!(tokens.verify_access(&issued.refresh_token), None);
        for junk in ["", ".", "a.b", "not a token"] {
            assert_eq!(tokens.verify_access(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn expired_access_tokens_are_rejected() {
        let tokens = service(0, 3600);
        let issued = tokens.login("alice").unwrap();

        assert_eq!(tokens.verify_access(&issued.access_token), None);
    }

    #[test]
    fn refresh_rotates_the_refresh_token() {
        let tokens = service(600, 3600);
        let first = tokens.login("alice").unwrap();

        let (user, second) = tokens.refresh(&first.refresh_token, everyone).unwrap();
        assert_eq!(user, "alice");
        assert_ne!(second.refresh_token, first.refresh_token);
        assert_eq!(
            tokens.verify_access(&second.access_token).as_deref(),
            Some("alice")
        );

        // The new token keeps working.
        tokens.refresh(&second.refresh_token, everyone).unwrap();
    }

    #[test]
    fn reusing_a_rotated_refresh_token_revokes_the_whole_family() {
        let tokens = service(600, 3600);
        let first = tokens.login("alice").unwrap();
        let (_, second) = tokens.refresh(&first.refresh_token, everyone).unwrap();

        assert_eq!(
            tokens.refresh(&first.refresh_token, everyone),
            Err(TokenError::Reused {
                user: "alice".to_owned()
            })
        );
        // Nothing of the family works any more, including what the legitimate client holds.
        assert_eq!(
            tokens.refresh(&second.refresh_token, everyone),
            Err(TokenError::Invalid)
        );
        assert_eq!(tokens.verify_access(&second.access_token), None);
        assert_eq!(tokens.verify_access(&first.access_token), None);
    }

    #[test]
    fn families_are_independent() {
        let tokens = service(600, 3600);
        let laptop = tokens.login("alice").unwrap();
        let phone = tokens.login("alice").unwrap();

        assert!(tokens.revoke(&laptop.refresh_token));

        assert_eq!(tokens.verify_access(&laptop.access_token), None);
        assert_eq!(
            tokens.verify_access(&phone.access_token).as_deref(),
            Some("alice")
        );
        tokens.refresh(&phone.refresh_token, everyone).unwrap();
    }

    #[test]
    fn revoke_kills_refresh_and_access_tokens() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        assert!(tokens.revoke(&issued.refresh_token));

        assert_eq!(
            tokens.refresh(&issued.refresh_token, everyone),
            Err(TokenError::Invalid)
        );
        assert_eq!(tokens.verify_access(&issued.access_token), None);
        assert!(!tokens.revoke("never-issued"));
    }

    #[test]
    fn expired_refresh_tokens_are_rejected() {
        let tokens = service(600, 0);
        let issued = tokens.login("alice").unwrap();

        assert_eq!(
            tokens.refresh(&issued.refresh_token, everyone),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn refresh_fails_for_a_removed_user() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        assert_eq!(
            tokens.refresh(&issued.refresh_token, |user| user != "alice"),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn refresh_rejects_unknown_tokens_and_access_tokens() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        assert_eq!(
            tokens.refresh("never-issued", everyone),
            Err(TokenError::Invalid)
        );
        assert_eq!(
            tokens.refresh(&issued.access_token, everyone),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn refresh_tokens_are_stored_hashed() {
        let tokens = service(600, 3600);
        let issued = tokens.login("alice").unwrap();

        let state = tokens.state.lock().unwrap();
        assert!(!state.refresh.contains_key(&hash_token("x")));
        assert!(
            state
                .refresh
                .contains_key(&hash_token(&issued.refresh_token))
        );
    }

    #[test]
    fn secret_file_must_be_long_enough() {
        let mut path = std::env::temp_dir();
        path.push(format!("ws2tcp-router-secret-{}.key", std::process::id()));

        fs::write(&path, "short\n").unwrap();
        assert!(load_secret(&path).is_err());

        fs::write(&path, "0123456789abcdef0123456789abcdef\n").unwrap();
        assert_eq!(load_secret(&path).unwrap().len(), 32);
        fs::remove_file(&path).unwrap();
    }
}
