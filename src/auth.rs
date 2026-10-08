//! Token authentication: generating and hashing tokens, and extracting the
//! calling `Agent` from a request's `Authorization` header.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderValue;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::config::Config;

/// Generates a new bearer token: `fp_` followed by the base64url (no
/// padding) encoding of 32 random bytes.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("fp_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Hashes a token with SHA-256, for comparison against a config's stored
/// `token_sha256`.
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

/// The agent that authenticated a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub name: String,
}

/// A lookup table from token hash to `Agent`, built once from `Config`.
#[derive(Debug, Default)]
pub struct Tokens {
    by_hash: HashMap<[u8; 32], Agent>,
}

impl Tokens {
    /// Builds the lookup table from every agent in `cfg`.
    pub fn from_config(cfg: &Config) -> Tokens {
        let by_hash = cfg
            .agents
            .iter()
            .map(|(name, agent)| (agent.token_sha256, Agent { name: name.clone() }))
            .collect();
        Tokens { by_hash }
    }

    /// Looks up the agent owning `token`, by comparing its hash.
    pub fn lookup(&self, token: &str) -> Option<Agent> {
        self.by_hash.get(&hash_token(token)).cloned()
    }

    /// Extracts the agent from an `Authorization` header value. Accepts only
    /// the exact prefix `Bearer ` followed by the token; anything else
    /// (wrong scheme, wrong casing, extra whitespace, missing header,
    /// non-UTF-8 bytes, or an unknown token) is `None`.
    pub fn from_header(&self, value: Option<&HeaderValue>) -> Option<Agent> {
        let value = value?.to_str().ok()?;
        let token = value.strip_prefix("Bearer ")?;
        self.lookup(token)
    }
}

/// The agent that authenticated the request, if any. Extraction never
/// fails: a missing or invalid `Authorization` header simply yields `None`,
/// leaving the handler to decide whether that is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaybeAgent(pub Option<Agent>);

impl<S> FromRequestParts<S> for MaybeAgent
where
    Arc<Tokens>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let tokens = Arc::<Tokens>::from_ref(state);
        let header = parts.headers.get(axum::http::header::AUTHORIZATION);
        Ok(MaybeAgent(tokens.from_header(header)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, Config};
    use std::path::PathBuf;

    #[test]
    fn generated_token_shape() {
        let token = generate_token();
        assert!(token.starts_with("fp_"), "token was {token:?}");
        assert_eq!(token.len(), 46, "token was {token:?}");
        let body = &token[3..];
        assert!(
            body.bytes().all(|b| matches!(
                b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'
            )),
            "token body was not base64url: {body:?}"
        );
    }

    fn config_with_planner(token: &str) -> Config {
        let mut cfg = Config::for_tests(PathBuf::from("/tmp/filepass-auth-test"));
        cfg.agents.insert(
            "planner".to_string(),
            AgentConfig {
                token_sha256: hash_token(token),
            },
        );
        cfg
    }

    #[test]
    fn lookup_by_hash() {
        let token = "fp_test-token";
        let cfg = config_with_planner(token);
        let tokens = Tokens::from_config(&cfg);

        assert_eq!(
            tokens.lookup(token),
            Some(Agent {
                name: "planner".to_string()
            })
        );
        assert_eq!(tokens.lookup("fp_other-token"), None);
    }

    #[test]
    fn header_variants_rejected() {
        let token = "fp_test-token";
        let cfg = config_with_planner(token);
        let tokens = Tokens::from_config(&cfg);

        let rejected = [
            "bearer fp_test-token",
            "Bearer  fp_test-token",
            "Token fp_test-token",
            "",
        ];
        for value in rejected {
            let header = HeaderValue::from_str(value).expect("valid header value");
            assert_eq!(
                tokens.from_header(Some(&header)),
                None,
                "expected {value:?} to be rejected"
            );
        }

        // Non-UTF-8 bytes (not valid as a header string at all).
        let non_utf8 = HeaderValue::from_bytes(b"Bearer \xff\xfe").expect("valid header bytes");
        assert_eq!(tokens.from_header(Some(&non_utf8)), None);

        // Missing header entirely.
        assert_eq!(tokens.from_header(None), None);

        let accepted = HeaderValue::from_str("Bearer fp_test-token").expect("valid header value");
        assert_eq!(
            tokens.from_header(Some(&accepted)),
            Some(Agent {
                name: "planner".to_string()
            })
        );
    }
}
