//! Configuration parsing and validation.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

/// Log output format selected by the `log_format` config key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// A single agent's credentials, as stored in the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub token_sha256: [u8; 32],
}

/// Fully parsed and validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_url: String,
    pub data_dir: PathBuf,
    pub log_format: LogFormat,
    pub trusted_proxies: Vec<IpNet>,

    pub max_file_size: u64,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub tombstone_ttl: Duration,
    pub max_tombstones: usize,
    pub upload_idle_timeout: Duration,
    pub max_upload_duration: Duration,
    pub download_idle_timeout: Duration,
    pub max_download_duration: Duration,
    pub shutdown_grace: Duration,

    pub total_quota: u64,
    pub agent_quota: u64,
    pub max_files: usize,
    pub min_free_space: u64,
    pub min_free_inodes: usize,

    pub upload_rate: u32,
    pub max_concurrent_uploads: usize,
    pub max_uploads_per_agent: usize,
    pub max_concurrent_downloads: usize,
    pub max_downloads_per_ip: usize,

    pub agents: BTreeMap<String, AgentConfig>,
}

/// Errors from parsing or validating a config file.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("missing required key `{0}`")]
    Missing(&'static str),
    #[error("invalid value for `{key}`: {reason}")]
    Invalid { key: &'static str, reason: String },
    #[error("default_ttl ({default_ttl:?}) must not be greater than max_ttl ({max_ttl:?})")]
    DefaultTtlAboveMax {
        default_ttl: Duration,
        max_ttl: Duration,
    },
    #[error("agent `{name}`: {reason}")]
    Agent { name: String, reason: String },
    #[error("agents `{a}` and `{b}` share the same token_sha256")]
    DuplicateTokenHash { a: String, b: String },
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<String>,
    public_url: Option<String>,
    data_dir: Option<String>,
    log_format: Option<String>,
    trusted_proxies: Option<Vec<String>>,

    max_file_size: Option<String>,
    default_ttl: Option<String>,
    max_ttl: Option<String>,
    tombstone_ttl: Option<String>,
    max_tombstones: Option<u64>,
    upload_idle_timeout: Option<String>,
    max_upload_duration: Option<String>,
    download_idle_timeout: Option<String>,
    max_download_duration: Option<String>,
    shutdown_grace: Option<String>,

    total_quota: Option<String>,
    agent_quota: Option<String>,
    max_files: Option<u64>,
    min_free_space: Option<String>,
    min_free_inodes: Option<u64>,

    upload_rate: Option<u64>,
    max_concurrent_uploads: Option<u64>,
    max_uploads_per_agent: Option<u64>,
    max_concurrent_downloads: Option<u64>,
    max_downloads_per_ip: Option<u64>,

    #[serde(default)]
    agents: BTreeMap<String, RawAgentConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    token_sha256: Option<String>,
}

/// Parses a size string: a bare integer is bytes; `B`, `KiB`, `MiB`, `GiB`,
/// `TiB` suffixes are powers of 1024. Case-sensitive.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_part, suffix) = s.split_at(digit_end);
    if num_part.is_empty() {
        return Err(format!("`{s}` has no numeric value"));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("`{s}` is not a valid size"))?;
    let multiplier: u64 = match suffix {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "TiB" => 1024 * 1024 * 1024 * 1024,
        other => return Err(format!("unknown size suffix `{other}` in `{s}`")),
    };
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("`{s}` overflows a 64-bit byte count"))
}

/// True if `name` is a valid agent name: `[a-z0-9][a-z0-9_-]{0,31}`, and not
/// the reserved word `total`.
pub fn valid_agent_name(name: &str) -> bool {
    if name == "total" {
        return false;
    }
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    if !first_ok {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Parses a trusted-proxy entry: a CIDR, or a bare address treated as a
/// `/32` (IPv4) or `/128` (IPv6) host route.
pub fn parse_trusted(entry: &str) -> Result<IpNet, String> {
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(addr) = entry.parse::<IpAddr>() {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        return Ok(IpNet::new(addr, prefix).expect("host prefix is always valid"));
    }
    Err(format!("`{entry}` is not a valid address or CIDR"))
}

/// Validates `public_url`: requires an `http://` or `https://` prefix and a
/// non-empty host, and strips a trailing `/`.
fn validate_public_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"));
    match rest {
        Some(host) if !host.is_empty() => Ok(trimmed.to_string()),
        _ => Err(format!(
            "`{raw}` must start with http:// or https:// and include a host"
        )),
    }
}

fn parse_duration_field(key: &'static str, raw: &str) -> Result<Duration, ConfigError> {
    humantime::parse_duration(raw).map_err(|e| ConfigError::Invalid {
        key,
        reason: e.to_string(),
    })
}

fn parse_size_field(key: &'static str, raw: &str) -> Result<u64, ConfigError> {
    parse_size(raw).map_err(|reason| ConfigError::Invalid { key, reason })
}

fn require_nonzero_duration(key: &'static str, d: Duration) -> Result<(), ConfigError> {
    if d.is_zero() {
        return Err(ConfigError::Invalid {
            key,
            reason: "must not be zero".to_string(),
        });
    }
    Ok(())
}

fn require_nonzero_u64(key: &'static str, v: u64) -> Result<(), ConfigError> {
    if v == 0 {
        return Err(ConfigError::Invalid {
            key,
            reason: "must not be zero".to_string(),
        });
    }
    Ok(())
}

fn parse_agent(name: &str, raw: RawAgentConfig) -> Result<AgentConfig, ConfigError> {
    let hex_str = raw.token_sha256.ok_or_else(|| ConfigError::Agent {
        name: name.to_string(),
        reason: "missing `token_sha256`".to_string(),
    })?;
    if hex_str.len() != 64 {
        return Err(ConfigError::Agent {
            name: name.to_string(),
            reason: format!(
                "`token_sha256` must be 64 hex characters, got {}",
                hex_str.len()
            ),
        });
    }
    let bytes = hex::decode(&hex_str).map_err(|e| ConfigError::Agent {
        name: name.to_string(),
        reason: format!("`token_sha256` is not valid hex: {e}"),
    })?;
    let mut token_sha256 = [0u8; 32];
    token_sha256.copy_from_slice(&bytes);
    Ok(AgentConfig { token_sha256 })
}

impl Config {
    /// Parses and validates a config from TOML source text.
    pub fn from_toml_str(s: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(s)?;

        let listen_str = raw.listen.ok_or(ConfigError::Missing("listen"))?;
        let listen: SocketAddr = listen_str.parse().map_err(|_| ConfigError::Invalid {
            key: "listen",
            reason: format!("`{listen_str}` is not a valid address:port"),
        })?;

        let public_url_raw = raw.public_url.ok_or(ConfigError::Missing("public_url"))?;
        let public_url =
            validate_public_url(&public_url_raw).map_err(|reason| ConfigError::Invalid {
                key: "public_url",
                reason,
            })?;

        let data_dir_str = raw.data_dir.ok_or(ConfigError::Missing("data_dir"))?;
        let data_dir = PathBuf::from(data_dir_str);

        let log_format = match raw.log_format.as_deref().unwrap_or("text") {
            "text" => LogFormat::Text,
            "json" => LogFormat::Json,
            other => {
                return Err(ConfigError::Invalid {
                    key: "log_format",
                    reason: format!("`{other}` must be `text` or `json`"),
                })
            }
        };

        let trusted_proxies_raw = raw
            .trusted_proxies
            .unwrap_or_else(|| vec!["127.0.0.1".to_string(), "::1".to_string()]);
        let trusted_proxies = trusted_proxies_raw
            .iter()
            .map(|entry| parse_trusted(entry))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|reason| ConfigError::Invalid {
                key: "trusted_proxies",
                reason,
            })?;

        let max_file_size = parse_size_field(
            "max_file_size",
            raw.max_file_size.as_deref().unwrap_or("2GiB"),
        )?;
        let default_ttl =
            parse_duration_field("default_ttl", raw.default_ttl.as_deref().unwrap_or("30m"))?;
        let max_ttl = parse_duration_field("max_ttl", raw.max_ttl.as_deref().unwrap_or("24h"))?;
        let tombstone_ttl = parse_duration_field(
            "tombstone_ttl",
            raw.tombstone_ttl.as_deref().unwrap_or("48h"),
        )?;
        let max_tombstones = raw.max_tombstones.unwrap_or(200_000) as usize;
        let upload_idle_timeout = parse_duration_field(
            "upload_idle_timeout",
            raw.upload_idle_timeout.as_deref().unwrap_or("60s"),
        )?;
        let max_upload_duration = parse_duration_field(
            "max_upload_duration",
            raw.max_upload_duration.as_deref().unwrap_or("1h"),
        )?;
        let download_idle_timeout = parse_duration_field(
            "download_idle_timeout",
            raw.download_idle_timeout.as_deref().unwrap_or("60s"),
        )?;
        let max_download_duration = parse_duration_field(
            "max_download_duration",
            raw.max_download_duration.as_deref().unwrap_or("2h"),
        )?;
        let shutdown_grace = parse_duration_field(
            "shutdown_grace",
            raw.shutdown_grace.as_deref().unwrap_or("30s"),
        )?;

        let total_quota =
            parse_size_field("total_quota", raw.total_quota.as_deref().unwrap_or("50GiB"))?;
        let agent_quota =
            parse_size_field("agent_quota", raw.agent_quota.as_deref().unwrap_or("10GiB"))?;
        let max_files = raw.max_files.unwrap_or(1000) as usize;
        let min_free_space = parse_size_field(
            "min_free_space",
            raw.min_free_space.as_deref().unwrap_or("5GiB"),
        )?;
        let min_free_inodes = raw.min_free_inodes.unwrap_or(10_000) as usize;

        let upload_rate = raw.upload_rate.unwrap_or(60) as u32;
        let max_concurrent_uploads = raw.max_concurrent_uploads.unwrap_or(32) as usize;
        let max_uploads_per_agent = raw.max_uploads_per_agent.unwrap_or(8) as usize;
        let max_concurrent_downloads = raw.max_concurrent_downloads.unwrap_or(64) as usize;
        let max_downloads_per_ip = raw.max_downloads_per_ip.unwrap_or(8) as usize;

        if default_ttl > max_ttl {
            return Err(ConfigError::DefaultTtlAboveMax {
                default_ttl,
                max_ttl,
            });
        }

        require_nonzero_u64("max_file_size", max_file_size)?;
        require_nonzero_duration("default_ttl", default_ttl)?;
        require_nonzero_duration("max_ttl", max_ttl)?;
        require_nonzero_duration("tombstone_ttl", tombstone_ttl)?;
        require_nonzero_u64("max_tombstones", max_tombstones as u64)?;
        require_nonzero_duration("upload_idle_timeout", upload_idle_timeout)?;
        require_nonzero_duration("max_upload_duration", max_upload_duration)?;
        require_nonzero_duration("download_idle_timeout", download_idle_timeout)?;
        require_nonzero_duration("max_download_duration", max_download_duration)?;
        require_nonzero_duration("shutdown_grace", shutdown_grace)?;
        require_nonzero_u64("total_quota", total_quota)?;
        require_nonzero_u64("agent_quota", agent_quota)?;
        require_nonzero_u64("max_files", max_files as u64)?;
        require_nonzero_u64("upload_rate", upload_rate as u64)?;
        require_nonzero_u64("max_concurrent_uploads", max_concurrent_uploads as u64)?;
        require_nonzero_u64("max_uploads_per_agent", max_uploads_per_agent as u64)?;
        require_nonzero_u64("max_concurrent_downloads", max_concurrent_downloads as u64)?;
        require_nonzero_u64("max_downloads_per_ip", max_downloads_per_ip as u64)?;
        // min_free_space and min_free_inodes may be zero.

        let mut agents = BTreeMap::new();
        for (name, raw_agent) in raw.agents {
            if !valid_agent_name(&name) {
                return Err(ConfigError::Agent {
                    name: name.clone(),
                    reason: "invalid agent name".to_string(),
                });
            }
            let agent = parse_agent(&name, raw_agent)?;
            agents.insert(name, agent);
        }

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut seen_names: BTreeMap<[u8; 32], String> = BTreeMap::new();
        for (name, agent) in &agents {
            if !seen.insert(agent.token_sha256) {
                let other = seen_names
                    .get(&agent.token_sha256)
                    .cloned()
                    .unwrap_or_default();
                return Err(ConfigError::DuplicateTokenHash {
                    a: other,
                    b: name.clone(),
                });
            }
            seen_names.insert(agent.token_sha256, name.clone());
        }

        Ok(Config {
            listen,
            public_url,
            data_dir,
            log_format,
            trusted_proxies,
            max_file_size,
            default_ttl,
            max_ttl,
            tombstone_ttl,
            max_tombstones,
            upload_idle_timeout,
            max_upload_duration,
            download_idle_timeout,
            max_download_duration,
            shutdown_grace,
            total_quota,
            agent_quota,
            max_files,
            min_free_space,
            min_free_inodes,
            upload_rate,
            max_concurrent_uploads,
            max_uploads_per_agent,
            max_concurrent_downloads,
            max_downloads_per_ip,
            agents,
        })
    }

    /// Reads and parses the config file at `path`.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Config::from_toml_str(&contents)
    }

    /// Builds a config with spec defaults for tests: `listen` on an
    /// ephemeral port, a loopback `public_url`, the given `data_dir`, and no
    /// agents. Always passes validation.
    pub fn for_tests(data_dir: PathBuf) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().expect("valid socket addr"),
            public_url: "http://localhost".to_string(),
            data_dir,
            log_format: LogFormat::Text,
            trusted_proxies: vec![
                parse_trusted("127.0.0.1").expect("valid"),
                parse_trusted("::1").expect("valid"),
            ],
            max_file_size: 2 << 30,
            default_ttl: Duration::from_secs(30 * 60),
            max_ttl: Duration::from_secs(24 * 60 * 60),
            tombstone_ttl: Duration::from_secs(48 * 60 * 60),
            max_tombstones: 200_000,
            upload_idle_timeout: Duration::from_secs(60),
            max_upload_duration: Duration::from_secs(60 * 60),
            download_idle_timeout: Duration::from_secs(60),
            max_download_duration: Duration::from_secs(2 * 60 * 60),
            shutdown_grace: Duration::from_secs(30),
            total_quota: 50 << 30,
            agent_quota: 10 << 30,
            max_files: 1000,
            min_free_space: 5 << 30,
            min_free_inodes: 10_000,
            upload_rate: 60,
            max_concurrent_uploads: 32,
            max_uploads_per_agent: 8,
            max_concurrent_downloads: 64,
            max_downloads_per_ip: 8,
            agents: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn minimal_config_gets_spec_defaults() {
        let toml = r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h/"
            data_dir   = "/tmp/filepass"

            [agents.planner]
            token_sha256 = "a7b0a230eda2b4ea1dbade582fe1c0e6e19f04d0273a2e41f165df8359cbedec"
        "#;
        let cfg = Config::from_toml_str(toml).expect("should parse");
        assert_eq!(cfg.max_file_size, 2 << 30);
        assert_eq!(cfg.default_ttl, Duration::from_secs(30 * 60));
        assert_eq!(cfg.max_downloads_per_ip, 8);
        assert_eq!(cfg.public_url, "https://h");
        assert_eq!(cfg.trusted_proxies.len(), 2);
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("2GiB").unwrap(), 2147483648);
        assert_eq!(parse_size("5").unwrap(), 5);
        assert_eq!(parse_size("10MiB").unwrap(), 10485760);
        assert!(parse_size("2GB").is_err());
        assert!(parse_size("x").is_err());
        assert!(parse_size("").is_err());
    }

    fn base_toml(extra: &str) -> String {
        format!(
            r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h"
            data_dir   = "/tmp/filepass"
            {extra}

            [agents.planner]
            token_sha256 = "a7b0a230eda2b4ea1dbade582fe1c0e6e19f04d0273a2e41f165df8359cbedec"
            "#
        )
    }

    #[test]
    fn rejects_unknown_key() {
        let toml = base_toml("bogus_key = 1");
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_default_ttl_above_max_ttl() {
        let toml = base_toml(
            r#"default_ttl = "2h"
            max_ttl = "1h""#,
        );
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_zero_limit() {
        let toml = base_toml("upload_rate = 0");
        assert!(Config::from_toml_str(&toml).is_err());

        let toml = base_toml(r#"tombstone_ttl = "0s""#);
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn allows_zero_min_free_space_and_inodes() {
        let toml = base_toml(
            r#"min_free_space = "0B"
            min_free_inodes = 0"#,
        );
        let cfg = Config::from_toml_str(&toml).expect("zero min_free_* should be allowed");
        assert_eq!(cfg.min_free_space, 0);
        assert_eq!(cfg.min_free_inodes, 0);
    }

    #[test]
    fn rejects_bad_agent_names() {
        for bad in ["Planner", "-x", "total", &"a".repeat(33)] {
            assert!(
                !valid_agent_name(bad),
                "expected {bad:?} to be an invalid agent name"
            );
        }
        for good in ["planner", "b-2_x"] {
            assert!(
                valid_agent_name(good),
                "expected {good:?} to be a valid agent name"
            );
        }
    }

    #[test]
    fn rejects_duplicate_token_hashes() {
        let toml = r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h"
            data_dir   = "/tmp/filepass"

            [agents.planner]
            token_sha256 = "a7b0a230eda2b4ea1dbade582fe1c0e6e19f04d0273a2e41f165df8359cbedec"
            [agents.builder]
            token_sha256 = "a7b0a230eda2b4ea1dbade582fe1c0e6e19f04d0273a2e41f165df8359cbedec"
        "#;
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn token_hash_uppercase_accepted() {
        let lower = "a7b0a230eda2b4ea1dbade582fe1c0e6e19f04d0273a2e41f165df8359cbedec";
        let upper = lower.to_uppercase();

        let toml_lower = format!(
            r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h"
            data_dir   = "/tmp/filepass"

            [agents.planner]
            token_sha256 = "{lower}"
            "#
        );
        let toml_upper = format!(
            r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h"
            data_dir   = "/tmp/filepass"

            [agents.planner]
            token_sha256 = "{upper}"
            "#
        );
        let cfg_lower = Config::from_toml_str(&toml_lower).expect("lowercase hash should parse");
        let cfg_upper = Config::from_toml_str(&toml_upper).expect("uppercase hash should parse");
        assert_eq!(
            cfg_lower.agents["planner"].token_sha256,
            cfg_upper.agents["planner"].token_sha256
        );
    }

    #[test]
    fn token_hash_bad_length_or_hex_names_agent() {
        let toml = r#"
            listen     = "127.0.0.1:8080"
            public_url = "https://h"
            data_dir   = "/tmp/filepass"

            [agents.planner]
            token_sha256 = "not-hex-and-too-short"
        "#;
        let err = Config::from_toml_str(toml).expect_err("bad hash should be rejected");
        assert!(err.to_string().contains("planner"));
    }

    #[test]
    fn trusted_proxies_bare_and_cidr() {
        assert_eq!(
            parse_trusted("127.0.0.1").unwrap().to_string(),
            "127.0.0.1/32"
        );
        assert_eq!(parse_trusted("::1").unwrap().to_string(), "::1/128");
        assert!(parse_trusted("10.0.0.0/8").is_ok());
        assert!(parse_trusted("nope").is_err());
    }

    #[test]
    fn rejects_malformed_public_url() {
        let toml = r#"
            listen     = "127.0.0.1:8080"
            public_url = "ftp//x"
            data_dir   = "/tmp/filepass"
        "#;
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn for_tests_passes_validation() {
        let cfg = Config::for_tests(PathBuf::from("/tmp/filepass-test"));
        assert_eq!(cfg.public_url, "http://localhost");
        assert!(cfg.agents.is_empty());
    }
}
